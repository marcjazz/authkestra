# RFC-006: `acr`/`amr` claims on issued ID tokens

> **Status: implemented**, in `authkestra-engine` (`Engine::authenticate`,
> `Identity::attributes` bookkeeping) and `authkestra-op` (the `amr_acr`
> module and the four `issue_id_token_with_extra` call sites in
> `handlers/token.rs`). This document is the design record; day-to-day
> reference for what the claims mean lives in this file since there is no
> separate OP Server page section for it yet.

## 1. Summary

`authkestra-op`'s issued ID tokens gain the two standard OIDC claims that
express *how* a user authenticated: `acr` (Authentication Context Class
Reference — OIDC Core §2, a single string) and `amr` (Authentication
Methods References — OIDC Core §2, an array of strings, values
conventionally drawn from the IANA registry in RFC 8176). Before this
change, nothing in the workspace expressed "this token attests the user
completed step-up/MFA" or "this is what method(s) actually authenticated
this session" to a relying party — `authkestra-engine` has a real step-up
mechanism (`EngineBuilder::with_mfa_method`, see
`crates/authkestra/examples/axum_mfa_server.rs`), but nothing downstream of
`Engine::authenticate` ever saw evidence that it ran.

## 2. Motivation

- `authkestra-engine`'s step-up mechanism (register a method "step-up only"
  via `with_mfa_method`, primary auth + `AuthResult::MfaRequired` +
  `AuthInput::MfaChallenge` continuation) has existed for a while and is
  documented (`docs/book/ch03-core-traits.md`, `docs/book/ch04-flows-and-protocols.md`).
  It produces a real, verified security outcome — but that outcome was
  discarded the moment `Engine::authenticate` returned: `AuthResult::Success`
  carries only an `Identity`, and nothing about *which* method(s) ran was
  recorded anywhere reachable from token issuance.
- A relying party integrating with an `authkestra-op` deployment therefore
  had no standard way to ask "did this user complete a second factor?" —
  which matters for anything that wants to require step-up for a sensitive
  action (a common pattern: check `acr` on the ID token / a fresh
  authentication, and if it doesn't say step-up was satisfied, force one).
- Downstream motivation (not a requirement this RFC has to satisfy): the
  merged-but-unintegrated Cedar policy engine PoC (`authkestra-policy`,
  referenced in prior discussion as PR #310) models its
  `AuthorizationRequest.context` as a bare `serde_json::Value` specifically
  because there was no canonical claim yet to point at for "how was this
  principal authenticated." This RFC creates that claim; wiring
  `authkestra-policy` to read it is out of scope here.

## 3. What already existed, and what didn't

Traced before designing anything (per the working process for this PR):

- `Identity` (`crates/authkestra-engine/src/auth/state.rs`) is the terminal
  "who is this" value returned by every authentication path — local
  (`Engine::authenticate`), OAuth-provider-federated, WebAuthn, etc. It
  already has a `attributes: HashMap<String, String>` bag used for exactly
  this kind of flow-local bookkeeping: `identity.attributes["nonce"]`
  threads the OIDC `nonce` through `authkestra_engine::flow::oauth2` and
  `authkestra-oidc`'s provider code without the `Identity` struct itself
  needing a `nonce` field.
- `AuthResult::Success(Identity)` is constructed in exactly two places, both
  in `crates/authkestra-engine/src/engine.rs`, inside `Engine::authenticate`:
  the primary-auth-was-sufficient branch, and the step-up-continuation
  branch. Both branches *locally* know which method(s) ran (`method_name`,
  `method.is_mfa_equivalent()`) — but discarded that knowledge before
  returning.
- `authkestra-op`'s `handle_authorize` (`handlers/authorize.rs`) and the
  four ID-token-issuing grant handlers in `handlers/token.rs`
  (`handle_device_code`, `default_handle_authorization_code`,
  `default_handle_refresh_token`, `default_handle_token_exchange`) all
  receive an already-authenticated `Identity` as a parameter — they never
  call `Engine::authenticate` themselves. So whatever carries `acr`/`amr`
  data has to arrive already attached to the `Identity` the host handed
  them; `authkestra-op` cannot derive it independently.
- The step-up continuation token (`MfaTokenClaims`, minted when
  `AuthResult::MfaRequired` is returned and consumed when the second factor
  completes) carried `sub`, `mfa_pending`, `exp` — **not** which primary
  method had already run. So even inside `Engine::authenticate` itself, the
  step-up-completion branch had no way to report the *primary* method,
  only the second factor it had just verified.

Conclusion: this information was not available at token issuance and had
to be threaded through — specifically, through `Identity` (via
`attributes`, not a new field — see §4.1) and through `MfaTokenClaims`
(a new `primary_method` field, so the full chain survives the step-up
round-trip).

## 4. Design decisions

### 4.1. Where the data lives: `Identity::attributes`, not a new field

`Identity` is constructed via struct literal in ~40 files across the
workspace (every OAuth provider, every built-in `AuthMethod`, every
adapter's tests, `authkestra-devsig`, the SQL store test suites, ...).
Adding a new named field to `Identity` — even an `Option`-typed one —
is a breaking change to every one of those call sites for a feature that
only `Engine::authenticate`'s two local-auth branches can actually
populate honestly; every other constructor would need to decide what to
put there with no real information to base it on.

Instead, `Engine::authenticate` stamps two well-known keys into the
existing `attributes: HashMap<String, String>` bag — the same mechanism
`"nonce"` already uses (`crates/authkestra-engine/src/flow/oauth2.rs`):

- `IDENTITY_ATTR_AMR` (`"amr"`) — the space-delimited list of internal
  auth-method names that authenticated this identity, primary first (e.g.
  `"password"`, or `"password totp"` after a completed step-up).
- `IDENTITY_ATTR_STEP_UP_SATISFIED` (`"step_up_satisfied"`) — the literal
  string `"true"` when this engine's step-up tier is satisfied (§4.3);
  **absent**, never `"false"`, otherwise.

Both constants live in `authkestra_engine::auth::state` and are re-exported
from `authkestra_engine::auth`, so `authkestra-op` (or any other consumer)
references the key names rather than the literal strings.

This keeps the change purely additive: zero existing `Identity { .. }`
literals anywhere in the workspace needed to change, and `AuthResult`'s
shape is untouched. The cost is that this is a plain string convention
rather than a typed field — judged the right trade given the alternative
was rewriting ~40 unrelated files (OAuth providers, `authkestra-devsig`,
every store test suite) to make a decision most of them have no basis for.

### 4.2. Threading the primary method through step-up

The step-up continuation branch of `Engine::authenticate` only knew the
*second* factor's method name; the primary method that ran earlier (and
minted the continuation token) wasn't recorded anywhere reachable at that
point. Fixed by adding `primary_method: String` to
`MfaTokenClaims` (`crates/authkestra-engine/src/auth/state.rs`), set when
the token is minted and read back when the step-up completes, so
`Engine::authenticate` can report `amr = [primary_method, step_up_method]`
(deduplicated, in case they're ever equal) rather than just the step-up
factor alone.

### 4.3. The `acr` scheme: binary, self-issued, not an AAL ladder

`authkestra-engine`'s step-up model is fundamentally binary — an identity
either satisfies primary auth only, or primary-plus-step-up (there is no
notion of a third tier). Two self-issued URN values reflect that honestly:

| Constant                          | Value                              | Meaning |
|------------------------------------|-------------------------------------|---------|
| `authkestra_op::ACR_SINGLE_FACTOR` | `urn:authkestra:acr:single-factor`  | Primary authentication only; no step-up ran, and the primary method itself isn't step-up-equivalent. |
| `authkestra_op::ACR_MFA`           | `urn:authkestra:acr:mfa`            | Step-up satisfied: either a completed step-up (MFA) challenge on top of primary auth, or a single primary `AuthMethod` that itself reports `is_mfa_equivalent()` (this engine's built-in WebAuthn, used as a primary, is the current example). |

This is **deliberately not** a NIST SP 800-63 AAL1/2/3 ladder or an eIDAS
LoA scheme. This engine cannot back a claim that specific — no
phishing-resistance attestation, no identity-proofing tier, no
re-authentication/`max_age` freshness tracking (§6) — and a relying party
parsing an AAL-shaped acr value that doesn't actually mean what AAL means
would be actively misled. A self-issued, narrowly-scoped URN says exactly
as much as this engine can verify and no more.

Both `ACR_MFA`'s two triggering conditions collapse to the same value
deliberately: the engine's own `is_mfa_equivalent()` contract already
means "treat this primary method as satisfying the step-up requirement" —
it would be inconsistent to honor that everywhere else (skipping the
`MfaRequired` challenge entirely) but then report a *lesser* acr for the
resulting token.

### 4.4. AMR value set

`authkestra-engine`'s internal auth-method names are remapped at the
`authkestra-op` boundary (`amr_acr::internal_method_to_amr`), moving closer
to RFC 8176 where a value fits exactly, and staying engine-specific where
the registry's nearest term would either be ambiguous or overclaim:

- `"password"` → `"pwd"` (`AMR_PASSWORD`) — RFC 8176's canonical token.
- `"totp"` stays `"totp"` — RFC 8176's closest generic value is `"otp"`,
  which doesn't distinguish TOTP from HOTP or a mailed/SMS code; this
  engine only ever implements TOTP, so the specific name is more
  informative, and RFC 8176 §2 explicitly allows registering (or, as here,
  using outside the registry) new values.
- `"webauthn"` stays `"webauthn"` — RFC 8176 has `"hwk"` (hardware key) and
  `"swk"` (software key), but this crate's WebAuthn integration doesn't
  distinguish a roaming authenticator from a platform one, so asserting
  either would overclaim what was actually verified.
- `AMR_MFA_MARKER` (`"mfa"`, RFC 8176's own generic multi-factor value) is
  *appended* to the array whenever `ACR_MFA` applies (either a real
  completed step-up, or an `is_mfa_equivalent` primary alone) — mirroring
  how several production IdPs report both the constituent method(s) and
  this summary value together, and giving a relying party that only checks
  `amr` (rather than `acr`) a value to look for.
- Any other internal method name (a custom `AuthMethod` an integrator
  registered) passes through unchanged — `authkestra-op` has no basis for
  remapping a name it doesn't recognize, and passing it through verbatim is
  more honest than dropping it.

### 4.5. Plain (non-step-up) OAuth2/OIDC logins still get both claims

A login through `authkestra-op`'s own `/authorize` + `/token` that never
enrolls or triggers step-up (the common case) still gets `amr = ["pwd"]`
(or whatever the primary method maps to) and `acr = ACR_SINGLE_FACTOR` —
not an absent claim. This is deliberate: "no step-up occurred" is
positively known and worth asserting, not the same as "we have no idea how
this identity authenticated" (§4.6).

### 4.6. Identities with no provenance get neither claim

An `Identity` whose `attributes` carry no `IDENTITY_ATTR_AMR` entry at all —
because it never passed through `Engine::authenticate` (a federated
identity from an external IdP, handed straight to `handle_authorize` by a
host application that does its own login) — gets **no** `acr`/`amr` claims
on the resulting ID token, rather than a fabricated or defaulted value.
Both claims are OPTIONAL per OIDC Core §2, so omitting them is conformant,
and asserting a scheme this crate has no evidence for would be worse than
saying nothing. This is the one gap this RFC leaves open rather than
closing — see §6.

## 5. Implementation summary

- `crates/authkestra-engine/src/auth/state.rs` — `IDENTITY_ATTR_AMR`,
  `IDENTITY_ATTR_STEP_UP_SATISFIED` constants; `MfaTokenClaims` gains
  `primary_method: String`.
- `crates/authkestra-engine/src/auth/mod.rs` — re-exports the two new
  constants.
- `crates/authkestra-engine/src/engine.rs` — `Engine::authenticate` stamps
  `attributes` on all three `AuthResult::Success` outcomes (primary-only,
  `is_mfa_equivalent`-primary, completed step-up), and sets
  `primary_method` when minting the continuation token.
- `crates/authkestra-op/src/amr_acr.rs` (new) — the AMR/ACR vocabulary
  (§4.3, §4.4) and `amr_acr_extra_claims(&Identity) -> HashMap<String, Value>`,
  re-exported from the crate root.
- `crates/authkestra-op/src/handlers/token.rs` — all four ID-token-issuing
  call sites (`handle_device_code`, `default_handle_authorization_code`,
  `default_handle_refresh_token`, `default_handle_token_exchange`) switched
  from `issue_id_token` to `issue_id_token_with_extra`, passing
  `amr_acr_extra_claims(&identity)`.

No change to `authkestra-op::handlers::userinfo` — OIDC Core's Standard
Claims don't include `acr`/`amr` among the claims a relying party would
normally request via UserInfo, and this RFC doesn't add a reason to.

## 6. Out of scope / deferred

- **Re-authentication / `max_age` handling.** OIDC Core §3.1.2.1's
  `max_age` request parameter (and `prompt=login`) would let a relying
  party force a *fresh* authentication rather than accepting a stale
  session's `acr`/`amr`. `authkestra-op` has no concept of "how long ago
  did this identity actually authenticate" today (no `auth_time` claim
  either), and building that is a genuinely separate, non-trivial feature
  (it touches session freshness tracking across every grant type, not just
  ID token claim shape). **Filed as a follow-up: GitHub issue
  [#381](https://github.com/marcjazz/authkestra/issues/381) — "Support OIDC
  `max_age` / `prompt=login` re-authentication in `authkestra-op`"**,
  referencing this PR (#380) and this RFC, mirroring how issues #370 and
  #376 were split off from their respective PRs this cycle.
- **A full NIST SP 800-63 AAL ladder / eIDAS LoA scheme.** Not deferred —
  actively rejected, per §4.3: this engine cannot back the guarantees such
  a scheme implies, and a narrower, honest scheme is preferable to a
  richer one this crate can't actually support.
- **Propagating an upstream federated IdP's own `acr`/`amr`.** When a host
  application authenticates a user against an external OIDC provider (via
  `authkestra-oidc`) and then hands the resulting `Identity` to
  `authkestra-op`'s `/authorize`, that identity carries no
  `IDENTITY_ATTR_AMR` (§4.6) even though the upstream ID token may have had
  its own `acr`/`amr`. Forwarding those would require `authkestra-oidc` to
  capture and thread them through in the same `attributes`-bag idiom used
  here, which is a reasonable follow-up but a distinct piece of work with
  its own trust questions (should an upstream's self-reported `acr` be
  taken at face value?) — not addressed by this RFC.

## 7. Testing

- `crates/authkestra-engine/src/tests.rs` — `amr_step_up_bookkeeping`
  module: primary-only login stamps `amr` with no step-up marker; a
  completed step-up stamps `amr` with both methods and the marker.
  `test_mfa_equivalent_bypasses_mfa` extended to assert the
  `is_mfa_equivalent`-primary case also sets the step-up marker.
- `crates/authkestra-op/src/amr_acr.rs` — unit tests for the claim
  derivation itself: no-attribute → no claims, primary-only →
  `ACR_SINGLE_FACTOR`, completed step-up → `ACR_MFA` plus the `"mfa"`
  marker, an `is_mfa_equivalent`-style single-method-but-satisfied case,
  and an unrecognized method name passing through unchanged.
- `crates/authkestra-op/src/handlers/token.rs` — end-to-end tests that
  issue a real ID token (via the refresh-token grant, the simplest of the
  four call sites to stand up) for a primary-only identity and a
  step-up-satisfied identity, decode it, and assert the `amr`/`acr` claims
  differ — plus a direct `assert_ne!` between the two outcomes, and a case
  confirming an identity with no `amr` attribute gets neither claim.

## 8. Design decisions a maintainer should double-check

- **`ACR_MFA` collapsing "completed step-up" and "`is_mfa_equivalent`
  primary alone" into one value** (§4.3) is a judgment call — a relying
  party that specifically wants to know "did a *second*, distinct
  credential get checked" (as opposed to "does this engine consider one
  credential sufficient") can still tell the two apart by counting
  non-`"mfa"` entries in `amr`, but `acr` alone doesn't distinguish them.
  If that distinction turns out to matter to an integrator, it's a
  backward-compatible addition (a third `acr` value), not a redesign.
- **The `attributes`-bag mechanism (§4.1)** trades a typed field for zero
  blast radius. If a future feature needs several more pieces of
  `Engine::authenticate`-local bookkeeping threaded the same way, revisit
  whether a small typed side-struct (`AuthContext`) attached to
  `AuthResult::Success` would be cleaner than accumulating more
  string-keyed `attributes` conventions.
