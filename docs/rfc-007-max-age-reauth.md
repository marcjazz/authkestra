# RFC-007: `max_age` / `prompt=login` re-authentication at `/authorize`

> **Status: implemented**, in `authkestra-op` (`handlers::authorize`: two new
> `AuthorizeRequest` fields, the `AuthorizeOutcome::ReauthenticationRequired`
> variant, and the freshness/prompt enforcement in `handle_authorize`) and
> the `authkestra-axum`/`authkestra-actix` facades (minimal wiring of the new
> outcome to a `/login` redirect). This document is the design record for
> issue [#381](https://github.com/marcjazz/authkestra/issues/381), split off
> from #380/RFC-006 (`docs/rfc-006-acr-amr-claims.md` §6).

## 1. Summary

`authkestra-op`'s `/authorize` handler now honours OIDC Core §3.1.2.1's
`max_age` and `prompt` request parameters where they concern authentication
freshness:

- `max_age=N`: if the presented `Identity`'s `auth_time` (RFC-006,
  `IDENTITY_ATTR_AUTH_TIME`) is more than `N` seconds old — or absent
  entirely — a fresh authentication is required.
- `prompt=login`: a fresh authentication is required unconditionally,
  regardless of `auth_time`.
- `prompt=none`: no UI may be shown. If a fresh authentication would
  otherwise be required, the request fails with `login_required`, delivered
  to the *client* via redirect — never as a signal to show UI.
- `prompt=none` combined with any other `prompt` value: `invalid_request`.

Because `authkestra-op` owns no login UI and no user table (decision 0005),
it cannot perform a re-authentication itself. The whole feature is
therefore built around one new outcome — `AuthorizeOutcome::ReauthenticationRequired`
— that tells the host application "re-run your own login flow, then call
`handle_authorize` again," rather than any attempt to drive re-authentication
from inside this crate.

## 2. Motivation

RFC-006 gave `authkestra-op` the vocabulary to *assert* how and when a user
authenticated (`acr`, `amr`, `auth_time`), but deliberately stopped short of
*enforcing* anything against it — see RFC-006 §4.4a and §6. Without
enforcement, a relying party that wants "require a login from the last N
minutes before doing something sensitive" (a common pattern once `acr`/`amr`
exist to check) has no way to ask `authkestra-op` for that: it can only
inspect the claims on a token *after* the fact and decide for itself,
out-of-band, whether to trust it. `max_age`/`prompt=login` are exactly OIDC's
standard vocabulary for asking for it *up front*, at `/authorize`, and this
RFC wires them in.

## 3. What already existed, traced before designing anything

- `Identity::attributes` (`IDENTITY_ATTR_AUTH_TIME`) already carries the Unix
  timestamp of the identity's most recent authentication, stamped by
  `Engine::authenticate` on every `AuthResult::Success` path — primary-only,
  `is_mfa_equivalent`-primary, and completed step-up (RFC-006 §4.4a). An
  `Identity` that never passed through `Engine::authenticate` (a federated
  login from `authkestra-oidc`, handed straight to `handle_authorize`)
  carries no such attribute.
- `handle_authorize` (`crates/authkestra-op/src/handlers/authorize.rs`) is a
  straight-line, mostly-synchronous validation pipeline: look up the client,
  validate `redirect_uri`, and from that point on every failure becomes a
  `Redirect` carrying an OAuth2 `error`/`error_description` pair rather than
  a direct HTTP error — `AuthorizeOutcome::DirectError` is reserved for the
  two checks that run *before* `redirect_uri` is confirmed safe to redirect
  to at all (`UnknownClient`, `RedirectUriMismatch`).
- `AuthorizeRequest` was already `#[non_exhaustive]` (added ahead of this
  RFC, presumably in anticipation of exactly this kind of addition);
  `AuthorizeOutcome` was not.
- Nothing in `handle_authorize`, or anywhere else in `authkestra-op`,
  tracked or enforced authentication freshness. `acr`/`amr`/`auth_time` were
  purely observational (RFC-006 §6).
- The house pattern for widening a public type without breaking downstream
  callers is `#[non_exhaustive]` plus a `new()` constructor, fields staying
  public for read/mutate access — established for `Jwk` (#342) and
  `MfaTokenClaims` (#380, RFC-006 §4.2). This RFC follows the same pattern
  for `AuthorizeOutcome`.

## 4. Design

### 4.1. The shape: OP signals, application performs

`handle_authorize`'s signature already makes the constraint explicit: it
takes an `identity: Identity` the caller — the host application — already
authenticated, and returns an `AuthorizeOutcome` synchronously. There is no
hook for "go log this user in again and come back to me" inside a single
call: this framework owns no user table and no login UI (decision 0005), so
`authkestra-op` cannot itself display a login form, verify a password, or
run a WebAuthn ceremony. All of that lives in the host application, which is
the only thing that knows how its users actually log in.

That leaves exactly one honest shape: **recognize** that the presented
`Identity` is not fresh enough, and **say so** to the caller, handing back
enough information to retry. A new `AuthorizeOutcome` variant is the natural
fit — it composes with the existing `Redirect`/`DirectError` split instead
of overloading either:

```rust
#[non_exhaustive]
pub enum AuthorizeOutcome {
    Redirect(String),
    DirectError(OpError),
    ReauthenticationRequired(Box<ReauthenticationRequired>),
}

#[non_exhaustive]
pub struct ReauthenticationRequired {
    pub request: AuthorizeRequest,
    pub max_age_exceeded: bool,
    pub prompt_login: bool,
}
```

`request` is the original `AuthorizeRequest`, handed back unmodified. The
host application's login UI runs as a separate page load — it cannot
literally resume this Rust call — but returning the request saves it from
independently persisting or re-parsing the original query string while it
round-trips through that UI (e.g. re-encoding it as the return-to state on
its own redirect to `/login`). `max_age_exceeded`/`prompt_login` say *why*,
for logging and for an application that wants to react differently to the
two triggers (there is no reason it must, but nothing here forecloses it).

`ReauthenticationRequired` is boxed inside the enum: it carries a whole
`AuthorizeRequest`, which would otherwise make it the dominant variant's
size and bloat every `AuthorizeOutcome` — including the overwhelmingly more
common `Redirect` — to match (`clippy::large_enum_variant` catches exactly
this).

Both types are `#[non_exhaustive]` with a `new()` constructor, matching the
`Jwk`/`MfaTokenClaims` pattern (§6 covers why this needed to happen now,
not later).

### 4.2. `prompt=none` and `login_required`: redirect to the *client*, not a signal to the application

`ReauthenticationRequired` is deliberately **not** what gets returned when
`prompt=none` is present and re-authentication would otherwise be needed.
OIDC Core §3.1.2.1 is explicit: `prompt=none` means the client asked for *no
UI whatsoever*; if the OP cannot satisfy the request silently, it "MUST
return an error, most typically `login_required`" — as a normal
authorization error response, i.e. a redirect back to the client's
`redirect_uri` with `error=login_required`.

Handing the host application a `ReauthenticationRequired` in this case would
be exactly wrong: the application's natural response to that variant is to
show its login UI, which is precisely the interaction `prompt=none` ruled
out. So the two triggers (`max_age` exceeded, `prompt=login`) are evaluated
*before* branching on `prompt=none`, and when `prompt=none` is present the
function takes the existing `error_redirect` path used for every other
request-shape error, with `error=login_required`, instead of the new
variant. This is why the check lives entirely inside `handle_authorize`
rather than at the boundary between `AuthorizeOutcome` and its caller: the
caller must never see a `ReauthenticationRequired` for a `prompt=none`
request in the first place.

`prompt=none` combined with any other `prompt` value (`"none login"`, etc.)
is rejected as `invalid_request` before either freshness check runs, per
OIDC Core §3.1.2.1's requirement that `none` not be combined with anything
else. This, too, is a `Redirect` (not `DirectError`): `client_id` and
`redirect_uri` are already validated by the time `prompt` is inspected, so
the request-shape error goes back to the client exactly like an invalid
`scope` or a missing PKCE challenge does.

### 4.3. The freshness computation

```
now - auth_time > max_age  =>  max_age_exceeded
```

taken directly from OIDC Core §3.1.2.1's own wording ("if it determines that
too much time has elapsed since the last End-User authentication"). Two
details matter:

- **`max_age=0` is meaningful, not "unset."** `AuthorizeRequest::max_age` is
  `Option<i64>`, and the enforcement code branches on `Some`/`None`, never
  on the numeric value — there is no `if max_age > 0` anywhere that would
  quietly treat `0` as "no freshness requirement." `max_age=0` behaves
  exactly as the formula above says: any identity with `auth_time` in the
  past (i.e. essentially always, since authentication and this request
  cannot be simultaneous) fails the check.
- **A missing `auth_time` fails closed.** OIDC Core §2 makes `auth_time`
  REQUIRED on the ID token whenever `max_age` was in the request. An
  `Identity` with no parseable `IDENTITY_ATTR_AUTH_TIME` — because it never
  passed through `Engine::authenticate` at all (RFC-006 §4.6) — cannot
  support that requirement: there is no evidence of *when*, or *whether*,
  this identity ever freshly authenticated. Silently ignoring `max_age` in
  this case would grant a code and let a later ID token either omit the
  REQUIRED claim or fabricate one; both are worse than the alternative,
  which is to treat "we don't know" the same as "definitely too old" and
  require re-authentication. This is a deliberate fail-closed choice, not
  an oversight: an integrator relying on a federated identity provider that
  wants `max_age` to work has to make sure its own `Identity` carries
  `auth_time` (by threading the upstream provider's own freshness signal
  into `attributes` before calling `handle_authorize` — not something this
  RFC does automatically, since forwarding an upstream `acr`/`amr`/`auth_time`
  without evaluating trust in it is exactly the gap RFC-006 §6 leaves open
  for a separate follow-up).
- One consequence worth naming explicitly: because a `max_age` request that
  reaches code issuance (a `Redirect`, not `ReauthenticationRequired`) is
  only possible when `auth_time` was present and fresh enough, the OIDC
  Core §2 REQUIRED-`auth_time`-when-`max_age`-was-requested constraint is
  satisfied *by construction* once this check is in place — RFC-006's
  `amr_acr_extra_claims` already emits `auth_time` whenever the identity
  carries it, and now every identity that reaches token issuance under a
  `max_age` request is guaranteed to carry it.

### 4.4. Where the checks live in the pipeline

Inserted as steps 7-8, after PKCE validation (step 6) and before
`AuthorizationCode` construction (renumbered to step 9): by that point
`client_id`/`redirect_uri`/`scope`/`response_type`/grant-type/PKCE are all
already known-good, so every failure here can safely use the existing
`error_redirect` closure. Ordering relative to those earlier checks is not
mandated by the spec; this placement was chosen to minimize the diff against
the existing numbered-steps structure rather than for any semantic reason.

### 4.5. Does a `max_age`-forced re-authentication reset step-up state?

This is the open design question the issue named. The answer: **yes, and
it's automatic, not something this RFC had to add logic for** — because of
how little state `authkestra-op` holds in the first place.

`authkestra-op` never persists a "this session/identity has step-up
satisfied" fact anywhere; `IDENTITY_ATTR_STEP_UP_SATISFIED` lives entirely on
the `Identity` value passed into a single `handle_authorize` call, stamped
fresh by `Engine::authenticate` for *that* call only. There is no store,
cache, or session record inside `authkestra-op` a stale step-up flag could
survive in. So when re-authentication is required:

- `ReauthenticationRequired` deliberately does **not** carry the `Identity`
  that was presented to the call that triggered it (see the doc comment on
  `ReauthenticationRequired::request`). It is simply dropped when the
  function returns.
- The only way `handle_authorize`'s second call (after the host
  application's fresh login) can see `IDENTITY_ATTR_STEP_UP_SATISFIED = true`
  again is if the fresh authentication the application ran *actually
  produced* that attribute — i.e., `Engine::authenticate` ran a real step-up
  challenge again (or a single `is_mfa_equivalent` primary method) during
  that fresh login.
- There is no code path, in this RFC or anywhere else in `authkestra-op`,
  that could carry the *old* identity's step-up flag forward into the new
  one. The reset is total, simply because nothing persists across the two
  calls except what the application chooses to persist in its own login
  flow.

This also means the answer is intentionally not configurable: an integrator
cannot ask `authkestra-op` to "remember" that step-up was satisfied across a
`max_age`-forced re-authentication, because `authkestra-op` never remembered
it as its own fact to begin with — it only ever reported what the most
recent `Engine::authenticate` call asserted. Whether *the host
application's* fresh login flow re-runs step-up is entirely up to that
application; nothing here prevents it from immediately re-issuing a
step-up-satisfied identity if that's what it wants to do (e.g., because it
independently remembers the user recently completed step-up via its own
session store), but `authkestra-op` supplies no shortcut for it and takes no
position on whether that would be appropriate.

## 5. Implementation summary

- `crates/authkestra-op/src/handlers/authorize.rs`:
  - `AuthorizeRequest` gains `max_age: Option<i64>` and
    `prompt: Option<String>`, both `#[serde(default)]`.
  - `AuthorizeOutcome` becomes `#[non_exhaustive]` and gains
    `ReauthenticationRequired(Box<ReauthenticationRequired>)`.
  - New `ReauthenticationRequired` struct (`#[non_exhaustive]`, `new()`
    constructor): `request: AuthorizeRequest`, `max_age_exceeded: bool`,
    `prompt_login: bool`.
  - `handle_authorize` gains steps 7-8: `prompt` validation
    (`none`-combined-with-anything-else → `invalid_request`), then
    `max_age`/`prompt=login` freshness enforcement, branching to
    `login_required` (via `error_redirect`, for `prompt=none`) or
    `ReauthenticationRequired` (otherwise).
- `crates/authkestra-axum/src/op.rs`, `crates/authkestra-actix/src/op.rs`:
  the (now non-exhaustive) `AuthorizeOutcome` match gains a
  `ReauthenticationRequired` arm. Both facades take the minimal option —
  redirect to `/login`, mirroring the existing "no session at all" branch
  immediately above it — rather than threading `reauth.request` through a
  `return_to` round-trip, since neither facade encodes one for the
  no-session case either today. A deployment that wants the login flow to
  resume the original `/authorize` request afterward has to carry
  `reauth.request` itself; wiring that end-to-end is future work, not part
  of this RFC's scope (`authkestra-op` already hands back everything needed
  to do it — see §4.1).
- Tests: `crates/authkestra-op/src/handlers/authorize.rs` `mod tests` —
  fresh-enough auth under `max_age` succeeds; stale auth triggers
  `ReauthenticationRequired`; `max_age=0` forces re-authentication even for
  a one-second-old identity; `prompt=login` forces re-authentication for an
  identity authenticated at the same instant; `prompt=none` with a stale
  identity yields `login_required` via redirect; `prompt=none` combined with
  another `prompt` value yields `invalid_request`; `max_age` against an
  identity with no `auth_time` at all forces re-authentication; a request
  with neither `max_age` nor `prompt=login` is unaffected by a missing
  `auth_time`, preserving existing behaviour exactly.

## 6. Breaking change

`AuthorizeOutcome` gains a variant, and (independently) is marked
`#[non_exhaustive]` for the first time — both breaking changes for any
downstream code that matches on it exhaustively or constructs
`ReauthenticationRequired`/`AuthorizeOutcome` variants directly (the latter
was never possible for tuple-variant construction from outside the crate in
a way `#[non_exhaustive]` further restricts in the same way it already does
for `AuthorizeRequest`). `AuthorizeRequest` itself gains two additive,
`#[serde(default)]` fields — not breaking for deserialization, but breaking
for exhaustive struct-literal construction (already restricted by its
existing `#[non_exhaustive]`, added ahead of this RFC).

Tagged `feat(op)!:` with a `BREAKING CHANGE:` footer so release-plz targets
the next minor as a breaking release. v0.11.0 ships without this work; this
targets **v0.12.0**.

## 7. Out of scope / deferred

- **Threading `reauth.request` through the facade crates' own `/login`
  redirect.** Both `authkestra-axum` and `authkestra-actix` currently drop
  it and redirect to a bare `/login`, exactly like their existing
  no-session branch. A deployment that wants `/login` to resume the
  original request after a fresh login has to carry it itself for now
  (e.g. as query parameters or server-side state) — not fundamentally
  different from the `return_to` encoding both facades already skip for
  the plain unauthenticated case, but worth closing at the same time if
  someone picks it up.
- **Discovery metadata.** `OidcDiscovery` was not updated to add `auth_time`
  to `claims_supported`, matching the precedent already set by RFC-006 (it
  didn't add `acr`/`amr` there either). There is no OIDC-defined
  `max_age`/`prompt` capability flag `claims_supported`-equivalent to add.
- **Issue #382 (enrolment gate) depends on this landing.** #382 wants to
  gate enrolment/re-issuance behind a fresh-enough authentication; this RFC
  is the freshness primitive that gate needs, but #382 will still need, on
  top of what lands here: (a) wiring `handle_enrol_start`/
  `handle_reissue_start` (`crates/authkestra-op/src/handlers/enrolment.rs`)
  to accept a `max_age`-like freshness requirement of their own — those
  handlers don't go through `handle_authorize` at all, so nothing here
  reaches them automatically; (b) a decision on what "fresh enough" means
  for an enrolment ceremony specifically (likely a much shorter window than
  a typical `/authorize` `max_age`, given what enrolment grants); and
  (c) the same "OP signals, application performs" shape decision made here,
  applied to whatever entry point #382 adds.
