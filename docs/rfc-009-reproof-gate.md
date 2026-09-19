# RFC-009: Re-proof gating for security-posture changes

> **Status: implemented**, in `authkestra-engine` (`auth::reproof`, and the
> gated enrolment surfaces `TotpAuthMethod::register_totp`,
> `WebAuthnAuthMethod::start_register` /
> `start_register_with_handle` / `finish_register`). This document is the
> design record for issue
> [#382](https://github.com/marcjazz/authkestra/issues/382), and picks up the
> thread `docs/rfc-007-max-age-reauth.md` §7 left open.

## 1. Summary

Enrolling a second factor is one of the operations that should demand a fresh
re-proof of identity rather than just a live session. Authkestra had no
mechanism for that and no guidance saying the application must supply one.

This RFC adds one: `ReproofRequirement`, a small, method-agnostic check that
answers *how recently, and how strongly, did this identity prove itself?*
against the attributes `Engine::authenticate` already stamps. The built-in
enrolment surfaces now take one and refuse to write anything that does not
satisfy it.

## 2. Motivation

### 2.1. The attack

If someone holds a session they should not — a stolen cookie, XSS, an
unlocked laptop — and the enrolment endpoint is not gated, they can enrol
**their own** TOTP secret or passkey against the victim's account. They then
hold a factor the real owner does not know about, and on many designs can
pull the recovery codes too. The account ends up more firmly theirs than the
owner's.

This is the pattern GitHub, Google, Oracle and Namecheap all guard with a
re-authentication prompt before touching security settings.

### 2.2. Why the usual fix is unavailable

The common implementation requires the account password — better-auth's
`twoFactor.enable({ password })`, for instance. Authkestra structurally
cannot offer that:

- there is no first-party end-user password concept. `BasicAuthenticator`
  delegates validation to the application, and the `argon2` usage in
  `authkestra-engine` hashes OAuth **client** secrets, not user passwords;
- per decision 0005 the framework owns no user table.

"Re-enter your password" is not a thing this framework is in a position to
ask for.

### 2.3. Which is the better answer anyway

A gate that demands one named factor is wrong for an account that does not
have it. A social-login-only or passwordless account has no password to
re-enter; requiring one would either lock those accounts out of enrolment or
force an escape hatch that swallows the guarantee.

So the gate asks a question every account can answer, and leaves *with what*
to whatever the account actually has.

## 3. What already existed, traced before designing anything

- **Step-up is a first-class primitive**: methods registered step-up-only,
  `AuthInput::MfaChallenge`, MFA continuation tokens
  (`MfaTokenClaims`).
- **RFC-006 (#380)** stamps `IDENTITY_ATTR_AMR`,
  `IDENTITY_ATTR_STEP_UP_SATISFIED` and `IDENTITY_ATTR_AUTH_TIME` onto every
  `Identity` that comes out of `Engine::authenticate`.
- **RFC-007 (#383)** turned `auth_time` into an enforceable freshness
  requirement at `/authorize`, and settled the semantics — inclusive
  comparison, `max_age=0` meaningful, missing `auth_time` fails closed.
- **`Session` stores the whole `Identity`**, `attributes` included. So
  `auth_time` and `step_up_satisfied` survive into the session store, and a
  handler holding a session already has everything a gate needs. Nothing new
  has to be persisted, and no new store trait is involved.

What was missing is the enforcement half for operations that never go
through `/authorize` at all.

## 4. Design

### 4.1. Signal, don't perform

`ReproofRequirement::check` returns a verdict. It never runs a login.

This is RFC-007 §4.1's shape, reached the same way: this framework owns no
login UI, so it cannot display a form, verify a password, or run a WebAuthn
ceremony. It can only recognise that the identity in hand is not fresh enough
and say so precisely enough for the caller to act.

`ReproofFailure`'s variants are distinguishable because the remedies differ:
`Stale` and `FreshnessUnknown` send the user to a re-login, while
`StepUpNotSatisfied` sends them to a step-up challenge — they are still who
they said they were, they just have not proved it strongly enough for this
particular operation.

### 4.2. Two dimensions, not one

```rust
#[non_exhaustive]
pub struct ReproofRequirement {
    pub max_age_secs: u64,
    pub require_step_up: bool,
}
```

`max_age_secs` alone would let an account that already has a second factor
add another one on the strength of the primary factor alone — which is
exactly the escalation path a stolen session takes. `require_step_up` closes
it by reading `IDENTITY_ATTR_STEP_UP_SATISFIED`.

It is off by default, and deliberately so: an account with no second factor
*yet* has nothing to satisfy it with, so gating first-time enrolment on it
would lock the feature behind itself. Callers that want both behaviours set
it from whether the user already has an enrolled factor
(`AuthMethod::has_enrolled`).

### 4.3. No default window

`ReproofRequirement::new` takes the window; there is no `Default`.

What counts as fresh depends entirely on what the gated operation grants —
enrolling a factor that will outlive the session is not the same decision as
revealing an email address — and a framework-chosen number would be obeyed
far more often than it was reviewed.

### 4.4. Freshness semantics, identical to RFC-007 §4.3

A gate that answered "is this proof recent enough" differently depending on
which entry point asked would be worse than either answer alone, so these
match `/authorize` exactly:

- **Missing or unparseable `auth_time` fails closed**, as
  `FreshnessUnknown`. An `Identity` that never passed through
  `Engine::authenticate` carries no evidence of when — or whether — it
  freshly authenticated. Treating "we don't know" as "recent enough" would
  make the gate silently absent for exactly the federated and
  application-constructed identities most likely to reach it. A malformed
  value is treated as a missing one: it is the same amount of evidence,
  which is none.
- **The comparison is inclusive.** `now - auth_time >= max_age_secs` is
  stale. `auth_time` has whole-second granularity, so a strict `>` would let
  an authentication landing in the same wall-clock second as the request
  satisfy `max_age_secs == 0`.
- **`max_age_secs == 0` is meaningful, not "unset"**, and follows from the
  above: every call must be preceded by a fresh authentication.

One addition RFC-007 did not have to make: **an `auth_time` in the future is
treated as fresh, not rejected.** It is reachable through ordinary clock skew
between instances of the same deployment, which this crate already tolerates
elsewhere (`token::DEFAULT_LEEWAY_SECS`), and failing on it would break a
correctly configured deployment for a condition the calling side cannot fix.
It is not a bypass: the value is stamped server-side by
`Engine::authenticate` and reaches the check from the caller's own session
store, never from the client.

### 4.5. Only the first failure is reported, and staleness comes first

Staleness subsumes step-up: an identity that has to re-prove from scratch
re-establishes step-up on the way through. Reporting `StepUpNotSatisfied` for
an identity that is *also* too old would send the caller after the narrower
of the two remedies.

### 4.6. The account is named by the identity, never beside it

This is the part that is easy to get wrong, and the reason the enrolment
signatures changed shape rather than just gaining an argument.

A gate of the form `enrol(user_id, identity, requirement)` reinstates the
same vulnerability one level up: a freshly re-proved session for *one*
account could name *another* account's id, and the check would pass. The
confused deputy is the caller, and no amount of freshness fixes it.

So the enrolment surfaces derive the credential-store key from
`identity.external_id`:

```rust
// before
totp.register_totp(user_id, issuer, account_name)
// after
totp.register_totp(&identity, &gate, issuer, account_name)
```

This is not a new contract, only a newly enforced one. `AuthInput::Totp`'s
`user_id` is already the credential-store key, and `Engine::authenticate`
already rejects a step-up whose verified identity does not match the `sub`
its continuation token names — so `external_id` was always the id enrolment
had to file under for authentication to work afterwards. The signature now
makes it impossible to do otherwise.

`WebAuthnAuthMethod::start_register_with_handle` keeps `handle` as an
explicit argument, because an application that maintains its own handle index
is the whole reason that method exists. The credential is still filed under
`identity.external_id` at completion.

### 4.7. Gate the start of a ceremony, and bind the subject into its state

WebAuthn registration is two calls. The check runs in
`start_register_with_handle` — the choke point `start_register` delegates to,
so it runs exactly once per ceremony — and not again in `finish_register`.
Re-checking at the end would buy nothing and would fail a user whose window
expired while they were touching their authenticator.

That leaves §4.6's problem in the second half. `webauthn-rs`' own
`PasskeyRegistration` is opaque and says nothing about *who* the ceremony was
opened for, so `finish_register(identity, response, state)` would let the two
arguments disagree — the same confused-deputy shape, moved to completion. An
earlier revision of this design took the `Identity` at completion and called
that sufficient; it was not. Nothing related the identity at finish to the one
whose re-proof minted the state, so the guarantee was a caller contract
described as an enforced property.

So the subject is bound into the ceremony state instead:

```rust
#[non_exhaustive]
pub struct PasskeyEnrolment {
    pub subject: String,          // external_id whose re-proof opened this
    pub state: PasskeyRegistration,
}
```

`start_register*` returns one; `finish_register` consumes one and takes no
account argument at all. This removes the possibility rather than checking for
it — there is no second argument left to mismatch. It is deliberately
*stronger* than validating a passed-in identity against the state, which would
have caught the mismatch but still required the caller to supply something it
could get wrong.

`PasskeyEnrolment` is `Serialize`/`Deserialize` because the application has to
carry it across the round trip to the authenticator (`authkestra-engine`
enables `webauthn-rs`' `danger-allow-state-serialisation` for exactly this).
It is server-side state: handing it to the client would let the client choose
the account the credential lands on.

## 5. Implementation summary

| | |
| --- | --- |
| `crates/authkestra-engine/src/auth/reproof.rs` | New. `ReproofRequirement`, `ReproofFailure`, `From<ReproofFailure> for AuthError`, and the module's tests. |
| `auth/mod.rs` | Exports `reproof`, `ReproofRequirement`, `ReproofFailure`. |
| `auth/totp.rs` | `register_totp` takes `&Identity` + `&ReproofRequirement` in place of `user_id`; checks before touching the store. |
| `auth/webauthn.rs` | `start_register` / `start_register_with_handle` take `&Identity` + `&ReproofRequirement` and return a `PasskeyEnrolment`; `finish_register` consumes one and takes no account argument. |
| `examples/totp_webauthn.rs` | Shows building the gate and where a failure sends the user. |

`ReproofFailure` maps to `AuthError::Credentials`, not `InvalidInput`:
nothing about the request was malformed. The caller presented a valid
identity whose proof was not good enough for what it asked to do.

## 6. Breaking change

`register_totp`, `start_register`, `start_register_with_handle` and
`finish_register` all change signature. There is no deprecation window and no
ungated variant left behind, which is deliberate: a security gate that ships
alongside the unguarded call it replaces is a gate most callers never adopt,
and the old spelling is exactly the vulnerable one.

The migration is mechanical — replace the `user_id` argument with the
`Identity` the session already holds, and add a window:

```rust
// before
let (secret, uri) = totp.register_totp(&user.id, "Acme", &user.email).await?;

// after
let gate = ReproofRequirement::new(300)
    .require_step_up(totp.has_enrolled(&user.id).await?);
let (secret, uri) = totp
    .register_totp(&session.identity, &gate, "Acme", &user.email)
    .await?;
```

## 7. Out of scope / deferred

- **The `authkestra-op` enrolment handlers.**
  `handlers::enrolment`'s `handle_enrol_start` / `handle_reissue_start` cover
  *device attestation* enrolment, which already carries its own
  `SecondFactorVerifier` and a `cnf.jkt` continuity check. They are a
  different ceremony with a different threat model, and giving them a
  `ReproofRequirement` as well is a separate decision — RFC-007 §7 named it,
  and it stays named rather than settled here.
- **Recovery codes, magic link, email/SMS OTP.** These do not exist yet.
  Issue #382 asked for the gate to land *before* them rather than after,
  precisely so their enrolment surfaces are built against it instead of
  retrofitted; that is what this RFC delivers, and each of those features
  picks up the gate when it lands.
- **A session-level "recently re-proved" marker.** Nothing here records that
  a re-proof happened, so two gated operations in a row each measure against
  the same original `auth_time`. That is the conservative behaviour and
  costs nothing while the gated set is small. If a flow ever needs "re-prove
  once, then do three things", it wants a re-proof token with its own short
  TTL — closer in shape to `MfaTokenClaims` than to anything in this RFC.
- **Gating on a specific `amr` value.** `require_step_up` is binary because
  `authkestra-engine`'s step-up model is binary (RFC-006 §4). An operation
  that wants "specifically a passkey, not a TOTP code" would need the `amr`
  vocabulary exposed as a requirement; `ReproofRequirement` is
  `#[non_exhaustive]` so that can arrive without breaking callers.
