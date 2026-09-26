# RFC-012: Recovery codes as a look-up secret authenticator

> **Status: implemented**, in `authkestra-engine` (`auth::recovery`, feature
> `recovery-codes`) as of v0.13.0. Design record for the third and last
> item in
> [Phase 2: Passwordless-Native Authentication](./roadmap.md#phase-2-passwordless-native-authentication).
> It is the first method on that track that actually **enrols**, which is what
> makes it different from

## 1. Summary

A set of codes, generated once, shown once, each usable once — the thing you
print and put in a drawer for the day your phone is in a river.

NIST SP 800-63B §5.1.2 calls this a **look-up secret authenticator**, and this
RFC uses that term deliberately. "TOTP recovery codes" is the common framing
and it is the wrong one here: these are a fallback for *whatever* the account
has registered — passkey, TOTP, magic link, OTP — not an appendix to one of
them.

Two things make it a different shape from the two methods before it. It
**enrols**, so it is gated, and it is the first caller RFC-009's gate has ever
had. And its codes are **long-lived**, so the "it expires in five minutes"
argument that carried a lot of weight in RFC-010 and RFC-011 is unavailable
here.

## 2. Motivation

### 2.1. What breaks without it

Every method on this track can be lost in a way the account cannot recover
from alone: a passkey lives in a device, a TOTP secret lives in an app, a
magic link needs a mailbox, an OTP needs a mailbox or a phone number. An
account whose only factors are device-bound or inbox-bound has no path back
when the device or the inbox is gone.

Without a fallback, that path is a support ticket — which is to say, it is
social engineering with a queue in front of it. The recovery path is the one
attackers actually use, and a designed one is better than an improvised one.

### 2.2. Why factor-agnostic, not "TOTP recovery"

Tying recovery codes to one method reproduces the problem they exist to
solve. An account that enrolled a passkey and no TOTP would have no recovery
codes, because the codes belong to a factor it never registered.

So they are their own `AuthMethod`, keyed by subject and independent of what
else the account has. The account has *a set of look-up secrets*, not
*TOTP's backup codes*.

## 3. What already exists, traced before designing anything

- **`ReproofRequirement`** (RFC-009): `check(&Identity)`, `require_step_up`.
  Built specifically so enrolment surfaces would be gated when they arrived
  rather than retrofitted. RFC-009 §7 names recovery codes as one of the three
  it was waiting for. This is the first of them to need it.
- **`TotpAuthMethod::register_totp(&Identity, &ReproofRequirement, ..)`** is
  the shape to follow: `gate.check(identity)?` first, `user_id` taken from
  `identity.external_id` and never passed alongside it (RFC-009 §4.6).
- **`CredentialStore`**: `save_credential`, `get_credentials`,
  `update_credential`, `delete_credential`, `delete_credentials`. The last two
  default to `Err(AuthError::Unsupported)`, so deletion is **not** something
  every store provides. §4.4 is about what that costs.
- **`AtomicConsume`** exists but is a `KvStore` primitive, and `KvStore::set`
  requires a `Duration` — there is no "no expiry". Recovery codes are not
  TTL-bounded state, so they belong in `CredentialStore`, which means the
  atomic-consume trick RFC-010 and RFC-011 both leaned on is **not available
  here**. §4.4.
- **The #395 guard** will fail the build until an `amr` row is stated.
- **`has_enrolled`** returns `false` for magic link and OTP, and is the
  signal `ReproofRequirement::require_step_up` callers use to decide whether
  to demand step-up. Recovery codes are the first method for which it is
  meaningfully `true`. §4.7.

## 4. Design

### 4.1. A set, generated and shown once

`generate` produces N codes, returns them once, and stores only hashes. There
is no "show me my codes again": the set is regenerated or it is gone.

Each code is its own credential rather than the set being one blob. That is
not a storage preference, it is what makes single use enforceable — see §4.4.

### 4.2. Entropy, and why 64 bits rather than the minimum

NIST SP 800-63B §5.1.2 permits look-up secrets as low as 20 bits, provided
the verifier throttles. This design takes the other branch and requires **at
least 64 bits**, so no throttling is needed.

The reasoning is the one RFC-011 §4.3 had to confront: a throttle is only as
good as the thing enforcing it, and a per-subject counter for a long-lived
secret has nowhere natural to live. OTP could hang an attempt budget off a
challenge with a five-minute TTL; a recovery code set lives for years, so an
equivalent budget would be a permanent counter that has to be reset, aged, or
explained. Choosing enough entropy that guessing is irrelevant removes the
whole apparatus.

Concretely: 10 codes of 80 bits, rendered base32 in groups, e.g.
`4KDW-9JMQ-2XPT-R7HV`. Base32 rather than base64 because these get read off
paper and typed — no case sensitivity, no `+/`.

### 4.3. Hashing: the one place a KDF is arguable

RFC-010 hashes with SHA-256 and argues a KDF buys nothing over 256 bits of
CSPRNG output. RFC-011 hashes with SHA-256 and admits it buys almost nothing
at all over 10⁶.

Recovery codes sit between, and are the only one of the three where the
question is genuinely open, because they are the only **long-lived** secret.
A store compromise exposes hashes an attacker can work on indefinitely rather
than for five minutes.

It still lands on SHA-256, for the same reason as RFC-010: 80 bits of uniform
random has no dictionary, so a memory-hard KDF slows an attacker by a constant
factor against a search space that is already infeasible. What a KDF would
actually buy is protection against *low-entropy* secrets, which §4.2 has
already ruled out by construction.

Recording it because a reader who sees SHA-256 on a long-lived credential
should find an argument, not a habit.

### 4.4. Single use has to be won, and `CredentialStore` does not yet promise it

This is the load-bearing section, and the lesson is borrowed directly from
#402's review: **a delete that happens after a check is not single use.**

`CredentialStore::delete_credential` already returns
`Ok(true)` if the credential existed and was deleted, `Ok(false)` if it did
not. That is exactly the shape of a winner signal — one caller gets `true`,
everyone else gets `false` — but **the contract does not say it is atomic.**
A store implementing it as "look it up, then delete it" satisfies the
documentation as written and lets two concurrent redemptions of the same code
both observe `true`.

Relying on it as-is would repeat the #402 defect exactly: a guarantee that
holds in serial tests and dissolves under a multi-threaded runtime.

So this RFC proposes **tightening the existing contract** rather than adding
a primitive:

> `Ok(true)` means *this call* removed the credential. Implementations must
> ensure that among concurrent callers naming the same `credential_id` at
> most one observes `true`.

Every in-tree store can satisfy that (a `DELETE ... RETURNING`, a single
`HDEL`, a map removal under a lock), and out-of-tree stores that cannot
already have `Unsupported` to return. Redemption then becomes: look up the
hash, and accept **only if** `delete_credential` returns `true`.

The alternative — storing the set as one credential and rewriting it through
`update_credential` — is read-modify-write, and is rejected for the same
reason `store/mod.rs` rejects it for replay guards and RFC-011 §4.3 rejects
it for attempt budgets.

### 4.5. Regeneration replaces the whole set, and the order matters

`generate` on an account that already has codes replaces them.

`delete_credentials` first and then `save` leaves a window where the account
has no recovery path, and that window is exactly when a user is most likely
to be mid-panic. Write the new set first, then delete the old one by id —
the same ordering `register_totp` already uses and documents.

The cost is a window where both sets are live, which is the right way round:
briefly having two valid sets is a smaller failure than briefly having none.

### 4.6. Gated on enrolment, and the bootstrap problem is real

`generate` takes a `&ReproofRequirement` and calls `gate.check(identity)?`
before anything else, exactly as `register_totp` does.

`require_step_up` is where it gets interesting, and RFC-009 already flagged
why: an account with no second factor has nothing to satisfy it with, so
demanding step-up for first-time enrolment locks the feature behind itself.
Recovery codes make that sharper than TOTP did, because they are plausibly
the *first* thing an account enrols — a passkey-only account setting up its
fallback has no second factor by definition.

This RFC does not resolve it by picking a default. It resolves it by
**refusing to pick**: `generate` takes the requirement from the caller, and
the documentation states the intended pattern — set `require_step_up` from
`has_enrolled`, so an account that already has a factor must use it, and one
that does not is gated on freshness alone. That is the guidance RFC-009 §4.2
already gives; this RFC is where it stops being hypothetical.

### 4.7. `has_enrolled` is true, and that is a first

Magic link and OTP both return `false` because neither has an enrolment
ceremony. Recovery codes do, so `has_enrolled` reports whether a live set
exists — and it is load-bearing rather than informational, because it is
exactly the signal §4.6 tells callers to drive `require_step_up` from.

It must therefore mean "has at least one **unredeemed** code", not "has ever
generated a set". An account down to zero codes has no fallback, and
reporting otherwise would tell the gate a factor exists to step up with.

### 4.8. Not MFA-equivalent, but it satisfies step-up

`is_mfa_equivalent()` is **`false`**. That flag asks whether this method used
*as the sole primary factor* is worth as much as primary-plus-step-up, and a
printed code is not: anyone holding the paper holds the account.

Used as a step-up it satisfies the tier through the ordinary step-up
machinery, which is the point of the method and is unaffected by that flag.
The distinction is the same one TOTP already draws.

Worth stating because "recovery codes are a second factor" is exactly the
reasoning that would set this flag to `true` and quietly let a code alone log
somebody in.

### 4.9. Telling the user how many are left

`remaining(&Identity)` returns a count.

Not an oracle worth worrying about: it takes an authenticated identity, and
it tells the account's owner something they need in order to regenerate
before running out. The alternative — discovering you are out of codes at the
moment you need one — is the failure this whole method exists to prevent.

### 4.10. `amr` is `recovery-code`, passed through

RFC 8176 registers nothing for a look-up secret. `otp` would be a lie (this
is neither one-time-password machinery nor time-based), and `mfa` is ruled
out by §4.8.

So it passes through as its own name, the same decision magic link's row
records and for the same reason: name the mechanism rather than overclaim a
registry term. The #395 guard will require the row to be written, which is
what it is for.

## 5. Proposed surface

Behind `#[cfg(feature = "recovery-codes")]`, in
`authkestra-engine::auth::recovery`:

```rust
pub struct RecoveryCodeAuthMethod<S: CredentialStore> { /* store: S */ }

impl<S: CredentialStore> RecoveryCodeAuthMethod<S> {
    pub fn new(store: S) -> Self;

    /// Generate and return a fresh set, replacing any existing one.
    /// The only time the codes are ever readable.
    pub async fn generate(
        &self,
        identity: &Identity,
        gate: &ReproofRequirement,
        count: u8,
    ) -> Result<Vec<String>, AuthError>;

    /// How many unredeemed codes remain.
    pub async fn remaining(&self, identity: &Identity) -> Result<usize, AuthError>;
}
```

with `AuthInput::RecoveryCode { user_id: String, code: String }` under the
same gate, and facade forwarding per #325.

`count` is explicit, for the reason RFC-010 §4.3 gives about TTL: a default
would be obeyed more often than reviewed.

## 6. Out of scope / deferred

- **Delivery.** As RFC-010 §2.2 — the codes are returned, not sent. Whether
  they are rendered as a PDF, a printable page or a clipboard blob is the
  application's.
- **Reminding an account it is low on codes.** §4.9 exposes the count; acting
  on it is application policy and probably an email, which this framework
  does not send.
- **Revoking a single code.** Regeneration replaces the set. A per-code
  revocation API has no obvious caller.
- **Admin-initiated recovery.** A support agent resetting an account is a
  different ceremony with a different threat model, and giving it this
  method's surface would make the audit story worse rather than better.

## 7. Open questions

1. **Does tightening `delete_credential`'s contract (§4.4) need a conformance
   test in `authkestra-store-testsuite`?** Every other atomicity promise on
   this track got one, and consistency says yes — but that suite covers
   `KvStore` and `OpStore` (`kv.rs`, `atomic.rs`, `op.rs`, `tx.rs`) and has no
   `CredentialStore` module at all, so it means opening one rather than adding
   a case.
2. **Should `generate` refuse when `remaining()` is still high**, to stop an
   accidental regeneration invalidating a set the user has already printed?
   Argues against itself: the caller may be regenerating *because* the old set
   leaked.
3. **Is `count` a `u8` with a documented sane range, or should the engine
   enforce bounds?** Ten is conventional; one is a footgun and 255 is
   pointless.
