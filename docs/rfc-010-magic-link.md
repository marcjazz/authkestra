# RFC-010: Magic-link authentication

> **Status: proposed**, not implemented. This document is the design record for
> the first item on the passwordless-native track (`docs/roadmap.md`), and is
> written to be the shared foundation for the email/SMS OTP work that follows
> it — see §4.9.

## 1. Summary

A magic link authenticates someone by proving they control an inbox: the
application sends them a single-use URL, and following it produces a session.

The engine's part of that is small and worth naming precisely, because most of
what people call "magic link" is not the framework's business. Authkestra owns
**minting a single-use, TTL-bounded, subject-bound token, and consuming it
exactly once to yield an `Identity`**. It does not own the address book, the
mail transport, the email template, or the decision about whether a given
address corresponds to an account.

This RFC fixes that boundary, and settles the handful of design questions where
getting it wrong produces an authentication method that looks correct and is
not: link forwarding, mail-scanner prefetch, account enumeration, and whether
any of this counts as a second factor. (It does not.)

## 2. Motivation

### 2.1. Why this, and why now

The strategic axis is advanced, correct identity primitives rather than the
boring basics. Magic link earns its place on that axis for a specific reason:
it is the most commonly *shipped-wrong* passwordless method. The naive
implementation — a random token in a URL, checked against a database row — has
at least four independent failure modes, all of which are invisible in testing
and all of which are live in production systems today.

It is also the first of three features (magic link, email/SMS OTP, recovery
codes) that share one shape: **the server mints a secret, delivers it out of
band, and later accepts it back exactly once**. Designing that shape once is
the point of doing this one first.

### 2.2. Why the framework cannot just "send the email"

Per decision 0005, Authkestra owns no user table. It does not know that
`alice@example.com` is a user, and it has no way to find out. It equally has no
mail transport, and acquiring one would mean taking a position on SMTP
libraries, queueing, retries, bounce handling and templating — none of which is
authentication.

Every alternative that hides this — a `Mailer` trait with a default SMTP
implementation, say — moves the framework into owning delivery while pretending
it doesn't. There is no `Mailer`, `Sender`, `Notifier` or `Transport` trait
anywhere in the workspace today, and this RFC does not add one.

## 3. What already exists, traced before designing anything

- **`store::AtomicConsume<T>`** is exactly the primitive this needs. The
  workspace already describes the use case, in `AtomicInsert`'s doc comment
  where the two are contrasted: `AtomicConsume` is *"for values the server
  creates and later atomically fetches-and-removes (an authorization code,
  say — the key is only ever seen after this server put it there)"*. A magic
  link token is that shape precisely. **No new store trait is required.**
- **`store::AtomicInsert<T>`** is the complement, for caller-supplied keys
  (a DPoP `jti`). It is *not* what this needs, and the distinction is already
  documented in `store/mod.rs` — worth stating so a future reader does not
  reach for the wrong one.
- **`AuthInput`** already carries feature-gated variants:
  `#[cfg(feature = "webauthn")] WebAuthnAuthentication` and
  `#[cfg(feature = "totp")] Totp`. A magic-link variant follows that
  convention exactly.
- **`AuthMethod`** is the trait to implement: `name()`, `authenticate()`,
  `has_enrolled()`, `is_mfa_equivalent()`.
- **The in-engine-behind-a-feature convention** is settled (#325): `webauthn`
  and `totp` live inside `authkestra-engine` behind Cargo features, forwarded
  through the `authkestra` facade. RFC-001's older "separate
  `authkestra-magic-link` crate" idea predates the unified engine and is
  stale.
- **`ReproofRequirement`** (RFC-009) gates security-posture changes. §4.10
  covers where it does and does not apply here.
- **`Identity`** carries `provider_id`, `external_id`, `email`, `username` and
  an `attributes` map, into which `IDENTITY_ATTR_AMR` and
  `IDENTITY_ATTR_AUTH_TIME` are stamped.

## 4. Design

### 4.1. The boundary, stated once

```
application                          engine
-----------                          ------
resolve address -> subject
                                     mint(subject, ttl) -> MagicLinkToken
render + send the mail
                        ... user follows the link ...
receive the token
                                     authenticate(MagicLink { token })
                                        -> consume exactly once
                                        -> Identity
establish the session
```

The engine never sees an email address unless the application chooses to put
one in the `Identity` it gets back. It never sends anything. It cannot, by
construction, leak whether an address is registered, because it is never told.

### 4.2. Minting is explicit, not a side effect of authenticating

`mint` is a separate call rather than something `authenticate` does when it
fails to find a token. A single entry point that either starts or completes a
flow depending on its argument is how you end up with a method that can be
driven into the wrong half of itself.

```rust
#[non_exhaustive]
pub struct MagicLinkToken {
    /// The secret to place in the URL. Returned exactly once; the engine
    /// keeps only a hash (§4.4).
    pub secret: String,
    /// When it stops being accepted. Absolute, not a duration, so the
    /// application can render it in the mail without recomputing.
    pub expires_at: i64,
}
```

The `secret` is returned by value and never stored in plaintext, so it cannot
be recovered afterwards — not by the application, not by an attacker with
store access. If the mail fails to send, the correct recovery is to mint a new
one.

### 4.3. No default TTL

Following RFC-009 §4.3: there is no default. `mint` takes the TTL explicitly.

A default here would have to be wrong for somebody — 15 minutes is generous for
a consumer login and reckless for an administrative one — and the failure is
silent, because a too-long TTL produces no error, just a wider window. Making
the caller name it means the number appears in their code where a reviewer can
see it.

### 4.4. The store holds a hash, not the token

The engine stores `SHA-256(secret)` as the key, not the secret.

This is not theatre. The store is frequently Redis or Postgres, shared with
other workloads, backed up, and visible to more operators than the application
process is. A store that holds live bearer credentials in plaintext turns a
read-only store compromise — a backup, a replica, a misconfigured `KEYS *` —
into account takeover for every pending link. Hashing makes it useless.

SHA-256 rather than a password hash is correct here and worth justifying: the
secret is 256 bits of CSPRNG output, not a human-chosen password, so there is
no dictionary to attack and nothing for a slow KDF to buy. Argon2 would add
latency to every verification for no gain.

### 4.5. Single use is enforced by the store, not by a flag

Consumption goes through `AtomicConsume::consume`, which fetches and removes in
one operation.

The obvious alternative — store a `used: bool` and set it after checking — is a
TOCTOU race. Two concurrent requests with the same token both read `used:
false` and both succeed. This is not hypothetical: mail clients and security
appliances issue concurrent prefetches of the same URL routinely (§4.7), so the
race is *reached in normal operation*, not only under attack.

`store/mod.rs` already makes this argument for `AtomicInsert` and replay
guards. It is the same argument.

### 4.6. Browser binding is a forced choice, not a default

The classic failure: a link is a bearer credential in a URL, so anyone who
obtains it authenticates. Shared inboxes, forwarded mail, a synced browser
history, a screenshot in a support ticket.

The mitigation is to bind the token to the browser that requested it — set a
nonce cookie at mint time, require it at consume time. The cost is that
"request on my laptop, open on my phone" stops working, which for some products
is the main way it is used.

Neither default is safe to pick on the application's behalf, so the design
does not pick one:

```rust
#[non_exhaustive]
pub enum MagicLinkBinding {
    /// The token is valid only when presented alongside the binding value
    /// issued at mint time. Blocks forwarded links; breaks cross-device.
    SameContext(String),
    /// The token is valid from anywhere. Cross-device works; a forwarded
    /// link authenticates whoever follows it.
    AnyContext,
}
```

`AnyContext` is spelled out rather than expressed as `Option::None`, for the
same reason RFC-009 has no default window: the risky choice should be a thing
someone typed.

### 4.7. Mail scanners will follow the link before the user does

Corporate mail security appliances, link-preview generators and some clients
fetch every URL in a message on arrival. Against a single-use token this is
not a nuisance, it is a **denial of login**: the scanner consumes the token and
the real user gets "this link has expired" on their first click.

This is the most common operational failure of shipped magic-link
implementations, and it cannot be fixed by making the token longer-lived or
multi-use — multi-use is a security regression, and a scanner is as fast as it
likes.

The design's answer is that **following the link must not be the thing that
consumes the token.** The engine consumes on an explicit, application-driven
call, so the application can put a "Sign in" button on the landing page and
consume on the resulting `POST`. A scanner issuing `GET` requests consumes
nothing.

This constrains the API shape: `authenticate` must be callable at a moment the
application chooses, which the split in §4.2 already provides. It is recorded
here because a future refactor that "helpfully" consumes on link resolution
would reintroduce it.

### 4.8. Enumeration is the application's response to write

Whether `POST /login {alice@example.com}` reveals that Alice has an account is
decided entirely by what the application returns, and how long it takes. The
engine cannot influence either: it is handed a subject that the application has
already resolved.

What the engine can do is avoid *forcing* a leak, and it does — `mint` for a
subject that does not exist is not an error case the engine has any view on,
because the engine never validates subjects against anything.

The documentation obligation is real and belongs with this RFC: the guidance
must say to return an identical response either way, and to do the work (or an
equivalent delay) on both paths so timing does not answer the question that the
response body refuses to.

### 4.9. Designed so OTP is the same thing with a different presentation

Email/SMS OTP is the next roadmap item, and it differs from magic link in
exactly two respects: the secret is short enough to be typed, and it therefore
needs attempt-limiting.

The core — mint a subject-bound secret, hash it, store it under a TTL, consume
it once — is identical, and the implementation should be a shared internal
module with two thin public surfaces over it, rather than two parallel
implementations that drift.

The one thing that must *not* be shared is the secret generator: a 6-digit code
is brute-forceable in a way a 256-bit token is not, so OTP needs a per-subject
attempt counter that magic link does not. Recording that now is cheaper than
discovering it when OTP reuses the magic-link path wholesale.

### 4.10. Not a second factor, and `has_enrolled` is honest about it

`is_mfa_equivalent()` returns **`false`**. Proving control of an inbox is one
factor — something you have, loosely — and an account whose recovery address is
the same inbox gains nothing from presenting it twice.

`has_enrolled()` returns **`false`**, always, and this is a deliberate
statement rather than an oversight of the default. There is no enrolment
ceremony: any subject the application can resolve can be sent a link. Returning
`true` would tell the MFA-prompting logic that a factor exists to step up
with, which is false.

This also settles the RFC-009 interaction: the re-proof gate protects
*enrolment*, and magic link has nothing to enrol, so no gated surface is added
here. The gate becomes relevant again at recovery codes, which do enrol.

### 4.11. `amr` is `"magic-link"`, and passes through the mapping unchanged

The `Identity` carries `IDENTITY_ATTR_AMR` set to `"magic-link"`.

Two layers are involved and it matters which is which. `Engine::authenticate`
stamps the `AuthMethod`'s own `name()`; `authkestra-op::amr_acr` then maps that
internal name to the wire value in the issued ID token. The mapping is not a
pass-through — `"password"` becomes `"pwd"`, `"totp"` becomes **both** `"otp"`
and `"totp"`, and RFC 8176's `"mfa"` marker is appended whenever step-up is
satisfied. Every method that exists today therefore emits at least one
registered value.

Magic link adds no arm to that mapping, and that is the right answer rather
than an omission. RFC 8176 registers nothing meaning "followed a link sent to
an inbox": `"otp"` would be a lie (there is no one-time *password* here, and
the thing is not typed), and `"mfa"` is unavailable because §4.10 already
established this is not a second factor. Passing `"magic-link"` through
verbatim is the same call `amr_acr` already makes for `"webauthn"`, for the
same reason — naming the actual mechanism beats asserting a registry term that
overclaims what was verified.

Email/SMS OTP, next on the track, is the opposite case and must **not** copy
this: `"otp"` fits it exactly, and pass-through there would be a real miss.
That asymmetry, and the fact that nothing currently forces a new method to
consider it, is tracked in #395.

## 5. Proposed surface

Behind `#[cfg(feature = "magic-link")]`, in
`authkestra-engine::auth::magic_link`:

```rust
pub struct MagicLinkAuthMethod<S> { /* store: S */ }

impl<S> MagicLinkAuthMethod<S>
where
    S: KvStore<MagicLinkRecord> + AtomicConsume<MagicLinkRecord>,
{
    pub fn new(store: S) -> Self;

    /// Mint a token for an already-resolved subject.
    pub async fn mint(
        &self,
        subject: &str,
        ttl: Duration,
        binding: MagicLinkBinding,
    ) -> Result<MagicLinkToken, AuthError>;
}

#[async_trait]
impl<S> AuthMethod for MagicLinkAuthMethod<S> { /* ... */ }
```

with `AuthInput::MagicLink { token: String, binding: Option<String> }` added
under the same feature gate, and `magic-link = []` in the engine's `[features]`
forwarded through the facade per #325.

`MagicLinkRecord` holds the subject and the binding, never the secret.

## 6. Out of scope / deferred

- **Mail transport, templating and deliverability.** §2.2. No `Mailer` trait.
- **Rate limiting.** Belongs at the HTTP edge where the IP and route are
  visible, not in the engine. The guidance should say so loudly, because an
  unrated mint endpoint is a mail-bombing primitive aimed at a third party.
- **Link-shortening and URL construction.** The engine returns a secret, not a
  URL; it does not know the application's routes.
- **Address verification as a side effect.** Following a link proves control of
  the inbox at that moment, and an application may reasonably treat that as
  verifying the address — but doing so automatically would be the engine
  writing to a user table it does not own.
- **Attempt counting.** Not needed at 256 bits; required for OTP (§4.9).

## 7. Open questions

1. **Should `mint` accept a caller-supplied secret?** Against: it invites weak
   secrets. For: it lets an application that already has a token-issuing
   service keep using it. Leaning against.
2. **Should the engine expose a "resend" that invalidates the previous
   token?** Minting twice currently leaves two live tokens until the first
   expires. Arguably correct — the first mail may simply be slow — but it
   widens the window, and the alternative costs a per-subject index the
   `AtomicConsume` shape does not otherwise need.
3. **Is `SameContext` binding better expressed as an opaque type** than a
   `String`, so the application cannot accidentally bind to something guessable
   (a username rather than a nonce)? Probably yes; costs a type.
