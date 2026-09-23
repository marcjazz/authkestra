# RFC-011: Email and SMS one-time codes

> **Status: implemented**, in `authkestra-engine` (`auth::otp`, feature `otp`)
> as of v0.13.0, including the opt-in resend cooldown from §7.2. Design record
> for the email/SMS OTP item in
> [Phase 2: Passwordless-Native Authentication](./roadmap.md#phase-2-passwordless-native-authentication),
> and the second of the three delivered-secret methods. Read
> [`rfc-010-magic-link.md`](./rfc-010-magic-link.md) first: this document is
> mostly about where OTP **cannot** follow it.

## 1. Summary

An emailed or texted one-time code authenticates the same way a magic link
does — the application delivers a secret out of band and hands it back — and
RFC-010 §4.9 committed to sharing the core rather than writing it twice.

That commitment survives, but it is thinner than it looked from the magic-link
side, and this RFC exists mainly to say why. A code short enough for a person
to type cannot be the store key, which is the single decision everything else
here follows from. It also needs attempt-limiting, and the store trait family
has no primitive that can count safely.

## 2. Motivation

### 2.1. Why OTP at all, when magic link exists

They fail in different places, and the difference is the product case:

- a link is useless in a native app, a terminal, or a set-top box, where there
  is no browser to hand the click to;
- a link cannot be read aloud, and a code can;
- SMS reaches accounts that have a phone number and no working mailbox — which
  is the recovery case, and the reason `sms` is in RFC 8176 at all.

It is also the second of the three methods on this track, and the one that
turns "we have a delivered-secret shape" into something worth having factored.

### 2.2. Why this cannot be magic link with a shorter secret

RFC-010's design rests on the secret being the store key:

```rust
self.store.set(&hash_secret(&secret), record, ttl)
```

That is what gives magic link single-use for free via `AtomicConsume`, and it
is why an unknown, expired or already-used token are indistinguishable there —
all three simply miss.

A six-digit code cannot work that way, for a reason that is easy to miss:
**a wrong code hashes to a key that does not exist, so there is nothing to
attribute the failure to.** The lookup misses and the server has no idea whose
code was being guessed, which means it cannot count the attempt, cannot lock
the challenge, and cannot tell a typo from an attack. An attacker gets
unlimited guesses against the entire keyspace at once, and every guess that
happens to collide with *anybody's* live code succeeds — a cross-account
attack that magic link's 256-bit secret makes arithmetically irrelevant and a
six-digit one does not.

So the key has to be the subject, and the code has to be a value. Everything
below follows from that.

## 3. What already exists, traced before designing anything

- **`auth::magic_link`** (RFC-010): `mint` / `AuthMethod::authenticate`, secret
  hashing via SHA-256, subject-bound record, TTL, `AtomicConsume`.
- **The store trait family**: `KvStore` (`get`/`set`/`delete`),
  `AtomicConsume` (`consume`), `AtomicInsert` (`insert_if_absent`),
  `IndexedKvStore`. **Nothing increments.** §4.3 is about that gap.
- **Two `KvStore` backends**: `MemoryStore` and `RedisStore`. The
  `authkestra-store-sqlx` crate is an `OpStore`, not a `KvStore`, so a new
  store trait costs two implementations plus the shared testsuite, not three.
- **`subtle` is not an engine dependency.** It is used in
  `authkestra-devsig` (`jws_util::constant_time_eq`). §4.7 needs it here,
  which magic link did not.
- **The #395 guard** fails the build until a new first-party method states its
  `amr` mapping. §4.8.
- **TOTP reports `is_mfa_equivalent() == false`**, and is the closest existing
  analogue for how a one-time code should describe itself.

## 4. Design

### 4.1. Keyed by subject, with the code as a hashed value

```rust
#[non_exhaustive]
pub struct OtpChallenge {
    /// SHA-256 of the code. Never the code.
    pub code_hash: String,
    pub channel: OtpChannel,
    pub attempts_remaining: u8,
}
```

stored under a key derived from the subject. Verification loads by subject,
compares hashes, and decides.

The hashing rationale from RFC-010 §4.4 carries over unchanged — a read-only
store compromise must not be account takeover — but with one difference worth
stating, because it cuts the other way: a six-digit code has only 10⁶
preimages, so an attacker holding the *store* can brute-force the hash offline
in microseconds. Hashing here therefore protects almost nothing against a
store compromise.

It is still right to do, for a narrower reason: it keeps live codes out of
logs, backups and replicas that get read by humans and grepped by accident.
Anyone relying on it for more than that has misread the threat model, which is
why this paragraph exists rather than a copy of §4.4's confident version.

### 4.2. One challenge per subject at a time

Minting for a subject replaces any live challenge for that subject.

The alternative — several concurrent codes — multiplies the guessing surface
by the number outstanding for no benefit anybody asked for, and makes "how
many attempts remain" ambiguous. Replacement also gives resend the obvious
semantics, which RFC-010 §7 left as an open question for magic link and which
this answers for OTP: the new code works, the old one stops.

### 4.3. Attempt-limiting needs a primitive that does not exist yet

A six-digit code is 10⁶. Against a five-minute TTL, an attacker at a thousand
requests a second gets 3×10⁵ guesses — better than one chance in four. **The
attempt limit is not a nicety here, it is the only thing making the method
safe**, and that is why it belongs in the engine rather than being deferred to
edge rate limiting the way RFC-010 §6 defers everything else: edge limits are
per-IP, and an attacker rotating IPs walks straight through them. Only a
per-subject counter closes it.

Counting safely is the problem. `attempts_remaining` lives in a record, and
decrementing it means read-modify-write, which is the exact TOCTOU race
`store/mod.rs` already argues against for replay guards — two concurrent wrong
guesses both read 3 and both write 2, so a parallel attacker gets far more
attempts than the limit says. Rejecting that on principle is this codebase's
established position and the right one.

Three ways out, in preference order:

1. **Add `AtomicDecrement` (recommended).** A sibling to `AtomicConsume` and
   `AtomicInsert`, in the same spirit: the store does one operation and
   returns what the count became. Redis has `DECR`, and a SQL backend has
   `UPDATE ... RETURNING`; `MemoryStore` already holds a mutex. Cost is two
   implementations and a testsuite case. This is the honest shape of the
   requirement, and the trait family exists precisely because this kind of
   thing keeps coming up.
2. **Claim attempt slots with `AtomicInsert`.** `insert_if_absent` on a key
   per attempt (`otp:{subject}:try:{n}`); the first caller to claim slot *n*
   owns it, and exhaustion is slot `max` being taken. Correct under
   concurrency and needs no new trait, at the cost of probing upward — up to
   `max` round trips per verification — and key sprawl the TTL has to sweep.
   The fallback if (1) is judged too invasive.
3. **Burn the challenge on the first wrong code**, as magic link does for a
   binding mismatch. Needs no counter at all and is trivially correct. It is
   listed for completeness and rejected: a code exists to be typed by a human,
   a human mistypes, and a method where one slip forces a fresh round trip
   through a mail queue will be the method nobody enables.

### 4.4. Six digits, and the limit is what carries the security

Digits, not alphanumerics: the code gets read off a lock screen, typed on a
phone keypad, sometimes read aloud. Case and character confusion (`0`/`O`,
`1`/`l`) cost more in support than they buy in entropy.

Six of them is 10⁶, which is not a lot, and this RFC is not pretending
otherwise — §4.3's limit is doing the work, not the length. A deployment that
wants more should get it by lowering the TTL, not by lengthening the code past
what people will type.

Generated with the same CSPRNG magic link uses, with **rejection sampling**
rather than `% 1_000_000`. Modulo over a uniform 32-bit draw biases the low
codes measurably, and a biased OTP is a smaller keyspace wearing the right
number of digits.

### 4.5. The channel is the engine's business, unusually

Everything else about delivery stays the application's, exactly as in RFC-010
§4.1 — no transport, no templates, no address book.

The channel is the exception, and only because the wire format forces it:
RFC 8176 registers `sms`, so an SMS code and an emailed one produce *different*
`amr` claims. The engine cannot map what it was not told, so `mint` takes an
`OtpChannel`:

```rust
#[non_exhaustive]
pub enum OtpChannel { Email, Sms }
```

This is not the engine acquiring an opinion about delivery. It never sends
anything and never sees an address. It records which claim to emit, because it
is the only component positioned to.

### 4.6. Consume on success, burn on exhaustion

A correct code consumes the challenge — single use, as with magic link.

A wrong code decrements. At zero the challenge is deleted rather than left to
expire, so an exhausted challenge and an unknown one look identical and there
is no "you have used up your attempts" oracle telling an attacker they had the
right subject.

Every failure — unknown subject, wrong code, exhausted, expired — returns
`AuthError::InvalidCredentials`, as RFC-010 established. The distinction is
logged, not returned.

### 4.7. Here the comparison must be constant-time

RFC-010 argued that magic link's binding check does not need a constant-time
comparison, because a mismatch burns the secret and an attacker therefore gets
exactly one attempt.

**That argument does not transfer, and assuming it did would be the subtlest
bug in this design.** OTP's whole point is that several attempts are allowed,
which is precisely the condition that makes a timing oracle exploitable: an
attacker with a few attempts per challenge and unlimited challenges can use
early-exit timing on the hash comparison to learn a prefix, and a prefix
collapses 10⁶ fast.

So the code-hash comparison uses a constant-time equality. `subtle` is already
in the workspace via `authkestra-devsig`; this adds it to `authkestra-engine`
behind the OTP feature.

### 4.8. `amr` is `otp`, plus `sms` on that channel

The #395 guard will fail the build until this is stated, which is the point of
it. The mapping is the case that guard was written for — see the warning left
on the magic-link row:

| channel | `amr` |
| --- | --- |
| email | `["otp"]` |
| SMS | `["sms", "otp"]` |

Both values are RFC 8176 registered, so unlike magic link this method is fully
legible to a relying party matching strictly against the registry. `sms` comes
first as the more specific term, matching how the `totp` row orders the
specific value alongside the generic one.

`is_mfa_equivalent()` is **`false`**, matching TOTP: a delivered code is one
factor. `has_enrolled()` is **`false`** for the same reason as magic link —
there is no enrolment ceremony, so RFC-009's re-proof gate adds no surface
here either.

### 4.9. What is actually shared with magic link

RFC-010 §4.9 said the core was "mint a subject-bound secret, hash it, store it
under a TTL, consume it once", with only the generator differing. That was
optimistic. What genuinely factors out is:

- CSPRNG secret generation (different alphabets, same source);
- SHA-256 hashing of a secret;
- the subject-bound, TTL-bounded record;
- single use on success;
- the uniform-failure discipline.

What does not, and should not be forced to:

- **the key**: the secret for magic link, the subject for OTP (§2.2);
- **when consumption happens**: on presentation for magic link, on success for
  OTP (§4.6);
- **attempt state**: magic link has none by construction;
- **binding**: `MagicLinkBinding` has no OTP analogue — a code typed into the
  page that requested it is already same-context, and there is no URL to
  forward.

So the shared piece is a small internal module — secret generation and
hashing — not a shared record type or a shared verification path. Forcing the
latter would produce a type with two half-used halves, which is worse than two
readable methods that share their primitives.

## 5. Proposed surface

Behind `#[cfg(feature = "otp")]`, in `authkestra-engine::auth::otp`:

```rust
pub struct OtpAuthMethod<S> { /* store: S */ }

impl<S> OtpAuthMethod<S>
where
    S: KvStore<OtpChallenge> + AtomicConsume<OtpChallenge> + AtomicDecrement<OtpChallenge>,
{
    pub fn new(store: S) -> Self;

    /// Mint a code for an already-resolved subject, replacing any live
    /// challenge for it.
    pub async fn mint(
        &self,
        subject: &str,
        ttl: Duration,
        channel: OtpChannel,
        max_attempts: u8,
    ) -> Result<OtpCode, OtpError>;
}
```

with `AuthInput::Otp { subject: String, code: String }` under the same gate,
`otp = ["dep:subtle"]` in the engine's `[features]`, and facade forwarding per
#325.

`max_attempts` is explicit for the reason RFC-010 §4.3 gives for TTL: any
default is wrong for somebody and the failure is silent.

## 6. Out of scope / deferred

- **Delivery.** As RFC-010 §2.2. No `Mailer`, no SMS gateway, no templates.
- **Edge rate limiting.** Still belongs at the HTTP edge — §4.3 adds a
  per-subject limit because edge limits cannot survive IP rotation, not as a
  replacement for them. An unrated mint endpoint is a toll-fraud primitive
  when the channel is SMS, which is worse than the mail-bombing case RFC-010
  warned about.
- **Phone-number verification and portability.** SIM swap is real and is not
  something this layer can detect.
- **TOTP.** Already exists and is unrelated: no delivery, no server-held
  challenge.

## 7. Open questions

1. **Is `AtomicDecrement` the right name and shape**, or should it be a
   general `AtomicApply`/compare-and-swap that the next counter can also use?
   A narrow trait is easier to implement correctly on every backend; a general
   one is likelier to be reused. Leaning narrow.
2. ~~**Should `mint` refuse to replace a challenge younger than some floor**,
   as a cheap resend-abuse brake, or is that entirely the edge's job?~~
   **Settled: yes, and not the edge's job alone.** `with_resend_cooldown`
   makes it opt-in and off by default, for the reason §4.2 gives about
   defaults generally. The argument for putting it in the engine at all is
   the one the attempt budget already rests on: edge limits are per-IP and an
   attacker rotating addresses walks through them, while the abuse — spending
   the operator's money on SMS, and burying a victim's phone — is per-subject.
   Enforced with `AtomicInsert::insert_if_absent`, so simultaneous requests
   cannot both find the coast clear, and the TTL handles expiry. Note that
   primitive floors its TTL at one second, so the cooldown does too.
3. **Does `OtpChannel` want a third variant** for voice delivery, which RFC
   8176 also registers (`tel`)? Cheap to add now, breaking to add to a
   `#[non_exhaustive]` enum later only in the sense that every match must
   already handle it.
