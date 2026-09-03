# Research spike: ML-DSA (post-quantum) support for WebAuthn passkeys

- **Issue:** [#275](https://github.com/marcjazz/authkestra/issues/275) — `engine(webauthn): add ML-DSA (post-quantum) support for passkey attestation`
- **Scope:** research only. This spike changes no `.rs` and no `Cargo.toml` file.
- **Date of research:** 2026-09-02. Every external claim below is dated, because this area is moving.
- **Recommendation (short):** **wait for upstream** — track, do not build. See [§5](#5-recommendation).

---

## 0. TL;DR

There is nothing to implement yet, and the blocker sits one layer below `webauthn-rs`.

1. The COSE code points exist and are stable (`ML-DSA-44 = -48`, `-49`, `-50`, RFC 9964).
2. But **WebAuthn itself does not use them**. WebAuthn Level 3 reached W3C Recommendation on 2026-08-25 with no post-quantum content; the only WebAuthn/ML-DSA binding is an *individual* IETF draft with no working group behind it; FIDO has a PQC *study group* rather than a CTAP profile.
3. `webauthn-rs` has no ML-DSA support, no PQC issue, no PQC branch, and — critically — **no extension point**: `COSEAlgorithm` is a closed `#[repr(i32)]` enum and `COSEKeyTypeId` has no `AKP` variant, so an ML-DSA credential is rejected during CBOR parsing at *registration*, long before any signature-verification hook could be reached. Verifying ML-DSA outside `webauthn-rs` is therefore **possible, but only by duplicating most of its registration pipeline** — which makes it the highest-risk option rather than the pragmatic middle one; see [§5](#5-recommendation).
4. Rust ML-DSA crates are license-clean and healthy, but all of them are unaudited — and that is the smallest of the four problems.
5. The "fragmented CTAP-HID payloads" item in #275 is an authenticator↔client transport concern. Authkestra is a server-side library that never sees a CTAP-HID frame. It is **out of scope**.

Building anything today would mean inventing a credential format that no authenticator produces and no browser will send.

---

## 1. `webauthn-rs` upstream

### 1.1 Versions

| Fact | Value | Source |
| --- | --- | --- |
| `webauthn-rs` max stable on crates.io | **0.5.5** (2026-04-30) | [crates.io API](https://crates.io/api/v1/crates/webauthn-rs) |
| Newest published (pre-release) | `0.6.1-dev` (2026-04-30) | same |
| Declared in `crates/authkestra-engine/Cargo.toml` | `"0.5.0"` | local |
| **Actually resolved in `Cargo.lock`** | **0.5.5** | local (`Cargo.lock`) |
| `webauthn-rs-core` max stable | 0.5.5, MPL-2.0 | [crates.io API](https://crates.io/api/v1/crates/webauthn-rs-core) |
| Repo default branch / last push | `master`, 2026-08-19 | GitHub API |
| License | **MPL-2.0** | GitHub API |

Note a correction to #275's framing: the `"0.5.0"` requirement is a caret range, and this workspace **already builds against 0.5.5**. The blocker is not staleness — 0.5.5 has no ML-DSA either.

MPL-2.0 is on this repo's `deny.toml` allow-list, so a fork would not fail `cargo deny check licenses`. MPL is file-level copyleft, so a fork would have to publish its modified files — fine legally, but it means a fork is a *maintained public artifact*, not a private patch.

### 1.2 Search for PQC work upstream

- GitHub issue/PR search across `repo:kanidm/webauthn-rs` for `ML-DSA OR Dilithium OR post-quantum OR PQC`: **1 hit**, a false positive — [PR #581 "Credential ID Length Limited to 4096 Bytes"](https://github.com/kanidm/webauthn-rs/pull/581) (merged 2026-08-19), which caps *credential IDs*, not public keys or signatures. Incidentally that cap would not block ML-DSA: public keys are 1312–2592 bytes and signatures 2420–4627 bytes, and neither travels in the credential ID.
- The same search across all of `org:kanidm`: **7 hits, none of them PQC work on WebAuthn** — PR #581 again, 5 Dependabot "Bump the all group" PRs, and [kanidm/kanidm#4091](https://github.com/kanidm/kanidm/issues/4091), a human-authored Kerberos ticket-authentication design issue that matches only on a passing "post-quantum" mention and has nothing to do with `webauthn-rs`.
  <br>*(Correction: an earlier revision of this document reported 5 hits, all Dependabot. That query carried an `in:title,body` qualifier which narrowed the result; the unqualified search returns 7. The conclusion is unchanged, but the count and characterisation were wrong.)*
- Branches on `kanidm/webauthn-rs`: `master`, `4.8-release`, `4.9-release`, `6.0-dev-drop-openssl`, `219-add-hybrid-transport`, `20250829-drop-openssl-redux`. None is PQC work. (`219-add-hybrid-transport` is caBLE/hybrid *transport*, unrelated to post-quantum "hybrid" signatures — an easy false lead.)

**Conclusion: no roadmap, no branch, no issue, no discussion. Upstream is not working on this and nobody has asked them to.**

### 1.3 The algorithm enum and the verification path

`webauthn-rs-proto/src/cose.rs` — verified against the vendored **0.5.5** source this workspace actually compiles, and against `master`:

```rust
#[repr(i32)]
pub enum COSEAlgorithm {
    ES256 = -7,  ES384 = -35, ES512 = -36,
    RS256 = -257, RS384 = -258, RS512 = -259,
    PS256 = -37,  PS384 = -38,  PS512 = -39,
    EDDSA = -8,
    INSECURE_RS1 = -65535,
    PinUvProtocol,
}
```

Properties that matter here:

- **Not `#[non_exhaustive]`, no `Other(i32)` catch-all, no trait.** A downstream crate cannot add a variant.
- `impl TryFrom<i128> for COSEAlgorithm` returns `Err(())` for any unlisted value, including `-48/-49/-50`.
- `COSEAlgorithm::secure_algs()` — the default for `WebauthnBuilder` — is `[ES256, RS256]` only. `EDDSA` is present but commented out with `-- Testing required`. Upstream is conservative even about EdDSA; ML-DSA is far outside its current risk appetite.

`webauthn-rs-core/src/interface.rs`:

```rust
pub enum COSEKeyTypeId { EC_Reserved = 0, EC_OKP = 1, EC_EC2 = 2, EC_RSA = 3, EC_Symmetric = 4 }
```

RFC 9964 puts ML-DSA keys under a **new** COSE key type, `AKP` (Algorithm Key Pair) = **7**. That value is not in this enum, so ML-DSA fails the key-type gate as well as the algorithm gate.

`webauthn-rs-core/src/crypto.rs` (0.5.5): `COSEKey::try_from` reads the CBOR map, does
`COSEAlgorithm::try_from(content_type).map_err(|_| WebauthnError::COSEKeyInvalidAlgorithm)?`, then matches on `(key_type, type_)` pairs. Verification is `pkey_verify_signature`, a private free function with a hard-coded `match` over `ES256 / RS256 / EDDSA / INSECURE_RS1` dispatching to `openssl::sign::Verifier`, with a catch-all arm returning `WebauthnError::COSEKeyInvalidType`.

**The decisive consequence:** an ML-DSA credential is rejected inside `finish_passkey_registration`, at CBOR key parsing. It can never become a stored `Passkey`, so no assertion-time hook would ever be reached for one. This does not make independent verification *impossible* — it makes it expensive: because the rejection happens at registration rather than at verification, there is no seam to hook, and covering ML-DSA outside `webauthn-rs` means **duplicating most of its registration pipeline** rather than substituting a single verification step. That cost, not impossibility, is what rules the option out; see [§5](#5-recommendation).

### 1.4 Extension points that do and do not exist

| Candidate | Verdict |
| --- | --- |
| Trait for signature verification | **Does not exist.** `pkey_verify_signature` is private with a hard-coded match. |
| Feature flag for extra algorithms | **Does not exist.** `webauthn-rs-core` 0.5.5 has `[features] default = []` and no algorithm features. |
| Adding a `COSEAlgorithm` variant downstream | **Impossible** — closed enum in another crate. |
| Configuring the algorithm list | **Partially.** `WebauthnCoreBuilder::credential_algorithms(Vec<COSEAlgorithm>)` is public in `webauthn-rs-core`, but the high-level `WebauthnBuilder` that Authkestra uses exposes no setter for it. Either way you can only pass *existing* variants — this lets you widen to `ES384`/`EdDSA`, never to ML-DSA. Reaching it also means dropping to `WebauthnCore::new_unsafe_experts_only`. |
| A future abstraction | **Emerging.** The `6.0-dev-drop-openssl` branch rewrites `crypto.rs` onto [`crypto-glue`](https://github.com/kanidm/crypto-glue), kanidm's own RustCrypto facade — the module doc comment changes from "currently uses OpenSSL" to "currently uses RustCrypto". `crypto-glue` 0.2.0's `Cargo.toml` has **no** `ml-dsa`/`ml-kem` dependency today, but this is the layer where PQC would land, and the natural place to contribute. |

One knock-on: the OpenSSL migration removes the cheapest theoretical shortcut. OpenSSL 3.5+ has ML-DSA; post-migration, RustCrypto's `ml-dsa` would have to be wired into `crypto-glue` instead. Anything built today against `webauthn-rs-core` 0.5.x's OpenSSL internals sits on a path upstream is actively abandoning.

---

## 2. The standards side

### 2.1 COSE code points — settled

From the [IANA COSE Algorithms registry](https://www.iana.org/assignments/cose/cose.xhtml) and [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html):

| Name | COSE value | Recommended | Reference |
| --- | --- | --- | --- |
| ML-DSA-44 | **-48** | Yes | RFC 9964 |
| ML-DSA-65 | **-49** | Yes | RFC 9964 |
| ML-DSA-87 | **-50** | Yes | RFC 9964 |

RFC 9964 also defines COSE key type **`AKP` (Algorithm Key Pair) = 7** for these keys, and requires the ML-DSA `ctx` parameter to be the empty string for all three parameter sets.

Sizes (RFC 9964; the private seed is always 32 bytes):

| | Public key | Signature |
| --- | --- | --- |
| ML-DSA-44 | 1312 B | 2420 B |
| ML-DSA-65 | 1952 B | 3309 B |
| ML-DSA-87 | 2592 B | 4627 B |

This is the only part of the stack that is genuinely ready.

> Side observation, **since confirmed against RFC 9864 by an independent review of this document**: the IANA registry shows `ES256` and `EdDSA` with Recommended = **Deprecated**, because RFC 9864 (fully-specified algorithms) defines fully-specified replacements and marks the polymorphic originals Deprecated. This matters because `webauthn-rs`'s default `secure_algs()` is exactly `[ES256, RS256]`. It is a separate, larger and considerably more actionable piece of crypto-agility work than ML-DSA — but it is **out of scope for #275**, and whether to open an issue for it is a maintainer decision (§6.8), not an action this spike takes.

### 2.2 WebAuthn / CTAP / FIDO — not ready

- **WebAuthn Level 3** is a **W3C Recommendation dated 2026-08-25** ([w3.org/TR/webauthn-3](https://www.w3.org/TR/webauthn-3/)). A full-text fetch found no occurrence of post-quantum, ML-DSA, Dilithium or PQC. It mandates no algorithm set; its own example RP accepts EdDSA/ES256/RS256. The current, final WebAuthn spec has nothing here to implement.
- The only WebAuthn↔ML-DSA binding is [`draft-vitap-ml-dsa-webauthn`](https://datatracker.ietf.org/doc/draft-vitap-ml-dsa-webauthn/), revision **-04, 2026-03-23**. It is an **individual submission from four authors at VIT-AP University with no IETF working group**, and it requests the same `-48/-49/-50` code points RFC 9964 already assigned. Individual drafts are not a standards commitment; this one is not adopted anywhere.
- **FIDO Alliance:** there is a **PQC Study Group** (per FIDO's own event/speaker pages) and a 2024 white paper, [*Addressing FIDO Alliance's Technologies in Post Quantum World*](https://fidoalliance.org/white-paper-addressing-fido-alliances-technologies-in-post-quantum-world/), framing a crypto-agile transition. There is **no published CTAP PQC profile**. CTAP 2.3 has shipped and defines no PQC algorithms.

**No authenticator in existence produces an ML-DSA WebAuthn credential, and no browser will send one.** An "integration test against a mock PQC authenticator" would therefore test a wire format we invented, against ourselves — precisely the false-confidence failure mode a spike exists to catch.

### 2.3 The CTAP-HID item is out of scope

#275 lists "Handling of fragmented CTAP-HID payloads for large PQC signatures (>8KB)".

The number is roughly right and the layer is wrong. CTAP-HID uses 64-byte reports: one INIT packet (7 bytes overhead) plus up to 128 CONT packets (5 bytes overhead each, sequence `0x00..=0x7f`), giving a maximum message payload of `64 - 7 + 128 * (64 - 5)` = **7609 bytes** — see the [FIDO CTAP](https://fidoalliance.org/specs/fido-v2.0-rd-20161004/fido-client-to-authenticator-protocol-v2.0-rd-20161004.html) and [U2F HID](https://fidoalliance.org/specs/u2f-specs-master/fido-u2f-hid-protocol.html) transport specs. So yes, an ML-DSA-87 ceremony (4627 B signature, plus a 2592 B key at registration, plus authenticator data) crowds that ceiling.

But fragmentation and reassembly happen entirely between the **authenticator and the client platform** (browser/OS). By the time a credential reaches Authkestra it is base64url JSON over HTTPS from the browser's WebAuthn API. `authkestra-engine` has no HID and no CTAP transport code — `crates/authkestra-engine/src/auth/webauthn.rs` receives `clientDataJSON` / `authenticatorData` / `signature` strings and hands them to `webauthn-rs`. Solving CTAP-HID fragmentation is work for `webauthn-authenticator-rs`, `fido-hid-rs`, browsers and the FIDO Alliance — never for this crate.

Suggested maintainer action: strike this checkbox from #275 rather than leave a permanently unachievable acceptance criterion on the issue.

---

## 3. Rust ML-DSA implementations

All candidates are license-compatible with `deny.toml`'s allow-list (which includes `MIT`, `Apache-2.0`, `BSD-3-Clause`, `BSD-2-Clause`, `ISC`, `MPL-2.0`).

| Crate | Latest | License | Notes |
| --- | --- | --- | --- |
| [`ml-dsa`](https://crates.io/api/v1/crates/ml-dsa) (RustCrypto) | **0.1.1**, 2026-06-05 | `Apache-2.0 OR MIT` | Pure Rust, FIPS 204 (final). **Runs NIST ACVP vectors** — [the repo](https://github.com/RustCrypto/signatures/tree/master/ml-dsa) ships `tests/key-gen.rs`, `sig-gen.rs`, `sig-ver.rs` driving `key-gen.json`/`sig-gen.json`/`sig-ver.json` through an `acvp::TestVectorFile` parser, plus `wycheproof.rs` and proptests. ~1.46M downloads. README: *"The implementation contained in this crate has never been independently audited!"* / *"USE AT YOUR OWN RISK!"* |
| [`fips204`](https://crates.io/api/v1/crates/fips204) | 0.4.6, **2024-12-22** | `MIT OR Apache-2.0` | `no_std`, no heap. **~20 months since the last release** — effectively dormant. [README](https://github.com/integritychain/fips204): *"The FIPS 204 standard and this software should be considered experimental — USE AT YOUR OWN RISK!"* and, as of 2024-11-08, *"NIST has not released top-level/external/hash test vectors!"* Constant-time claims rest on manual review and `dudect`. |
| [`pqcrypto-mldsa`](https://crates.io/api/v1/crates/pqcrypto-mldsa) | 0.1.2, 2025-08-05 | `MIT OR Apache-2.0` (crate metadata) | Bindings over vendored PQClean C. **Not verified in this spike:** the licensing of the bundled C sources and whether `cargo deny` classifies them cleanly. Pulls a C toolchain into the build — a real cost for a library consumed by others. |
| `aws-lc-rs` | **1.17.3, already present in this `Cargo.lock`** (transitively) | ISC / Apache-2.0 / OpenSSL | Reported to expose ML-DSA behind an *unstable* build flag, backed by AWS-LC — the only realistic path to a FIPS-validated ML-DSA in Rust. **Not verified in this spike**; worth a look if PQC becomes real, precisely because the dependency is already there. |

If a choice ever has to be made, **`ml-dsa` (RustCrypto) is the one to pick**: permissive dual license, actively released, real ACVP conformance vectors in-tree, no C toolchain, and — decisively — it is the ecosystem `webauthn-rs` is itself migrating toward via `crypto-glue`. None of the three is audited; "unaudited but ACVP-conformant" is the best available state of the art in pure Rust today.

---

## 4. What the engine actually does today

`crates/authkestra-engine/src/auth/webauthn.rs` (263 lines total — 197 lines of implementation plus tests, which start at the `#[cfg(test)]` on line 199; feature `webauthn`, `webauthn-rs = { version = "0.5.0", features = ["danger-allow-state-serialisation"] }`):

- Uses only the **high-level** `webauthn_rs::prelude` API: `WebauthnBuilder`, `start_passkey_registration`, `finish_passkey_registration`, `start_passkey_authentication`, `finish_passkey_authentication`, plus the `Passkey` / `AuthenticationResult` / `PasskeyRegistration` / `PasskeyAuthentication` types.
- Never touches `webauthn-rs-core`, `COSEAlgorithm`, `COSEKey`, or any crypto primitive. `Passkey` is opaque: stored as `serde_json::Value` through `CredentialStore` (`crates/authkestra-engine/src/store/sql/credential.rs`), matched by `passkey.cred_id()`, counter-updated via `update_credential(&auth_result)`.
- Wired at `crates/authkestra-engine/src/engine.rs` (`with_webauthn`, `start_webauthn`, `AuthInput::WebAuthnAuthentication`) and exercised by `crates/authkestra/examples/axum_mfa_server.rs`.
- Test coverage is the in-file `mod tests` plus `crates/authkestra-engine/src/tests.rs:188`: builder / `name` / `is_mfa_equivalent` / `has_enrolled` / challenge-shape assertions and an `InvalidInput` negative case. **No existing test verifies a real signature** — all of them stop before crypto.

Two grounded implications:

1. Authkestra's coupling to `webauthn-rs` is *thin but total*. Thin, because only about eight high-level functions are used — a facade would be small. Total, because everything cryptographic, including the algorithm allow-list, lives behind that facade with no seam. Authkestra cannot widen the algorithm list even to `ES384` today without dropping to `webauthn-rs-core`.
2. Because the engine stores `Passkey` as opaque JSON, any future ML-DSA credential type would need a storage discriminator. Cheap to add later; not worth pre-building now.

---

## 5. Recommendation

### Wait for upstream. Track, do not build.

Concretely, the technical conclusion is: build nothing now, and re-evaluate on a defined trigger rather than on a schedule. What to do with the *issue* — keep #275 open as a tracker versus close it, and whether to strike the CTAP-HID item — is proposed but not decided here; those are §6.2 and §6.3.

### Why not the other three options

**Verify ML-DSA independently of `webauthn-rs`** — rejected, and it is worth being precise about why, because it sounds like the pragmatic middle path. It is not. Because `COSEKey::try_from` rejects `kty=7` and `alg=-48` at *registration*, there is no `Passkey` to intercept. Doing this means reimplementing attested-credential-data parsing, `clientDataJSON` / origin / challenge validation, RP ID hashing, flag and counter handling, and attestation-statement verification — rebuilding the security-critical half of `webauthn-rs` inside Authkestra, in parallel with the maintained one, for a credential type no authenticator emits. That is the highest-risk option on the table, not the safe one.

**Fork and patch** — rejected. MPL-2.0 permits it and `deny.toml` would accept it. But it means owning a public fork of a security library, tracking a `master` that is mid-rewrite from OpenSSL to `crypto-glue` (so the patches would need redoing wholesale at 0.6), and shipping that fork to Authkestra's downstream users. Unacceptable maintenance burden and blast radius for zero user-visible capability.

**Contribute upstream** — right destination, wrong time. There is no spec to implement, so a PR today would be *proposing* a wire format rather than implementing one, and it would land on `crypto.rs` code that `6.0-dev-drop-openssl` deletes. This becomes the correct option once the triggers below fire; see stage 3.

### Trade-offs of waiting

- **Cost:** #275 stays open with nothing shipped, and Authkestra carries no "PQC-ready" claim. Given WebAuthn L3 is a Recommendation with no PQC content, no competing server library can honestly claim it either.
- **Risk accepted:** if FIDO/W3C move faster than expected, Authkestra starts from zero. Mitigated by stage 1's cheap monitoring, and by the fact that the *server-side* work — add a code point, dispatch a verifier — is genuinely small once the format is fixed. The expensive parts (authenticators, browsers, CTAP) are not ours.
- **Risk avoided:** shipping unaudited PQC crypto against a speculative format, and permanently owning either a fork or a parallel WebAuthn verifier.
- **Honest counterweight:** "wait" only stays correct if someone actually watches. An unwatched wait decays into a surprise. Hence stage 1.

### Staged plan

**Stage 0 — bookkeeping (this PR plus a maintainer pass, ~1 h).** Land this document. The rest of this stage is **conditional on the maintainer's answers to §6.2 and §6.3 and is not assumed here** — if they decide to keep #275 as a tracker and to drop the out-of-scope item, the mechanical follow-through is: relabel #275 `blocked: upstream`, remove the CTAP-HID checkbox with a link to §2.3, and correct the issue's "pinned at 0.5.0" note to "resolves to 0.5.5; still no ML-DSA". Only the last of those three is a plain factual fix and safe to make either way. If instead the maintainer closes #275, stages 1–4 fall away with it.

**Stage 1 — monitoring (~1 h to set up, ~15 min/quarter).** Record four trip-wires on #275 and check them quarterly:

1. W3C publishes a WebAuthn draft (L4 or an L3 amendment) containing ML-DSA;
2. FIDO publishes a CTAP PQC profile, or the PQC Study Group produces a spec;
3. `kanidm/webauthn-rs` opens a PQC issue/PR/branch, or `crypto-glue` gains an `ml-dsa` dependency;
4. any shipping authenticator or browser announces ML-DSA credential support.

Trigger to act: **(1 or 2) AND 4** — a spec *and* something real to test against. Trigger 3 alone means *offer help upstream*, not build here.

**Stage 2 — crypto-agility prep, optional and independent of PQC (~1–2 days).** If the maintainer wants motion, the useful work is not ML-DSA: it is removing Authkestra's current inability to influence the algorithm list at all. A thin internal facade over the ~8 `webauthn-rs` calls in `auth/webauthn.rs`, plus a stored-credential type discriminator in `store/sql/credential.rs`, would (a) let a future algorithm be added in one place, (b) turn the eventual 0.5→0.6 `webauthn-rs` upgrade into a one-file change, and (c) pay for itself on that upgrade regardless of whether PQC ever happens. **Explicitly do not add an ML-DSA crate dependency in this stage** — an unused, unaudited crypto dependency is a liability, not preparation.

**Stage 3 — contribute upstream, only once the triggers fire (est. 2–4 weeks, upstream-paced).** Open an issue on `kanidm/webauthn-rs` citing the spec, then propose in order: `ml-dsa` support in `crypto-glue`; `AKP = 7` in `COSEKeyTypeId` and `-48/-49/-50` in `COSEAlgorithm`; verification dispatch in the post-OpenSSL `crypto.rs`; deliberately *not* adding it to `secure_algs()`. Authkestra then consumes the released version. This must target the 0.6/`crypto-glue` line, not 0.5.x.

**Stage 4 — Authkestra integration (est. 2–3 days once stage 3 ships).** Bump `webauthn-rs`, expose the algorithm list through Authkestra's config (opt-in, default off), extend the credential-store discriminator, add integration tests against upstream's fixtures or a real authenticator. Only meaningful after stage 3.

---

## 6. Decisions that belong to the maintainer

This spike deliberately stops short of these; each is a judgement call, not a derivable answer.

1. **Accept "wait for upstream", or override it?** If Authkestra needs a PQC story for positioning or compliance reasons this spike cannot see, that is a product decision that changes the answer.
2. **Keep #275 open as a tracker, or close it as "blocked upstream, no action possible"?** An open issue with no achievable work is a cost; a closed one loses the tracking.
3. **Remove the CTAP-HID checkbox from #275?** §2.3 argues it is out of scope for a server-side library, but editing the issue author's acceptance criteria is their call.
4. **Fund stage 2 (the crypto-agility facade) now, later, or never?** It is justified by the `webauthn-rs` 0.6 migration on its own merits, but it is real work with no user-visible feature attached.
5. **Is upstream contribution (stage 3) something this project wants to spend weeks of maintainer-paced effort on**, versus simply waiting for kanidm?
6. **Risk appetite for unaudited PQC crypto**, whenever it becomes relevant. `ml-dsa` (RustCrypto) is the recommended crate, but "no independent audit" is a standing acceptance no spike can make on the maintainer's behalf.
7. **Should the `webauthn-rs` requirement be written as `"0.5.5"` instead of `"0.5.0"`** to match what `Cargo.lock` resolves? Cosmetic and unrelated to PQC — flagged only because the audit surfaced it.
8. **Follow up on the IANA `ES256`/`EdDSA` "Deprecated" finding (§2.1)?** Now confirmed against RFC 9864, so the question is no longer whether it is real but whether to act: it is a bigger and more immediate crypto-agility question than ML-DSA, it touches `webauthn-rs`'s default `secure_algs()`, and it arguably deserves its own issue. Opening one is the maintainer's call, not this spike's.

---

## 7. Draft comment for #275

> Not posted by this spike — the maintainer posts it if they agree.
>
> **Keep this section in sync with the document.** It is a summary of §§1–6, and a reviewer should treat any divergence between the two as a defect in this section. It is deliberately short: the doc is the artifact, this is the pointer to it.

---

Research spike done — recommendation: **wait for upstream, track rather than build**. Full findings with citations: `docs/research/webauthn-pqc-spike.md`.

The decisive fact is that the blocker sits *below* `webauthn-rs`, not inside it. `COSEAlgorithm` is a closed `#[repr(i32)]` enum, `COSEKeyTypeId` has no `AKP = 7`, and `COSEKey::try_from` rejects an unknown `alg` **during CBOR parsing at registration** — so an ML-DSA credential never becomes a stored `Passkey`. Verifying ML-DSA outside `webauthn-rs` is still possible, but only by duplicating most of its registration pipeline (attested credential data parsing, clientData/origin/challenge checks, RP ID hash, flags, counters, attestation). That makes it the highest-risk option, not the pragmatic middle one. Fork-and-patch fares no better: `master` is mid-rewrite from OpenSSL onto `crypto-glue`, so the patches would need redoing wholesale at 0.6.

And there is nothing to implement against anyway. RFC 9964 settles the COSE code points (`-48/-49/-50`, new key type `AKP = 7`), but WebAuthn L3 reached W3C Recommendation on 2026-08-25 (date independently confirmed) and — on a full-document search, so read this as "none found" rather than a proof of absence — contains no post-quantum content. The only WebAuthn/ML-DSA binding is an individual IETF draft with no working group; FIDO has a PQC study group but no CTAP profile. No authenticator emits an ML-DSA credential and no browser sends one.

Two corrections to the issue while I'm here:

- **`"0.5.0"` is a caret range and `Cargo.lock` already resolves to 0.5.5**, the current max stable. Not a staleness problem — 0.5.5 has no ML-DSA either.
- **The CTAP-HID item looks out of scope.** The ~7.6 KB message ceiling is real (`64 - 7 + 128*(64 - 5)` = 7609 bytes; arithmetic independently confirmed, though sourced from the CTAP 2.0 / U2F HID framing because the CTAP 2.2 spec fetch failed — the scope argument doesn't depend on the exact number). But fragmentation happens between authenticator and client platform; Authkestra receives base64url JSON over HTTPS and has no HID or CTAP code. That work belongs to `fido-hid-rs` / browsers / FIDO.

§5 of the doc has a staged plan (quarterly trip-wires; an optional crypto-agility facade that pays for itself on the 0.5→0.6 `webauthn-rs` migration regardless of PQC; upstream contribution only once a spec exists). §6 lists what I've deliberately left to you — including whether to keep this issue open as a tracker or close it, and whether to strike the CTAP-HID checkbox.

---

## 8. Sources

Fetched and verified on 2026-09-02:

- https://crates.io/api/v1/crates/webauthn-rs
- https://crates.io/api/v1/crates/webauthn-rs-core
- https://crates.io/api/v1/crates/ml-dsa
- https://crates.io/api/v1/crates/fips204
- https://crates.io/api/v1/crates/pqcrypto-mldsa
- https://github.com/kanidm/webauthn-rs — repo metadata, branch list, and issue/PR search via the GitHub API
- https://github.com/kanidm/webauthn-rs/pull/581
- `kanidm/webauthn-rs` sources on `master` and `6.0-dev-drop-openssl`: `webauthn-rs-proto/src/cose.rs`, `webauthn-rs-core/src/{crypto,proto,interface,core}.rs`, `webauthn-rs-core/Cargo.toml`
- https://github.com/kanidm/crypto-glue — `Cargo.toml`, v0.2.0
- https://github.com/RustCrypto/signatures/tree/master/ml-dsa — README, `Cargo.toml`, `tests/`
- https://github.com/integritychain/fips204
- https://www.iana.org/assignments/cose/cose.xhtml
- https://www.rfc-editor.org/rfc/rfc9964.html
- https://www.w3.org/TR/webauthn-3/
- https://datatracker.ietf.org/doc/draft-vitap-ml-dsa-webauthn/
- https://fidoalliance.org/white-paper-addressing-fido-alliances-technologies-in-post-quantum-world/
- https://fidoalliance.org/specs/fido-v2.0-rd-20161004/fido-client-to-authenticator-protocol-v2.0-rd-20161004.html
- https://fidoalliance.org/specs/u2f-specs-master/fido-u2f-hid-protocol.html
- Local: the vendored `webauthn-rs-proto-0.5.5` and `webauthn-rs-core-0.5.5` sources, this repo's `Cargo.lock`, `deny.toml`, and `crates/authkestra-engine/`

### Not verified in this spike

- The **CTAP 2.2 Proposed Standard could not be fetched** (the request failed). The 7609-byte CTAP-HID ceiling and its formula come from the FIDO CTAP 2.0 and U2F HID transport specs, which define the same framing; the **arithmetic was independently confirmed** by a review of this document, but the *provenance* caveat stands — it is not sourced from CTAP 2.2 itself. The claim that CTAP 2.3 shipped without breaking changes versus 2.2 remains secondary-source only. The scope argument in §2.3 does not depend on the exact number.
- The **absence** of PQC terms in WebAuthn L3 rests on a single full-document fetch, not an exhaustive re-read. The L3 **Recommendation date (2026-08-25) was independently confirmed**; the absence claim was not, and should be read as "none found" rather than proof of absence.
- `pqcrypto-mldsa`'s **vendored C source licensing** and its `cargo deny` behaviour were not checked — the crate is not recommended, so this was not run down.
- `aws-lc-rs` ML-DSA availability and its unstable-flag status are **secondary-source only**; the API was not inspected.
- ~~The IANA `ES256`/`EdDSA` "Deprecated" / RFC 9864 observation in §2.1 was not confirmed against RFC 9864 itself.~~ **Resolved:** confirmed against RFC 9864 by an independent review of this document. It remains a maintainer decision (§6.8), not an action.
- FIDO PQC Study Group details come from FIDO event and speaker pages, not from a published charter.
- No claim here rests on running `cargo` — this spike changed no code and built nothing.
