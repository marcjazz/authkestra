# Chapter 9: Security & Threat Model

Authkestra is designed to resist the security challenges of the next decade, including the threat
of quantum computing and the limitations of point-in-time authentication.

Sections 4 and 5 describe properties of the code as it ships today. Sections 1, 2 and 3 are
RFC-002 roadmap targets and are marked as such — treat them as intent, never as guarantees you can
rely on in a deployment.

## 1. Quantum Resilience (PQC) *(planned — not implemented)*
> **No post-quantum algorithm is implemented anywhere in the workspace.** Tokens are signed with
> the classical `jsonwebtoken` algorithm set (RSA, ECDSA, EdDSA). A deployment today has no
> "harvest now, decrypt later" protection beyond what those give.

The intended direction: **ML-DSA (FIPS 204)** as the primary signature algorithm, with
**SLH-DSA (FIPS 205)** as a stateless hash-based backup for high-security environments.

## 2. Continuous Session Security (CAEP) *(planned — not implemented)*
> **There is no SSF/CAEP receiver or transmitter.** Session invalidation today is whatever your
> `SessionStore` supports: `delete_session` on a known session id, plus the store's own TTL. There
> is no global kill-switch and no risk-telemetry ingestion.

The intended direction: consume Shared Signals Framework events so that a compromised account or a
device posture change attenuates or revokes sessions in near real time.

## 3. Privacy-Preserving Identity *(partially shipped)*
- **SD-JWT selective disclosure** *(shipped)*: the holder chooses, per verifier, which claims to
  reveal — see section 5 for exactly what is and is not covered.
- **BBS+ signatures / unlinkability** *(planned — not implemented)*: there is no BBS+ code in the
  workspace. Two SD-JWT presentations of the same token carry the same issuer signature, so they
  **are** correlatable by a colluding verifier. Do not rely on unlinkability today.

## 4. Modern Hardened Defaults *(shipped)*
- **PKCE on by default**: `OAuth2Flow` enables PKCE unless explicitly disabled.
- **Exact Redirect Matching**: `authkestra-op` matches a client's registered `redirect_uris` exactly — no prefix or wildcard matching — and refuses to redirect at all when the check fails, preventing open redirectors. The only relaxation is the one RFC 8252 §7.3 requires: a registered loopback IP redirect URI (`http://127.0.0.1/...`, `http://[::1]/...`) matches on any port, since a native app is handed an ephemeral port by the OS at request time. Everything else about the URI still has to match exactly, `localhost` is not accepted as a substitute for the IP literal (§8.3), and the exemption cannot reach a non-loopback host — so it does not widen the open-redirect surface.
- **Sender-Constrained Tokens**: DPoP (RFC 9449) and mutual-TLS (RFC 8705) binding, both fail-closed
  when their replay/binding stores are not wired — see Chapter 4 §1.
- **Stateless OAuth state/nonce**: carried in encrypted cookies, never in the database.

## 5. SD-JWT: Fail-Closed Disclosure Verification *(shipped)*
`authkestra-engine`'s SD-JWT support (`token::sd_jwt`) is deliberately fail-closed rather than lenient, on four specific points:
- **`_sd_alg` is never silently defaulted.** An absent `_sd_alg` defaults to `sha-256` per spec, but a *present-and-different* value is rejected outright rather than coerced — an unrecognized digest algorithm being treated as "must mean sha-256" is exactly the kind of algorithm-confusion bug that lets an attacker steer a verifier onto a weaker hash while it still believes it's checking sha-256.
- **An unmatched Disclosure digest fails the whole verification**, not just that one claim. A Disclosure whose digest isn't in the signed `_sd[]` is a claim the issuer never vouched for; accepting it would let a holder (or a network attacker appending to the compact form) inject arbitrary claims.
- **Duplicate digests in `_sd[]` are rejected.** Legitimately-generated Disclosures are independently salted and never collide, so a duplicate digest is a cheap way to smuggle a second, attacker-chosen Disclosure past the digest-membership check once one legitimate digest becomes known.
- **A disclosed claim can never shadow a registered top-level claim** (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`) or an already-present `extra` claim. Selective disclosure is additive by design; letting a Disclosure silently overwrite `aud` or `exp` would let a holder forge the very claims the issuer's signature is supposed to pin down.

**This module does not provide holder proof-of-possession.** Unlike the unlinkability BBS+ signatures give under section 3 above, there is no Key Binding JWT (KB-JWT) support here: `validate_sd_jwt` verifies the issuer's signature and the Disclosure digests only, with no notion of a holder key. A verifier that needs to confirm the presenter is the token's legitimate holder — not just an eavesdropper replaying a captured presentation — has to build that binding itself; it is not implied by a successful `validate_sd_jwt` call. Array-element/nested Disclosures and SD-JWT VC (`vc+sd-jwt`) type metadata are likewise out of scope today.
