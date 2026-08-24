# Chapter 9: Security & Threat Model

Authkestra is designed to resist the security challenges of the next decade, including the threat of quantum computing and the limitations of point-in-time authentication.

## 1. Quantum Resilience (PQC)
We are transitioning our cryptographic foundation to **Post-Quantum Cryptography** to mitigate "harvest now, decrypt later" attacks.
- **ML-DSA (FIPS 204)**: Our primary signature algorithm for tokens and internal credentials.
- **SLH-DSA (FIPS 205)**: Used as a stateless, hash-based backup for high-security environments.

## 2. Continuous Session Security (CAEP)
Legacy bearer tokens are a significant vulnerability. Authkestra mitigates this by shifting to **Continuous Access Evaluation**.
- **SSF Event Stream**: We integrate with the Shared Signals Framework to receive real-time risk telemetry.
- **Immediate Invalidation**: Sessions can be killed globally in milliseconds if an account compromise or device posture change is detected.

## 3. Privacy-Preserving Identity
To prevent user tracking and correlation between services:
- **BBS+ Signatures**: Allow for zero-knowledge proofs of identity attributes.
- **Unlinkability**: Every presentation of a credential is cryptographically unique, ensuring Identity Providers and Relying Parties cannot collude to track user behavior.

## 4. Modern Hardened Defaults
- **PKCE Mandatory**: No OAuth flows without Proof Key for Code Exchange.
- **Exact Redirect Matching**: Preventing open redirector vulnerabilities.
- **Sender-Constrained Tokens**: Using DPoP to bind tokens to the client's cryptographic key.

## 5. SD-JWT: Fail-Closed Disclosure Verification
`authkestra-engine`'s SD-JWT support (`token::sd_jwt`) is deliberately fail-closed rather than lenient, on four specific points:
- **`_sd_alg` is never silently defaulted.** An absent `_sd_alg` defaults to `sha-256` per spec, but a *present-and-different* value is rejected outright rather than coerced — an unrecognized digest algorithm being treated as "must mean sha-256" is exactly the kind of algorithm-confusion bug that lets an attacker steer a verifier onto a weaker hash while it still believes it's checking sha-256.
- **An unmatched Disclosure digest fails the whole verification**, not just that one claim. A Disclosure whose digest isn't in the signed `_sd[]` is a claim the issuer never vouched for; accepting it would let a holder (or a network attacker appending to the compact form) inject arbitrary claims.
- **Duplicate digests in `_sd[]` are rejected.** Legitimately-generated Disclosures are independently salted and never collide, so a duplicate digest is a cheap way to smuggle a second, attacker-chosen Disclosure past the digest-membership check once one legitimate digest becomes known.
- **A disclosed claim can never shadow a registered top-level claim** (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`) or an already-present `extra` claim. Selective disclosure is additive by design; letting a Disclosure silently overwrite `aud` or `exp` would let a holder forge the very claims the issuer's signature is supposed to pin down.

**This module does not provide holder proof-of-possession.** Unlike the unlinkability BBS+ signatures give under section 3 above, there is no Key Binding JWT (KB-JWT) support here: `validate_sd_jwt` verifies the issuer's signature and the Disclosure digests only, with no notion of a holder key. A verifier that needs to confirm the presenter is the token's legitimate holder — not just an eavesdropper replaying a captured presentation — has to build that binding itself; it is not implied by a successful `validate_sd_jwt` call. Array-element/nested Disclosures and SD-JWT VC (`vc+sd-jwt`) type metadata are likewise out of scope today.
