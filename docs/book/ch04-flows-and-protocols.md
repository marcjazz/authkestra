# Chapter 4: Flows and Protocols

Authentication and delegation in the 2020s require more than just simple redirects. Authkestra implements protocols that are secure-by-default and optimized for the autonomous machine economy.

## 1. OAuth 2.1: The Modern Baseline
Authkestra strictly adheres to the **OAuth 2.1** consolidation.
- **Mandatory PKCE**: Proof Key for Code Exchange is required for all flows.
- **No Implicit Grant**: Legacy insecure flows are deprecated.
- **Sender-Constraint**: Native support for **DPoP** (Demonstrating Proof-of-Possession) ensuring tokens cannot be replayed if stolen.

## 2. GNAP (Grant Negotiation and Authorization Protocol)
The **GNAP (RFC 9635)** implementation in `authkestra-engine` represents the future of delegation.
- **Intent-Driven**: Clients negotiate specific access rights in a single JSON request.
- **Dynamic Client Instances**: No more static `client_id` bottlenecks. Software instances negotiate keys on-the-fly.
- **Decoupled Interaction**: Support for multiple interaction modes, including QR codes, device codes, and app-to-app redirects.

## 3. Verifiable Presentations (OIDC4VP)
As users transition to digital wallets (e.g., the EUDI Wallet), Authkestra provides the infrastructure to act as a **Verifier**.
- **OIDC4VP Support**: Requesting verifiable credentials directly within an OpenID Connect flow.
- **Privacy-Preserving Proofs**: Support for validating **BBS+** signatures and **SD-JWTs**, allowing for selective disclosure without tracking.

## 4. WebAuthn & PQC
Our WebAuthn implementation is being upgraded to handle **Post-Quantum Cryptography**.
- **ML-DSA Support**: Preparing for the day when classical ECC and RSA are broken by quantum computers.
- **Fragmented Payloads**: Specialized transport handling to manage the multi-kilobyte PQC signatures that exceed standard CTAP-HID limits.

## 5. SD-JWT: Selective Disclosure Today
Separate from the wallet-facing OIDC4VP verifier support in section 3 above, `authkestra-engine` ships a concrete, usable-today primitive for issuing and verifying **SD-JWTs** (`draft-ietf-oauth-selective-disclosure-jwt`) directly — no wallet or VP exchange required.
- **One Token, Many Presentations**: `TokenManager::issue_sd_jwt` mints a single JWT carrying some claims in the clear and others only as `_sd[]` digests, plus a matching list of Disclosures. The holder reconstructs a different SD-JWT compact form (`<jwt>~<disclosure>~...~`) per verifier, forwarding only the Disclosures that verifier needs — the issuer never mints a second token.
- **`TokenManager::validate_sd_jwt`**: validates the underlying JWT exactly like `validate_token` (signature, issuer, audience, expiry), then checks every presented Disclosure against `_sd[]`, returning only the claims that were both presented and proved out.
- **What this covers today**: flat, top-level, object-property Disclosures only.
- **What this does NOT cover** (see the module docs on `token/sd_jwt.rs` for the full rationale): no **Key Binding JWT (KB-JWT)** / holder proof-of-possession, no **array-element or recursive/nested Disclosures**, and no **SD-JWT VC** (`vc+sd-jwt`) type metadata. A caller needing any of those has to build it on top — there is no code path for them yet.
- A full worked example (one issuer, two verifiers each seeing a different subset of claims, plus a rejected tampered Disclosure) lives at `crates/authkestra-engine/examples/sd_jwt.rs` — run it with `cargo run -p authkestra-engine --example sd_jwt`.
