# Chapter 4: Flows and Protocols

Authentication and delegation in the 2020s require more than just simple redirects. Authkestra
implements protocols that are secure-by-default and optimized for the autonomous machine economy.

Sections 1 and 5 describe code that ships today. Sections 2, 3 and 4 are RFC-002 roadmap items and
are marked as such — nothing in the workspace implements them yet.

## 1. OAuth 2.1: The Modern Baseline *(shipped)*
Authkestra strictly adheres to the **OAuth 2.1** consolidation.
- **PKCE by default**: `OAuth2Flow` enables PKCE unless you explicitly turn it off.
- **No Implicit Grant**: `authkestra-op` starts from `response_types_supported: ["code"]`; there is no implicit or hybrid flow.
- **Sender-Constraint**: **DPoP** (RFC 9449) is implemented on both sides — `authkestra-op` binds refresh tokens to a `jkt` and tracks proof `jti`s, and `authkestra-resource`'s `JwtStrategy` enforces `cnf.jkt` when `require_dpop` is on. Both replay guards fail closed: without a store wired, DPoP-bound requests are refused rather than waved through. RFC 8705 mutual-TLS binding (`cnf.x5t#S256`) is available the same way via `require_cert_binding`.

## 2. GNAP (Grant Negotiation and Authorization Protocol) *(planned — not implemented)*
> **Nothing in `authkestra-engine` implements GNAP (RFC 9635) today.** The roadmap's Phase 1 item
> "Update the `Flow` trait for GNAP compatibility" is still open; `Flow` is currently
> `id()` + `execute(FlowContext) -> FlowResult`, shaped around redirect and polling flows.

The intended direction:
- **Intent-Driven**: Clients negotiate specific access rights in a single JSON request.
- **Dynamic Client Instances**: No more static `client_id` bottlenecks. Software instances negotiate keys on-the-fly.
- **Decoupled Interaction**: Multiple interaction modes, including QR codes, device codes, and app-to-app redirects.

## 3. Verifiable Presentations (OIDC4VP) *(planned — not implemented)*
> **There is no OIDC4VP verifier, no W3C Verifiable Credential type, and no BBS+ support in the
> workspace.** The planned `authkestra-vc` crate does not exist. What *is* shipped for selective
> disclosure is plain SD-JWT — section 5 below, with its limits stated there.

The intended direction, as users transition to digital wallets (e.g., the EUDI Wallet), is for
Authkestra to act as a **Verifier**: requesting verifiable credentials inside an OIDC flow, and
validating BBS+ proofs for unlinkable selective disclosure.

## 4. WebAuthn & PQC *(WebAuthn shipped; PQC planned — not implemented)*
WebAuthn ships today inside `authkestra-engine` behind the `webauthn` feature, built on
`webauthn-rs`: registration and authentication ceremonies, signature-counter tracking to detect
cloned authenticators, and use as either a primary or a step-up method. See the Passkeys page on the documentation site, and
`crates/authkestra/examples/axum_mfa_server.rs` for a runnable TOTP + WebAuthn server.

> **Post-quantum support is not implemented.** No ML-DSA, no SLH-DSA, and no fragmented-payload
> CTAP-HID transport handling. The algorithm set is whatever `webauthn-rs` and `jsonwebtoken`
> support classically.

## 5. SD-JWT: Selective Disclosure Today *(shipped)*
Separate from the wallet-facing OIDC4VP verifier support in section 3 above, `authkestra-engine` ships a concrete, usable-today primitive for issuing and verifying **SD-JWTs** (`draft-ietf-oauth-selective-disclosure-jwt`) directly — no wallet or VP exchange required.
- **One Token, Many Presentations**: `TokenManager::issue_sd_jwt` mints a single JWT carrying some claims in the clear and others only as `_sd[]` digests, plus a matching list of Disclosures. The holder reconstructs a different SD-JWT compact form (`<jwt>~<disclosure>~...~`) per verifier, forwarding only the Disclosures that verifier needs — the issuer never mints a second token.
- **`TokenManager::validate_sd_jwt`**: validates the underlying JWT exactly like `validate_token` (signature, issuer, audience, expiry), then checks every presented Disclosure against `_sd[]`, returning only the claims that were both presented and proved out.
- **What this covers today**: flat, top-level, object-property Disclosures only.
- **What this does NOT cover** (see the module docs on `token/sd_jwt.rs` for the full rationale): no **Key Binding JWT (KB-JWT)** / holder proof-of-possession, no **array-element or recursive/nested Disclosures**, and no **SD-JWT VC** (`vc+sd-jwt`) type metadata. A caller needing any of those has to build it on top — there is no code path for them yet.
- A full worked example (one issuer, two verifiers each seeing a different subset of claims, plus a rejected tampered Disclosure) lives at `crates/authkestra-engine/examples/sd_jwt.rs` — run it with `cargo run -p authkestra-engine --example sd_jwt`.
