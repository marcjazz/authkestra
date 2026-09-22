# Authkestra Roadmap (Next-Gen Identity Edition)

This roadmap outlines the evolution of Authkestra into a next-generation identity platform, focusing on verifiable primitives, quantum resilience, and continuous trust.

---

## 0. North Star

> **Authkestra = composable, verifiable, and quantum-resistant auth primitives for humans and AI systems.**

- **Verifiable by Design**: Built on W3C Verifiable Credentials and BBS+ Zero-Knowledge Proofs.
- **Quantum-Safe**: Native support for Post-Quantum Cryptography (ML-DSA).
- **Continuous Trust**: Real-time session attenuation via the Shared Signals Framework (SSF/CAEP).
- **Modern Delegation**: Transitioning from OAuth 2.1 baseline to GNAP (OAuth 3.0) intent-driven authorization.

---

## 1. Core Pillars (The "Next-Gen" Vision)

1.  **GNAP & OAuth 2.1**: Move beyond rigid redirects. Support dynamic client instances and intent-driven negotiation.
2.  **Decentralized Identity**: Native integration for European Digital Identity Wallets (eIDAS 2.0), DIDs, and OIDC4VP.
3.  **Privacy-Enhanced Crypto**: SD-JWT and BBS+ signatures for selective disclosure and unlinkable proofs.
4.  **Continuous Access Evaluation (CAEP)**: Shifting from point-in-time auth to dynamic risk-based session management.
5.  **Policy-as-Code (ReBAC/ABAC)**: Decoupling authorization logic into Zanzibar-style relationship graphs and declarative policy engines (AWS Cedar).

---

## 2. Architecture & Crate Structure

**The Unified Engine (shipped):**
- `authkestra-engine`: The central brain. Framework-agnostic. Implements the core orchestrator
  and traits, and carries session/token storage plus the pluggable backends (Redis, SQL, Memory)
  behind feature flags — there is no separate `authkestra-session` crate.

**Extension Ecosystem:**
- *(shipped)* `authkestra-op`, `authkestra-devsig`, `authkestra-oidc`, `authkestra-providers`,
  `authkestra-resource`, `authkestra-crypto-util`.
- *(planned)* `authkestra-vc`: Verifiable Credentials & OIDC4VP implementation.
- *(proof of concept)* `authkestra-policy`: fine-grained ReBAC/ABAC enforcement with AWS Cedar.
  The engine evaluates policies and reloads them at runtime, but nothing calls it yet — see
  [rfc-008-policy-engine.md](./rfc-008-policy-engine.md) and
  [authkestra#21](https://github.com/marcjazz/authkestra/issues/21).
- *(planned)* `authkestra-ssf`: Shared Signals Framework receiver/transmitter.
- *(planned)* PQC-ready hardware-backed authentication; WebAuthn ships today inside
  `authkestra-engine` behind the `webauthn` feature.

**Adapters (shipped):**
- `authkestra-axum` / `authkestra-actix`: Native web framework integrations.

---

## 3. Phased Roadmap

### Phase 1: Engine Consolidation & GNAP Prep
- ✅ Merge `core`, `flow`, `token` into `authkestra-engine`.
- ✅ Implement `Engine` builder with Typestate pattern.
- ✅ Update `Flow` trait for GNAP compatibility (trait shape only — see `docs/rfc-004-gnap-flow.md`; the GNAP grant endpoints themselves are tracked separately).

### Phase 2: Passwordless-Native Authentication

The strategic bet is advanced, correct primitives rather than parity on the
basics — so the authentication methods we add are the ones a passwordless
account actually uses, and they share one shape: the server mints a secret,
delivers it out of band, and accepts it back exactly once.

- ✅ Re-proof gating for security-posture changes (`docs/rfc-009-reproof-gate.md`). A prerequisite, not a sibling: all three items below add enrolment surfaces with identical exposure, so the gate had to exist first or be retrofitted three times.
- Magic link — in `authkestra-engine` behind a feature flag, per the convention `webauthn`/`totp` already follow (`docs/rfc-010-magic-link.md`).
- Email/SMS OTP — the same delivered-secret core, differing only in that the secret is short enough to type and therefore needs attempt-limiting.
- Recovery codes, as a **look-up secret authenticator** (NIST SP 800-63B §5.1.2). Deliberately not "TOTP recovery": a factor-agnostic fallback across whichever methods an account has registered, not one tied to a single factor.

> **Passwords and SAML are migration tooling here, not features.** Scope is
> one-way: verify-once against a legacy hash, read-once of a SAML assertion,
> so an integrator can move accounts onto Authkestra. Neither is planned as a
> first-class ongoing authentication method — that is the market we are
> deliberately not competing in.

### Phase 3: Quantum-Safe & Privacy-Preserving Auth
- Support ML-DSA in WebAuthn.
- Implement SD-JWT and BBS+ proof validation.
- Standardize DID-based identity modeling.

### Phase 4: Continuous Trust & Policy-as-Code
- Implement SSF/CAEP for real-time revocation.
- Launch ReBAC (Zanzibar) and ABAC (Cedar) policy engines.
- Refocus `authkestra-resource` on dynamic policy enforcement.

### Phase 5: Platform & AI-Native DX
- CLI for rapid scaffolding.
- Admin API & Next.js Identity Dashboard.
- AI-driven risk scoring and anomaly detection.

---

## 4. Community & Contribution
We use RFCs for major architectural shifts. See [`docs/rfc-002-next-gen-identity.md`](./rfc-002-next-gen-identity.md) for technical deep dives.
