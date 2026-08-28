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
- *(planned)* `authkestra-policy`: Fine-grained ReBAC/ABAC enforcement.
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
- ⬜ Update `Flow` trait for GNAP compatibility.

### Phase 2: Quantum-Safe & Privacy-Preserving Auth
- Support ML-DSA in WebAuthn.
- Implement SD-JWT and BBS+ proof validation.
- Standardize DID-based identity modeling.

### Phase 3: Continuous Trust & Policy-as-Code
- Implement SSF/CAEP for real-time revocation.
- Launch ReBAC (Zanzibar) and ABAC (Cedar) policy engines.
- Refocus `authkestra-resource` on dynamic policy enforcement.

### Phase 4: Platform & AI-Native DX
- CLI for rapid scaffolding.
- Admin API & Next.js Identity Dashboard.
- AI-driven risk scoring and anomaly detection.

---

## 4. Community & Contribution
We use RFCs for major architectural shifts. See [`docs/rfc-002-next-gen-identity.md`](./rfc-002-next-gen-identity.md) for technical deep dives.
