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

**The Unified Engine:**
- `authkestra-engine`: The central brain. Framework-agnostic. Implements the core orchestrator and traits.

**Extension Ecosystem:**
- `authkestra-webauthn`: PQC-ready hardware-backed authentication.
- `authkestra-vc`: Verifiable Credentials & OIDC4VP implementation.
- `authkestra-policy`: Fine-grained ReBAC/ABAC enforcement.
- `authkestra-ssf`: Shared Signals Framework receiver/transmitter.
- `authkestra-session-*`: Pluggable storage backends (Redis, SQL, Memory).

**Adapters:**
- `authkestra-axum` / `authkestra-actix`: Native web framework integrations.

---

## 3. Phased Roadmap

### Phase 1: Engine Consolidation & GNAP Prep
- Merge `core`, `flow`, `token` into `authkestra-engine`.
- Implement `AuthEngine` builder with Typestate pattern.
- Update `Flow` trait for GNAP compatibility.

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
We use RFCs for major architectural shifts. See `docs/rfc-002-next-gen-identity.md` (coming soon) for technical deep dives.
