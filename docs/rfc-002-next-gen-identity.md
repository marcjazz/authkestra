# RFC-002: Next-Generation Identity Architecture

## 1. Summary
This RFC builds upon **RFC-001** by defining the functional transition of Authkestra into a "Next-Gen" identity platform. It introduces support for **GNAP**, **Post-Quantum Cryptography (PQC)**, **Verifiable Credentials**, and **Continuous Access Evaluation (CAEP)**.

## 2. Motivation
The digital identity landscape is shifting towards:
- **Decentralization**: Users holding their own credentials (W3C VCs, eIDAS 2.0).
- **Quantum Threats**: Need for ML-DSA and SLH-DSA signatures.
- **Dynamic Access**: Moving away from static bearer tokens to continuous evaluation.
- **Modern Delegation**: OAuth 2.1 consolidation and GNAP negotiation.

## 3. Technical Specifications

### 3.1. GNAP & OAuth 2.1 Implementation
- **OAuth 2.1**: Mandate PKCE, deprecate Implicit/Password grants, enforce DPoP/MTLS for sender-constraint.
- **GNAP (RFC 9635)**: Implement the `Engine` to handle unified JSON requests for multiple tokens, bypassing the rigid "redirect-only" model. Support dynamic client instance keys.

### 3.2. Verifiable Credentials & Privacy
- **Data Model**: Adopt W3C Verifiable Credentials Data Model v2.0.
- **Selective Disclosure**: Implement **SD-JWT** to allow users to share subsets of claims.
- **Zero-Knowledge Proofs**: Integrate **BBS+** signatures (via `bls12_381` crate) for unlinkable proof presentations.

### 3.3. Post-Quantum Cryptography (PQC)
- **Algorithm Support**: Add `ML-DSA-44` and `ML-DSA-65` support to the `TokenService` trait.
- **WebAuthn Integration**: Handle CTAP fragmented packet exchanges (larger than 8KB) required for PQC signatures on hardware keys.

### 3.4. Continuous Authentication (SSF/CAEP)
- **Signal Receiver**: Implement an HTTP listener for Security Event Tokens (SETs, RFC 8417).
- **CAEP Profiles**: Support `Session Revoked`, `Credential Change`, and `Token Claims Change` events to trigger real-time session updates.

### 3.5. Fine-Grained Authorization (FGA)
- **ReBAC**: Implement a "Zanzibar" style relationship store (`user -> relation -> object`).
- **ABAC**: Integrate **AWS Cedar** for declarative, mathematically provable authorization policies.

## 4. Migration Impact
- **authkestra-engine**: Becomes the orchestrator for all new traits.
- **authkestra-vc**: New crate for OIDC4VP/VC logic.
- **authkestra-ssf**: New crate for Shared Signals Framework.

## 5. Timeline
- **Immediate**: Update `Engine` traits to be "Future-Proof" (RFC-001 completion).
- **Mid-Term**: Implement PQC WebAuthn and SD-JWT.
- **Long-Term**: Full GNAP and CAEP event bus integration.
