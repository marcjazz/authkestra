# Next-Generation Migration Plan (v2)

This plan integrates the core structural migration from RFC-001 with the advanced feature set required for the next-generation identity ecosystem outlined in `deep-search.md`.

## 1. Engine Consolidation & Future-Proofing (Phase 1)

- **Merge into `authkestra-engine`**: Consolidate `core`, `flow`, and `token`.
- **GNAP Preparation**: Expand the `Flow` trait to support intent-driven JSON requests and dynamic client instances (GNAP / RFC 9635) alongside legacy OAuth 2.1.
- **Identity Representation**: Redesign the `Identity` and `Claims` structs to support Decentralized Identifiers (DIDs) and W3C Verifiable Credentials inherently.

## 2. Advanced Cryptography & Tokenization (Phase 2)

- **PQC-Ready Traits**: Ensure `TokenService` and `AuthMethod` cryptographic abstractions support Post-Quantum algorithms (ML-DSA) and larger payload sizes.
- **Privacy-Preserving Tokens**: Implement Selectively Disclosable JWTs (SD-JWT) and integrate BBS+ signature validation logic to allow zero-knowledge proof presentations.
- **WebAuthn Evolution**: Upgrade the WebAuthn plugin to support Post-Quantum cryptographic handshakes, gracefully handling CTAP payload constraints.

## 3. Continuous Authentication (Phase 3)

- **Shared Signals Framework (SSF)**: Implement a streaming event receiver in `authkestra-engine` to digest SSF events.
- **CAEP Integration**: Add dynamic session attenuation logic allowing sessions to be revoked or challenged instantly based on external risk telemetry without waiting for token expiration.

## 4. Fine-Grained Authorization & Policy-as-Code (Phase 4)

- **Beyond ABAC-lite**: Rename `authkestra-guard` to `authkestra-policy` or `authkestra-resource`.
- **ReBAC Engine**: Introduce a Zanzibar-inspired relationship graph traversal engine for complex permissions (tuples of `user`, `relation`, `object`).
- **ABAC Integration**: Support declarative Policy-as-Code (like AWS Cedar or Rego) for context-heavy attribute decisions.

## Ticket Alignment & Mapping

Based on the current GitHub Project items, here is how the existing tickets align with the Next-Gen vision:

### 1. Engine Consolidation (Phase 1)
*   **Update Issue #11 (Define Core Traits)**: 
    *   Ensure `Identity` can store DIDs and handle W3C Verifiable Credentials.
    *   Ensure `Flow` trait is generic enough for GNAP negotiation (RFC 9635).
*   **Update Issue #13 (Refactor OAuth Flow)**: 
    *   Add "Prepare for GNAP" as a sub-task.
    *   Strictly enforce OAuth 2.1 defaults (PKCE mandatory).

### 2. Authentication Expansion (Phase 2)
*   **Update Issue #17 (WebAuthn)**:
    *   Requirement: Support Post-Quantum Cryptography (ML-DSA-44).
    *   Task: Handle fragmented CTAP-HID payloads for larger PQC signatures.
*   **NEW TICKET: Privacy-Preserving Credentials**:
    *   Implement SD-JWT (Selectively Disclosable JWT).
    *   Integrate BBS+ signature validation for zero-knowledge proofs.

### 3. Continuous Authentication (Phase 3)
*   **NEW TICKET: Continuous Access Evaluation (CAEP/SSF)**:
    *   Implement Shared Signals Framework (RFC 9493).
    *   Enable real-time session revocation/step-up via CAEP events.

### 4. Authorization Foundation (Phase 4)
*   **Update Issue #20 (RBAC) -> ReBAC**:
    *   Transition from simple RBAC to a Zanzibar-inspired Relationship-Based Access Control model.
*   **Update Issue #21 (ABAC-lite) -> Policy-as-Code**:
    *   Incorporate AWS Cedar or OPA for declarative, mathematically provable authorization.

### 5. AI-Native DX (Phase 6)
*   **Update Issue #24 (Roadmap)**:
    *   Inject AI-driven risk scoring and anomaly detection using behavioral biometrics telemetry.
