# Chapter 1: Vision and Architecture

Welcome to the Authkestra internals guide! This book provides the definitive roadmap for Authkestra's transition into a next-generation identity ecosystem.

## The Vision: Beyond Traditional Auth

Authkestra is not just another authentication library. Our mission is to provide **composable, verifiable, and quantum-resistant primitives** for both human users and autonomous AI systems. 

We are architecting a platform that moves beyond the static perimeter-based security of the last decade towards a **Zero-Trust, continuous evaluation model**.

## The Architecture Map

The project is structured as a unified **Orchestration Engine** (`authkestra-engine`) that interacts with abstracted, future-proof traits.

### The Five Pillars of the New Architecture:

1.  **GNAP & OAuth 2.1**: A move towards intent-driven negotiation (RFC 9635) and secure-by-default delegation.
2.  **Decentralized Identity**: Native support for W3C Verifiable Credentials and OpenID Connect for Verifiable Presentations (OIDC4VP).
3.  **Privacy-Enhancing Cryptography**: Implementing SD-JWT and BBS+ signatures for selective disclosure and unlinkable proofs.
4.  **Continuous Access Evaluation**: Real-time trust evaluation using the Shared Signals Framework (SSF/CAEP).
5.  **Fine-Grained Policy-as-Code**: Decoupling authorization into Zanzibar-style relationship graphs (ReBAC) and declarative policies (ABAC/Cedar).

## Crate Layers

1.  **Engine Layer (`authkestra-engine`)**: The framework-agnostic runtime and core traits.
2.  **Extension Layer**: Pluggable modules for WebAuthn (PQC-ready), VCs, and specific Identity Providers.
3.  **Adapter Layer**: Native integrations for Axum and Actix Web.
4.  **Policy Layer**: High-performance authorization enforcement engines.
