# Chapter 1: Vision and Architecture

Welcome to the Authkestra internals guide! This book aims to provide the community with a clear path forward for rewriting the project from its current architecture to the desired next-gen auth framework.

## The Vision

Authkestra aims to be the premier Rust authentication framework—highly modular, easily extensible, type-safe by design, and agnostic to the web framework you choose (Axum, Actix, etc.).

We are moving away from tight coupling and hardcoded implementations toward an orchestration engine.

## The Architecture Map

The project is structured around a central core (`AuthEngine`), which interacts with abstracted traits (`AuthMethod`, `SessionStore`, `Provider`).

The layers are defined as follows:

1. **Core Layer:** The pure Rust engine, managing state, executing flows, and handling the core domain entities (Identities, Claims).
2. **Protocol Layer:** Implementations of specific standards like OAuth2, OIDC, SAML, etc.
3. **Adapter Layer:** Bindings for different frameworks (Actix, Axum) and databases (SQLx, Redis).
4. **API Layer:** Management endpoints and admin panels.

### Open Challenges & Design Ambiguities

- **Crate Segmentation:** Should `authkestra-core` contain basic traits, or should they live in an `authkestra-traits` crate to avoid circular dependencies?
- **Feature Flags vs. Crates:** We currently heavily rely on separate crates. Could feature flags in a single monolithic crate provide a better developer experience?
