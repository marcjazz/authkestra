# Authly README

# Authly: Explicit, Modular Authentication for Rust

`authly` is a modular, framework-agnostic authentication orchestration system designed to be idiomatic to Rust, emphasizing **explicit control flow, strong typing, and composability** over dynamic middleware strategies common in other ecosystems.

This repository provides a workspace for the core components, focusing initially on OAuth2/OIDC with Axum integration.

## 🚀 Features

- **Modular Design**: Concerns are strictly separated into crates: `authly-core`, `authly-flow`, `authly-session`, `authly-token`, and framework adapters like `authly-axum`.
- **Explicit Flow Control**: Dependencies and authentication context are injected explicitly via **Extractors** (Axum) or constructor arguments, eliminating "magic" middleware.
- **Provider Agnostic**: Easily integrate new OAuth providers by implementing the `OAuthProvider` trait.
- **Session Management**: Flexible session storage via the `SessionStore` trait, with built-in support for in-memory, Redis, and SQL via `sqlx`.
- **Stateless Tokens**: Comprehensive JWT support via `authly-token`.

## 📦 Workspace Crates

| Crate                                                            | Responsibility                                                            |
| :--------------------------------------------------------------- | :------------------------------------------------------------------------ |
| [`authly-core`](authly-core/README.md)                           | Foundational types, traits (`Identity`, `OAuthProvider`, `SessionStore`). |
| [`authly-flow`](authly-flow/README.md)                           | Orchestrates OAuth2/OIDC flows (Authorization Code, PKCE).                |
| [`authly-session`](authly-session/README.md)                     | Session persistence layer abstraction.                                    |
| [`authly-token`](authly-token/README.md)                         | JWT signing, verification, and token abstraction.                         |
| [`authly-providers-github`](authly-providers-github/README.md)   | Concrete implementation for GitHub OAuth.                                 |
| [`authly-providers-google`](authly-providers-google/README.md)   | Concrete implementation for Google OAuth.                                 |
| [`authly-providers-discord`](authly-providers-discord/README.md) | Concrete implementation for Discord OAuth.                                |
| [`authly-axum`](authly-axum/README.md)                           | Axum-specific integration, including `AuthSession` extractors.            |

## 🗺️ Technical Design Principles

The architecture favors compile-time guarantees over runtime flexibility:

- **Trait-Based Extension**: Customization is achieved by implementing traits, not by configuring dynamic strategies.
- **Explicit Injection**: Authentication context is never implicitly available; users must explicitly request it via extractors (e.g., `AuthSession(session): AuthSession`).
- **Framework Agnostic Core**: `authly-flow` is pure Rust logic, completely independent of any web framework.
