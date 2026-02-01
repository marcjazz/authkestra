# Authkestra: Explicit, Modular Authentication for Rust

`authkestra` is a modular, framework-agnostic authentication orchestration system designed to be idiomatic to Rust, emphasizing **explicit control flow, strong typing, and composability** over dynamic middleware strategies common in other ecosystems.

This repository provides a workspace for the core components, focusing initially on OAuth2/OIDC with Axum and Actix integration.

## 🚀 Features

- **Modular Design**: Concerns are strictly separated into crates: `authkestra-core`, `authkestra-flow`, `authkestra-session`, `authkestra-token`, and framework adapters like `authkestra-axum` and `authkestra-actix`.
- **Explicit Flow Control**: Dependencies and authentication context are injected explicitly via **Extractors** (Axum/Actix) or constructor arguments, eliminating "magic" middleware.
- **Provider Agnostic**: Easily integrate new OAuth providers by implementing the `OAuthProvider` trait.
- **Session Management**: Flexible session storage via the `SessionStore` trait, with built-in support for in-memory, Redis, and SQL via `sqlx`.
- **Stateless Tokens**: Comprehensive JWT support via `authkestra-token`.

## 📦 Workspace Crates

| Crate                                                                    | Responsibility                                                            |
| :----------------------------------------------------------------------- | :------------------------------------------------------------------------ |
| [`authkestra-core`](authkestra-core/README.md)                           | Foundational types, traits (`Identity`, `OAuthProvider`, `SessionStore`). |
| [`authkestra-flow`](authkestra-flow/README.md)                           | Orchestrates OAuth2/OIDC flows (Authorization Code, PKCE).                |
| [`authkestra-session`](authkestra-session/README.md)                     | Session persistence layer abstraction.                                    |
| [`authkestra-token`](authkestra-token/README.md)                         | JWT signing, verification, and token abstraction.                         |
| [`authkestra-providers-github`](authkestra-providers-github/README.md)   | Concrete implementation for GitHub OAuth.                                 |
| [`authkestra-providers-google`](authkestra-providers-google/README.md)   | Concrete implementation for Google OAuth.                                 |
| [`authkestra-providers-discord`](authkestra-providers-discord/README.md) | Concrete implementation for Discord OAuth.                                |
| [`authkestra-axum`](authkestra-axum/README.md)                           | Axum-specific integration, including `AuthSession` extractors.            |
| [`authkestra-actix`](authkestra-actix/README.md)                         | Actix-specific integration.                                               |
| [`authkestra-oidc`](authkestra-oidc/README.md)                           | OpenID Connect discovery and provider support.                            |

## 🛠️ Usage

To see Authkestra in action, check out the [examples](examples/) directory:

- [Axum with GitHub OAuth](examples/axum_oauth.rs)
- [Actix with GitHub OAuth](examples/actix_github.rs)
- [OIDC Generic Provider](examples/oidc_generic.rs)
- [Device Flow](examples/device_flow.rs)

## 🗺️ Technical Design Principles

The architecture favors compile-time guarantees over runtime flexibility:

- **Trait-Based Extension**: Customization is achieved by implementing traits, not by configuring dynamic strategies.
- **Explicit Injection**: Authentication context is never implicitly available; users must explicitly request it via extractors (e.g., `AuthSession(session): AuthSession`).
- **Framework Agnostic Core**: `authkestra-flow` is pure Rust logic, completely independent of any web framework.

## 📜 License

This project is dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
