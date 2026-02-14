# Authkestra

`authkestra` is a modular, framework-agnostic authentication orchestration system designed to be idiomatic to Rust, emphasizing **explicit control flow, strong typing, and composability** over dynamic middleware strategies common in other ecosystems.

## 📦 Getting Started

The easiest way to use Authkestra is via the `authkestra` facade crate. It re-exports all sub-crates behind feature flags, allowing you to manage your authentication stack from a single dependency.

Add this to your `Cargo.toml`:

```toml
[dependencies]
# Use the facade with the features you need
authkestra = { version = "0.1.1", features = ["axum", "github"] }
```

For advanced users, individual crates are still available and can be used independently if preferred.

## 🚀 Features

- **Modular Design**: Concerns are strictly separated into crates: `authkestra-core`, `authkestra-flow`, `authkestra-guard`, `authkestra-session`, `authkestra-token`, and framework adapters like `authkestra-axum` and `authkestra-actix`.
- **Explicit Flow Control**: Dependencies and authentication context are injected explicitly via **Extractors** (Axum/Actix) or constructor arguments, eliminating "magic" middleware.
- **Flexible Chaining**: Use the `AuthkestraGuard` to chain multiple authentication strategies (Token, Session, Basic, Custom) in any order.
- **Provider Agnostic**: Easily integrate new OAuth providers by implementing the `OAuthProvider` trait.
- **Session Management**: Flexible session storage via the `SessionStore` trait, with built-in support for in-memory, Redis, and SQL via `sqlx`.
- **Stateless Tokens**: Comprehensive JWT support and offline validation.

## 📦 Workspace Crates

| Crate                                                                    | Responsibility                                                            |
| :----------------------------------------------------------------------- | :------------------------------------------------------------------------ |
| [`authkestra`](authkestra/README.md)                                     | **Primary Facade**: Re-exports all other crates behind features.          |
| [`authkestra-core`](authkestra-core/README.md)                           | Foundational types, traits (`Identity`, `OAuthProvider`, `SessionStore`). |
| [`authkestra-flow`](authkestra-flow/README.md)                           | Orchestrates OAuth2/OIDC flows (Authorization Code, PKCE).                |
| [`authkestra-guard`](authkestra-guard/README.md)                         | Authentication guard and strategies (JWT offline validation, etc).        |
| [`authkestra-session`](authkestra-session/README.md)                     | Session persistence layer abstraction.                                    |
| [`authkestra-token`](authkestra-token/README.md)                         | JWT signing and token abstraction.                                        |
| [`authkestra-providers-github`](authkestra-providers-github/README.md)   | Concrete implementation for GitHub OAuth.                                 |
| [`authkestra-providers-google`](authkestra-providers-google/README.md)   | Concrete implementation for Google OAuth.                                 |
| [`authkestra-providers-discord`](authkestra-providers-discord/README.md) | Concrete implementation for Discord OAuth.                                |
| [`authkestra-axum`](authkestra-axum/README.md)                           | Axum-specific integration, including `AuthSession` extractors.            |
| [`authkestra-actix`](authkestra-actix/README.md)                         | Actix-specific integration.                                               |
| [`authkestra-oidc`](authkestra-oidc/README.md)                           | OpenID Connect discovery and provider support.                            |

## 🛠️ Usage

To see Authkestra in action, check out the [examples](examples/) directory:

- [Get Started](authkestra-examples/src/bin/client_credentials_flow.rs)
- [Axum Combined Flow (Authkestra + AuthkestraGuard)](authkestra-examples/src/bin/axum_combined_flow.rs)
- [Axum with GitHub OAuth](authkestra-examples/src/bin/axum_oauth.rs)
- [Actix with GitHub OAuth](authkestra-examples/src/bin/actix_github.rs)
- [OIDC Generic Provider](authkestra-examples/src/bin/oidc_generic.rs)
- [Device Flow](authkestra-examples/src/bin/device_flow.rs)

## �️ Technical Design Principles

The architecture favors compile-time guarantees over runtime flexibility:

- **Trait-Based Extension**: Customization is achieved by implementing traits, not by configuring dynamic strategies.
- **Explicit Injection**: Authentication context is never implicitly available; users must explicitly request it via extractors (e.g., `AuthSession(session): AuthSession`).
- **Framework Agnostic Core**: `authkestra-flow` is pure Rust logic, completely independent of any web framework.

## 📜 License

This project is dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
