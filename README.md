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

- **Modular Design**: Concerns are strictly separated into crates: `authkestra-engine`, `authkestra-resource`, `authkestra-session`, and framework adapters like `authkestra-axum` and `authkestra-actix`.
- **Explicit Flow Control**: Dependencies and authentication context are injected explicitly via **Extractors** (Axum/Actix) or constructor arguments, eliminating "magic" middleware.
- **Flexible Chaining**: Use the `AuthEngineGuard` to chain multiple authentication strategies (Token, Session, Basic, Custom) in any order.
- **Provider Agnostic**: Easily integrate new OAuth providers by implementing the `OAuthProvider` trait.
- **Session Management**: Flexible session storage via the `SessionStore` trait, with built-in support for in-memory, Redis, and SQL via `sqlx`.
- **Stateless Tokens**: Comprehensive JWT support and offline validation.

## 📦 Workspace Crates

| Crate                                                                    | Responsibility                                                            |
| :----------------------------------------------------------------------- | :------------------------------------------------------------------------ |
| [`authkestra`](authkestra/README.md)                                     | **Primary Facade**: Re-exports all other crates behind features.          |
| [`authkestra-engine`](authkestra-engine/README.md)                       | Foundational types, traits and the **AuthEngine** orchestrator.           |
| [`authkestra-resource`](authkestra-resource/README.md)                   | Resource server enforcement and validation (JWT, etc).                    |
| [`authkestra-session`](authkestra-session/README.md)                     | Session persistence layer abstraction.                                    |
| [`authkestra-providers`](authkestra-providers/README.md)                 | Concrete implementation for OAuth providers (GitHub, Google, Discord).    |
| [`authkestra-axum`](authkestra-axum/README.md)                           | Axum-specific integration, including `AuthSession` extractors.            |
| [`authkestra-actix`](authkestra-actix/README.md)                         | Actix-specific integration (Second-tier adapter, no macro support yet).   |
| [`authkestra-oidc`](authkestra-oidc/README.md)                           | OpenID Connect discovery and provider support.                            |

## 🛠️ Usage

To see Authkestra in action, check out the [examples](authkestra-examples/examples/) directory:

- [Axum Basic Setup](authkestra-examples/examples/axum_basic_setup.rs): `cargo run --example axum_basic_setup`
- [Actix Basic Setup](authkestra-examples/examples/actix_basic_setup.rs): `cargo run --example actix_basic_setup`
- [Axum with GitHub OAuth](authkestra-examples/examples/axum_oauth2_github.rs): `cargo run --example axum_oauth2_github`
- [Axum with Google OIDC](authkestra-examples/examples/axum_oidc_google.rs): `cargo run --example axum_oidc_google`
- [Axum with Redis Session](authkestra-examples/examples/axum_session_redis.rs): `cargo run --example axum_session_redis`
- [Client Credentials Flow](authkestra-examples/examples/axum_client_credentials.rs): `cargo run --example axum_client_credentials`
- [Device Flow](authkestra-examples/examples/axum_device_flow.rs): `cargo run --example axum_device_flow`
- [Axum Resource Server](authkestra-examples/examples/axum_resource_server.rs): `cargo run --example axum_resource_server`

## �️ Technical Design Principles

The architecture favors compile-time guarantees over runtime flexibility:

- **Trait-Based Extension**: Customization is achieved by implementing traits, not by configuring dynamic strategies.
- **Explicit Injection**: Authentication context is never implicitly available; users must explicitly request it via extractors (e.g., `AuthSession(session): AuthSession`).
- **Framework Agnostic Core**: `authkestra-engine` is pure Rust logic, completely independent of any web framework.
- **Typestate Builder Pattern**: The `AuthEngine` is built using typestates to enforce compile-time safety (e.g., session methods are only available if a session store is configured).

## 📜 License

This project is dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
