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

- **Modular & Unified Core**: Following our RFC-001 architecture, core concerns are unified in `authkestra-engine` while adapters like `authkestra-axum` and `authkestra-actix` provide seamless framework integrations.
- **Stateless OAuth**: OAuth `state` and `nonce` are stored securely in encrypted cookies—never in your database—keeping your architecture clean and horizontally scalable.
- **Performant OIDC Discovery**: OIDC discovery documents are cached via background `tokio::spawn` tasks, completely eliminating per-request latency for fetching keys.
- **Database Agnostic**: Authkestra never enforces schemas. All data access is strictly defined via traits (e.g., `UserStore`, `SessionStore`), allowing you to use any database or ORM.
- **Flexible Chaining**: Chain multiple authentication strategies (Token, Session, Basic, Custom) seamlessly.
- **OpenID Connect Provider (OP)**: Build your own identity provider and authorization server using `authkestra-op`.
- **Session Management**: Built-in support for in-memory, Redis, and SQL via `sqlx`.

## 📦 Workspace Crates

| Crate                                                                    | Responsibility                                                            |
| :----------------------------------------------------------------------- | :------------------------------------------------------------------------ |
| [`authkestra`](crates/authkestra/README.md)                                     | **Primary Facade**: Re-exports all other crates behind features.          |
| [`authkestra-engine`](crates/authkestra-engine/README.md)                       | Foundational types, traits and the **Engine** orchestrator.           |
| [`authkestra-resource`](crates/authkestra-resource/README.md)                   | Resource server enforcement and validation (JWT, etc).                    |
| [`authkestra-session`](crates/authkestra-session/README.md)                     | Session persistence layer abstraction.                                    |
| [`authkestra-providers`](crates/authkestra-providers/README.md)                 | Concrete implementation for OAuth providers (GitHub, Google, Discord).    |
| [`authkestra-axum`](crates/authkestra-axum/README.md)                           | Axum-specific integration, including `AuthSession` extractors.            |
| [`authkestra-actix`](crates/authkestra-actix/README.md)                         | Actix-specific integration, including `State` macro support.    |
| [`authkestra-oidc`](crates/authkestra-oidc/README.md)                           | OpenID Connect discovery and provider support.                            |
| [`authkestra-op`](crates/authkestra-op/README.md)                               | OpenID Connect Provider (OP) implementation.                              |
| [`authkestra-macros`](crates/authkestra-macros/README.md)                       | Procedural macros for simplifying Authkestra integration.                 |

## 🛠️ Usage

Authkestra utilizes a powerful **Typestate Builder Pattern** (`Engine::builder()`). This enforces at compile-time that certain methods are only available if their prerequisites are met (e.g., you can only call session methods if a `SessionStore` was provided).

### Quick Start Example

```rust
use authkestra::flow::{Engine, OAuth2Flow};
use authkestra_providers::github::GithubProvider;

// The builder ensures compile-time safety for your authentication stack
let github_provider = GithubProvider::new(client_id, client_secret, redirect_uri);

let auth_engine = Engine::builder()
    .provider(OAuth2Flow::new(github_provider))
    .session_store(session_store)
    .build();
```

To see complete, runnable examples for various frameworks and flows, check out the [examples](crates/authkestra/examples/) directory:

- [Axum Basic Setup](crates/authkestra/examples/axum/basic_setup.rs): `cargo run --example axum_basic_setup`
- [Actix Basic Setup](crates/authkestra/examples/actix/basic_setup.rs): `cargo run --example actix_basic_setup`
- [Axum with GitHub OAuth](crates/authkestra/examples/axum/oauth2_github.rs): `cargo run --example axum_oauth2_github`
- [Axum with Google OIDC](crates/authkestra/examples/axum/oidc_google.rs): `cargo run --example axum_oidc_google`
- [Axum with Redis Session](crates/authkestra/examples/axum/session_redis.rs): `cargo run --example axum_session_redis`
- [Axum with SQL Store](crates/authkestra/examples/axum/sql_store.rs): `cargo run --example axum_sql_store`
- [Client Credentials Flow](crates/authkestra/examples/core/client_credentials.rs): `cargo run --example core_client_credentials`
- [Device Flow](crates/authkestra/examples/core/device_flow.rs): `cargo run --example core_device_flow`
- [Axum Resource Server](crates/authkestra/examples/axum/resource_server.rs): `cargo run --example axum_resource_server`
- [Axum OP Server](crates/authkestra/examples/axum/op_server.rs): `cargo run --example axum_op_server`

## 🏗️ Technical Design Principles

Our architecture enforces strict design principles to guarantee compile-time safety and optimal Developer Experience (DX):

- **Typestate Builder Pattern**: The `Engine::builder()` uses Rust's typestate pattern. This makes misconfigurations a compile-time error rather than a runtime surprise.
- **Trait Objects over Generics**: For I/O bound paths, we prefer `Box<dyn Trait>` (e.g., `Box<dyn AuthMethod>`) over heavy monomorphized generics. This drastically optimizes compilation times without sacrificing meaningful runtime performance.
- **Framework Agnostic Core**: The `authkestra-engine` is pure Rust logic. Axum and Actix integrations are entirely isolated in separate adapter crates, utilizing explicit Extractors like `AuthSession(session)`.
- **Plugin Interfaces**: We extend functionality via strict plugin interfaces (`AuthMethod`, `Flow`) rather than opaque, ordering-dependent middleware.
- **Production-Ready Tracing**: Every handler, endpoint, and logical branch is deeply instrumented with the `tracing` crate, ensuring request flows and errors are fully visible in production without code changes.

## 📜 License

This project is dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
