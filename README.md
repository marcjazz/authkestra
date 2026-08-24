# Authkestra

`authkestra` is a modular, framework-agnostic authentication orchestration system designed to be idiomatic to Rust, emphasizing **explicit control flow, strong typing, and composability** over dynamic middleware strategies common in other ecosystems.

## 📦 Getting Started

The easiest way to use Authkestra is via the `authkestra` facade crate. It re-exports all sub-crates behind feature flags, allowing you to manage your authentication stack from a single dependency.

Add this to your `Cargo.toml`:

```toml
[dependencies]
# Use the facade with the features you need
authkestra = { version = "0.3", features = ["axum", "github"] }
```

For advanced users, individual crates are still available and can be used independently if preferred.

### 🔐 TLS backend

Authkestra talks to identity providers over HTTPS, so it needs a TLS backend. It
is selected by a feature flag rather than by `reqwest`'s defaults, so you can
choose the crypto provider yourself:

| Feature | Backend | Notes |
| --- | --- | --- |
| `rustls-aws-lc-rs` | rustls + [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs) | **Default.** Compiles C and assembly, so it needs a C toolchain. |
| `rustls-no-provider` | rustls, provider chosen by you | Pure-Rust builds (`ring`), `*-unknown-linux-musl`, `cargo-deny` policies that ban `aws-lc-rs`. |

The default keeps the historical behaviour, so no change is needed unless you
want to get off `aws-lc-rs`. To do that, turn the default off and install a
provider yourself:

```toml
[dependencies]
authkestra = { version = "0.3", default-features = false, features = ["axum", "github", "rustls-no-provider"] }
rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12", "logging"] }
```

```rust,ignore
// Must run before any Authkestra call that builds an HTTP client,
// otherwise reqwest panics at client construction.
rustls::crypto::ring::default_provider()
    .install_default()
    .expect("failed to install rustls crypto provider");
```

Every Authkestra crate that speaks HTTPS exposes the same two features and
forwards them to `authkestra-engine`. Cargo features are additive, so if any
crate in your graph still enables `rustls-aws-lc-rs`, `aws-lc-rs` comes back —
check with `cargo tree -i aws-lc-rs -e features`.

## 🚀 Features

- **Modular & Unified Core**: Following our RFC-001 architecture, core concerns are unified in `authkestra-engine` while adapters like `authkestra-axum` and `authkestra-actix` provide seamless framework integrations.
- **Stateless OAuth**: OAuth `state` and `nonce` are stored securely in encrypted cookies—never in your database—keeping your architecture clean and horizontally scalable.
- **Performant OIDC Discovery**: OIDC discovery documents are cached via background `tokio::spawn` tasks, completely eliminating per-request latency for fetching keys.
- **Database Agnostic**: Authkestra never enforces schemas. All data access is strictly defined via traits (e.g., `UserStore`, `SessionStore`), allowing you to use any database or ORM.
- **Flexible Chaining**: Chain multiple authentication strategies (Token, Session, Basic, Custom) seamlessly.
- **OpenID Connect Provider (OP)**: Build your own identity provider and authorization server using `authkestra-op`.
- **Session Management**: Built-in support for in-memory, Redis, and SQL via `sqlx`.
- **SD-JWT (Selective Disclosure)**: Issue a single JWT carrying selectively disclosable claims (`draft-ietf-oauth-selective-disclosure-jwt`); the holder decides, per presentation, which claims to reveal to each verifier.

## 📦 Workspace Crates

| Crate | Description |
| --- | --- |
| [`authkestra`](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra/README.md)                                     | **Primary Facade**: Re-exports all other crates behind features.          |
| [`authkestra-engine`](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-engine/README.md)                       | Foundational types, traits and the **Engine** orchestrator.           |
| [`authkestra-resource`](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-resource/README.md)                   | Resource server enforcement and validation (JWT, etc).                    |
| [`authkestra-providers`](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-providers/README.md)                 | Concrete implementation for OAuth providers (GitHub, Google, Discord).    |
| [`authkestra-axum`](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-axum/README.md)                           | Axum-specific integration, including `AuthSession` extractors.            |
| [`authkestra-actix`](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-actix/README.md)                         | Actix-specific integration, including `State` macro support.    |
| [`authkestra-oidc`](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-oidc/README.md)                           | OpenID Connect discovery and provider support.                            |
| [`authkestra-op`](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-op/README.md)                               | OpenID Connect Provider (OP) implementation.                              |
| [`authkestra-devsig`](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-devsig/README.md)                       | Device-bound signature authentication (proof-of-possession + Issuer attestation). |
| [`authkestra-macros`](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-macros/README.md)                       | Procedural macros for simplifying Authkestra integration.                 |

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

To see complete, runnable examples for various frameworks and flows, check out the examples directory inside each crate:

- [Axum Basic Setup](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-axum/examples/basic_setup.rs): `cargo run -p authkestra-axum --example basic_setup`
- [Actix Basic Setup](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-actix/examples/basic_setup.rs): `cargo run -p authkestra-actix --example basic_setup`
- [Axum with GitHub OAuth](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-axum/examples/oauth2_github.rs): `cargo run -p authkestra-axum --example oauth2_github`
- [Axum with Google OIDC](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-axum/examples/oidc_google.rs): `cargo run -p authkestra-axum --example oidc_google`
- [Axum with Redis Session](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-axum/examples/session_redis.rs): `cargo run -p authkestra-axum --example session_redis`
- [Axum with SQL Store](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-axum/examples/sql_store.rs): `cargo run -p authkestra-axum --example sql_store`
- [Client Credentials Flow](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-engine/examples/client_credentials.rs): `cargo run -p authkestra-engine --example client_credentials`
- [Device Flow](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-engine/examples/device_flow.rs): `cargo run -p authkestra-engine --example device_flow`
- [SD-JWT (Selective Disclosure)](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-engine/examples/sd_jwt.rs): `cargo run -p authkestra-engine --example sd_jwt`
- [Axum Resource Server](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-axum/examples/resource_server.rs): `cargo run -p authkestra-axum --example resource_server`
- [Axum OP Server](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-axum/examples/op_server.rs): `cargo run -p authkestra-axum --example op_server`
- [Axum MFA Server (TOTP + WebAuthn)](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-axum/examples/mfa_server.rs): `cargo run -p authkestra-axum --example mfa_server`

## 🏗️ Technical Design Principles

Our architecture enforces strict design principles to guarantee compile-time safety and optimal Developer Experience (DX):

- **Typestate Builder Pattern**: The `Engine::builder()` uses Rust's typestate pattern. This makes misconfigurations a compile-time error rather than a runtime surprise.
- **Trait Objects over Generics**: For I/O bound paths, we prefer `Box<dyn Trait>` (e.g., `Box<dyn AuthMethod>`) over heavy monomorphized generics. This drastically optimizes compilation times without sacrificing meaningful runtime performance.
- **Framework Agnostic Core**: The `authkestra-engine` is pure Rust logic. Axum and Actix integrations are entirely isolated in separate adapter crates, utilizing explicit Extractors like `AuthSession(session)`.
- **Plugin Interfaces**: We extend functionality via strict plugin interfaces (`AuthMethod`, `Flow`) rather than opaque, ordering-dependent middleware.
- **Production-Ready Tracing**: Every handler, endpoint, and logical branch is deeply instrumented with the `tracing` crate, ensuring request flows and errors are fully visible in production without code changes.

## 📜 License

This project is dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](https://github.com/marcjazz/authkestra/blob/main/LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](https://github.com/marcjazz/authkestra/blob/main/LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
