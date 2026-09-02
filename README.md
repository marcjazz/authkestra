# Authkestra

[![CI](https://github.com/marcjazz/authkestra/actions/workflows/ci.yml/badge.svg)](https://github.com/marcjazz/authkestra/actions)
[![Coverage](https://codecov.io/gh/marcjazz/authkestra/branch/main/graph/badge.svg)](https://codecov.io/gh/marcjazz/authkestra)
[![Crates.io](https://img.shields.io/crates/v/authkestra.svg)](https://crates.io/crates/authkestra)
[![Docs](https://docs.rs/authkestra/badge.svg)](https://docs.rs/authkestra)

`authkestra` is a modular, framework-agnostic authentication orchestration system designed to be idiomatic to Rust, emphasizing **explicit control flow, strong typing, and composability** over dynamic middleware strategies common in other ecosystems.

## 📦 Getting Started

The easiest way to use Authkestra is via the `authkestra` facade crate. It re-exports all sub-crates behind feature flags, allowing you to manage your authentication stack from a single dependency.

Add this to your `Cargo.toml`:

```toml
[dependencies]
# Use the facade with the features you need
authkestra = { version = "0.7", features = ["axum", "github"] }
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
authkestra = { version = "0.7", default-features = false, features = ["axum", "github", "rustls-no-provider"] }
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
- **Database Agnostic**: Authkestra never enforces schemas. All data access is strictly defined via traits (`KvStore`, `SessionStore`, `CredentialStore`, and `authkestra-op`'s `OpStore`), allowing you to use any database or ORM. There is deliberately no user/account table and no `UserStore` trait — your application owns that data (see `docs/book/ch02-core-engine-and-identity.md`).
- **Flexible Chaining**: Chain multiple authentication strategies (Token, Session, Basic, Custom) seamlessly.
- **OpenID Connect Provider (OP)**: Build your own identity provider and authorization server using `authkestra-op`.
- **Session Management**: Built-in support for in-memory, Redis, and SQL via `sqlx`.
- **SD-JWT (Selective Disclosure)**: Issue a single JWT carrying selectively disclosable claims (`draft-ietf-oauth-selective-disclosure-jwt`); the holder decides, per presentation, which claims to reveal to each verifier.

## 📦 Workspace Crates

| Crate | Description |
| --- | --- |
| [`authkestra`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra)                     | **Primary Facade**: Re-exports all other crates behind features. Hosts the runnable examples. |
| [`authkestra-engine`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-engine)       | Foundational types, traits and the **Engine** orchestrator.               |
| [`authkestra-resource`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-resource)   | Resource server enforcement and validation (JWT, etc).                    |
| [`authkestra-providers`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-providers) | Concrete implementation for OAuth providers (GitHub, Google, Discord).    |
| [`authkestra-axum`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-axum)           | Axum-specific integration, including `AuthSession` extractors.            |
| [`authkestra-actix`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-actix)         | Actix-specific integration, including `ActixState` macro support.         |
| [`authkestra-oidc`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-oidc)           | OpenID Connect discovery and provider support.                            |
| [`authkestra-op`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-op)               | OpenID Connect Provider (OP) implementation.                              |
| [`authkestra-devsig`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-devsig)       | Device-bound signature authentication (proof-of-possession + Issuer attestation). |
| [`authkestra-crypto-util`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-crypto-util) | Shared strict signature/key verification helpers used by the OP and devsig crates. |
| [`authkestra-macros`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-macros)       | Procedural macros for simplifying Authkestra integration.                 |

## 🛠️ Usage

Authkestra utilizes a powerful **Typestate Builder Pattern** (`Engine::builder()`). This enforces at compile-time that certain methods are only available if their prerequisites are met (e.g., you can only call session methods if a `SessionStore` was provided).

### Quick Start Example

```rust,ignore
use authkestra::Authkestra;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::{OAuth2Flow, SessionStore};
use authkestra_providers::github::GithubProvider;
use std::sync::Arc;

// The builder ensures compile-time safety for your authentication stack
let github_provider = GithubProvider::new(client_id, client_secret, redirect_uri);
let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());

let auth_engine = Authkestra::builder()
    .provider(OAuth2Flow::new(github_provider))
    .session_store(session_store)
    .build();
```

Every runnable example lives in the facade crate, under
[`crates/authkestra/examples/`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra/examples),
so a single `cargo run -p authkestra --example <name>` covers both frameworks. Each example's
own module docs list the environment variables it needs.

| Example | Command |
| --- | --- |
| Axum basic setup | `cargo run -p authkestra --example axum_basic_setup --all-features` |
| Actix basic setup | `cargo run -p authkestra --example actix_basic_setup --all-features` |
| Axum with GitHub OAuth | `cargo run -p authkestra --example axum_oauth2_github --all-features` |
| Axum with Google OIDC | `cargo run -p authkestra --example axum_oidc_google --all-features` |
| Axum stateless OAuth (JWT callback) | `cargo run -p authkestra --example axum_oauth_stateless --all-features` |
| Axum with Redis session | `cargo run -p authkestra --example axum_session_redis --all-features` |
| Axum with SQL store | `cargo run -p authkestra --example axum_sql_store --all-features` |
| Axum resource server | `cargo run -p authkestra --example axum_resource_server --all-features` |
| Axum OP server | `cargo run -p authkestra --example axum_op_server --all-features` |
| Axum OP server on SQLx | `cargo run -p authkestra --example axum_op_server_sqlx --all-features` |
| Axum OP server with device attestation | `cargo run -p authkestra --example axum_op_server_attestation --features full` |
| Axum MFA server (TOTP + WebAuthn) | `cargo run -p authkestra --example axum_mfa_server --all-features` |
| Axum device-bound signatures | `cargo run -p authkestra --example axum_devsig --all-features` |
| Axum data-layer macros (`KvStore` derive) | `cargo run -p authkestra --example axum_data_layer_macros --all-features` |
| Axum OP server with a custom grant | `cargo run -p authkestra --example axum_op_server_custom_grant --all-features` |
| Axum resource server with chained strategies | `cargo run -p authkestra --example axum_resource_server_strategy --all-features` |

Most of these have an Actix counterpart under the same name with the `actix_` prefix —
`actix_basic_setup`, `actix_oauth2_github`, `actix_oidc_google`, `actix_oauth_stateless`,
`actix_op_server`, `actix_op_server_sqlx`, `actix_op_server_custom_grant`,
`actix_op_server_attestation`, `actix_resource_server_strategy`, `actix_devsig`. Five scenarios
are Axum-only today and have **no** Actix twin: `axum_mfa_server`, `axum_session_redis`,
`axum_sql_store`, `axum_data_layer_macros`, and `axum_resource_server`.

Four protocol-level examples live in `authkestra-engine` instead, because they need no web
framework at all:

- [Client Credentials Flow](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-engine/examples/client_credentials.rs): `cargo run -p authkestra-engine --example client_credentials`
- [Device Flow](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-engine/examples/device_flow.rs): `cargo run -p authkestra-engine --example device_flow`
- [SD-JWT (Selective Disclosure)](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-engine/examples/sd_jwt.rs): `cargo run -p authkestra-engine --example sd_jwt`
- [TOTP enrolment and verification](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-engine/examples/totp_webauthn.rs) (named `totp_webauthn`, but it exercises the TOTP path only): `cargo run -p authkestra-engine --example totp_webauthn --features totp,sql-sqlite`

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
