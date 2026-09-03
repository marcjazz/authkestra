# Chapter 8: Getting Started Tutorial

Welcome to the Authkestra getting started guide! This chapter walks you through wiring an
`Engine` into a basic web application. We'll use `axum` here, but the engine construction is
byte-for-byte identical for `actix-web` — only the adapter call at the end differs.

> The canonical, always-compiled version of this tutorial is
> `crates/authkestra/examples/axum_basic_setup.rs`. If anything below disagrees with it, the
> example is right — run it with
> `cargo run -p authkestra --example axum_basic_setup --all-features`.

## Prerequisites

Before starting, ensure you have:

- Rust (latest stable) installed via `rustup`.
- A basic understanding of Rust async programming and web frameworks.

## Step 1: Create a New Project

Initialize a new Rust project:

```bash
cargo new authkestra-hello-world
cd authkestra-hello-world
```

Add the dependencies to your `Cargo.toml`. The `authkestra` facade re-exports the rest of the
workspace behind feature flags; you also want `authkestra-engine` directly for the store types:

```toml
[dependencies]
authkestra = { version = "0.7", features = ["axum", "session"] }
authkestra-axum = { version = "0.7", features = ["macros", "session"] }
authkestra-engine = { version = "0.7", features = ["session", "memory"] }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
tower-cookies = "0.11"
serde_json = "1"
```

## Step 2: Build the Engine

The core of Authkestra is the `Engine`, constructed through a **typestate builder**. Methods only
exist once their prerequisite has been supplied — calling a session API on an engine built
without `.session_store()` is a compile error, not a runtime panic.

`AkWebAppEngine` is the alias for a session-configured engine. Using the alias, rather than
spelling out the typestate generics, keeps the compiler error legible when a builder call is
missing.

```rust,ignore
use authkestra::Authkestra;
use authkestra_axum::{AuthSession, AxumExt, AxumState};
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::{AkWebAppEngine, SessionConfig, SessionStore};
use axum::{response::Json, routing::get, Router};
use serde_json::json;
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;

/// The `AxumState` derive generates every `FromRef` impl the extractors need.
#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkWebAppEngine,
}

#[tokio::main]
async fn main() {
    // 1. Pick a storage backend. `SessionStore` is a trait, so swapping `MemoryStore`
    //    for `RedisStore` or `SqlKvStore` is a one-line change. The explicit
    //    `Arc<dyn SessionStore>` annotation is what coerces the concrete store into
    //    the trait object `.session_store()` expects.
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());

    // 2. Build the engine.
    let engine = Authkestra::builder()
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false, // plain HTTP for local development
            ..Default::default()
        })
        .build();

    let state = AppState { auth: engine.clone() };

    // 3. Mount the engine's routes. `axum_router()` wires
    //    `/auth/login/{provider}`, `/auth/callback/{provider}` and `/auth/logout`.
    let app = Router::new()
        .route("/", get(|| async { "Hello, Authkestra!" }))
        .route("/api/user", get(get_user))
        .merge(engine.axum_router())
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}
```

Note that no provider is registered yet — this step is about the *session* half of the engine.
`CookieManagerLayer` is required: the session and OAuth-state cookies are read through
`tower-cookies`.

## Step 3: Protect a Route

Use the `AuthSession` extractor. Taking it as `Option<AuthSession>` lets you return your own
response for the unauthenticated case instead of the adapter's default rejection:

```rust,ignore
async fn get_user(session: Option<AuthSession>) -> Json<serde_json::Value> {
    match session {
        Some(AuthSession(session)) => Json(json!({
            "id": session.identity.external_id,
            "email": session.identity.email,
        })),
        None => Json(json!({ "error": "not authenticated" })),
    }
}
```

## Step 4: Run It

```bash
cargo run
```

You should see `Server running on http://localhost:3000`. `GET /api/user` returns
`{"error":"not authenticated"}` until a session cookie exists — which brings us to providers.

## Adding OAuth2

An OAuth provider is registered as a `Flow`, not as a bare provider: wrap it in an `OAuth2Flow`.
The provider's own `provider_id()` (here, `"github"`) is what the `{provider}` path segment
matches against, so this registration is what makes `/auth/login/github` resolve.

```rust,ignore
use authkestra_engine::OAuth2Flow;
use authkestra_providers::github::GithubProvider;

let github = GithubProvider::new(
    std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID").unwrap(),
    std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET").unwrap(),
    // Must exactly match the callback URL registered with GitHub.
    "http://localhost:3000/auth/callback/github".to_string(),
);

let engine = Authkestra::builder()
    .provider(OAuth2Flow::new(github))
    .session_store(session_store)
    .build();
```

Add `authkestra = { version = "0.7", features = ["axum", "session", "github"] }` to pull in the
provider. Registering a second provider is another `.provider(...)` call — the same two routes
serve both, resolved at runtime.

The full version of this is
`crates/authkestra/examples/axum_oauth2_github.rs`:

```bash
AUTHKESTRA_GITHUB_CLIENT_ID=... AUTHKESTRA_GITHUB_CLIENT_SECRET=... \
  cargo run -p authkestra --example axum_oauth2_github --all-features
```

## Conclusion

You've integrated Authkestra into a basic Rust web application. From here, explore swapping in a
persistent store (Chapter 6), protecting an API with the `Guard` and JWT strategies, or standing
up your own OpenID Provider with `authkestra-op`. Every scenario has a runnable counterpart under
`crates/authkestra/examples/`.
