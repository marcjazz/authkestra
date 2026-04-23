# Chapter 8: Getting Started Tutorial

Welcome to the Authkestra getting started guide! This chapter provides a highly practical "Hello World" tutorial that walks you through setting up `AuthEngine` in a basic web application. We'll use the popular `axum` framework for this example, but the concepts apply similarly to `actix-web`.

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

Add the necessary dependencies to your `Cargo.toml`:

```toml
[dependencies]
tokio = { version = "1.0", features = ["full"] }
axum = "0.7"
authkestra-core = { version = "0.1", features = ["axum"] }
# Include necessary providers if needed, e.g.:
# authkestra-providers-github = "0.1"
```

## Step 2: Initialize AuthEngine

The core of Authkestra is the `AuthEngine`. Let's initialize it in our `main.rs`. For this tutorial, we will set up a basic in-memory configuration.

```rust
use axum::{routing::get, Router};
use authkestra_core::engine::{AuthEngine, EngineConfig};
use authkestra_core::providers::LocalProvider;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // 1. Configure the engine
    let config = EngineConfig::default()
        .with_secret_key("super_secret_development_key_do_not_use_in_prod");

    // 2. Instantiate the engine and add providers
    let mut engine = AuthEngine::new(config);

    // Add a local email/password provider for demonstration
    engine.add_provider(LocalProvider::new());

    let engine = Arc::new(engine);

    // 3. Set up the Axum router
    let app = Router::new()
        .route("/", get(|| async { "Hello, Authkestra!" }))
        // Mount Authkestra routes under /auth
        .nest("/auth", authkestra_axum::routes(engine.clone()))
        // Use the engine as state if needed in other routes
        .with_state(engine);

    // 4. Run the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}
```

## Step 3: Run the Application

Run your application using Cargo:

```bash
cargo run
```

You should see `Server running on http://localhost:3000`.

## Exploring the Endpoints

By mounting the Authkestra routes under `/auth`, you immediately gain access to standard authentication flows.

- **Login**: Navigate to `http://localhost:3000/auth/login` (if UI is enabled) or use the API endpoint `POST /auth/login`.
- **Register**: `POST /auth/register` (for local providers).

## Adding OAuth2 (Optional)

Adding an OAuth2 provider like GitHub is just a few extra lines:

```rust
use authkestra_providers_github::GitHubProvider;

// Inside main, before wrapping engine in Arc:
let github_provider = GitHubProvider::new(
    std::env::var("GITHUB_CLIENT_ID").unwrap(),
    std::env::var("GITHUB_CLIENT_SECRET").unwrap(),
);
engine.add_provider(github_provider);
```

## Securing a Route

To protect a route, you can use Authkestra's provided extractors or middleware to ensure the user is authenticated.

```rust
use authkestra_axum::extract::RequireAuth;
use axum::response::IntoResponse;

async fn protected_profile(user: RequireAuth) -> impl IntoResponse {
    format!("Hello, user {}!", user.id())
}

// In router:
// .route("/profile", get(protected_profile))
```

## Conclusion

You've successfully integrated Authkestra into a basic Rust web application! From here, you can explore adding persistent storage adapters, implementing custom authorization policies, or adding more identity providers.
