//! # Axum resource server — `Guard` strategy (preferred)
//!
//! Validates bearer tokens issued by *someone else* (any OIDC provider). This
//! is the recommended shape: a [`Guard`] owns one or more strategies, and the
//! `Auth<T>` extractor asks the guard rather than reaching for JWT internals.
//!
//! `axum_resource_server.rs` shows the lower-level alternative (wiring
//! `JwksCache` and `jsonwebtoken::Validation` yourself); prefer this one unless
//! you need that control.
//!
//! ```sh
//! OIDC_ISSUER=https://accounts.google.com \
//!   cargo run -p authkestra --example axum_resource_server_strategy --all-features
//! ```

use authkestra_axum::{Auth, AxumState};
use authkestra_resource::{jwt::JwtStrategy, jwt::ValidationConfig, Guard};
use axum::{
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

/// A custom identity structure representing a validated token user.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserIdentity {
    sub: String,
    email: Option<String>,
    scope: Option<String>,
}

/// AppState using Engine's `Guard`.
#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(store)]
    guard: Arc<Guard<UserIdentity>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `RUST_LOG=authkestra=debug` surfaces the engine's own instrumentation.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,authkestra=debug".into()),
        )
        .init();

    dotenvy::dotenv().ok();

    // 1. Configure the JWT Strategy
    let issuer =
        std::env::var("OIDC_ISSUER").unwrap_or_else(|_| "https://accounts.google.com".to_string());

    let validation_config = ValidationConfig::builder()
        .jwks_url(format!("{}/.well-known/jwks.json", issuer))
        .issuer(issuer)
        .build();

    let jwt_strategy = JwtStrategy::<UserIdentity>::new(validation_config);

    // 2. Configure the Resource Enforcer (Guard)
    let guard = Guard::builder().strategy(jwt_strategy).build();

    let state = AppState {
        guard: Arc::new(guard),
    };

    // 3. Build Axum Router
    let app = Router::new()
        .route("/", get(index))
        .route("/api/protected", get(protected))
        .with_state(state);

    let port = port_from_env();
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(%port, "Axum resource server (Guard strategy) listening on http://localhost:{port}");

    axum::serve(listener, app).await?;

    Ok(())
}

/// Bind port, overridable via `PORT` so several examples can run without
/// colliding on 3000.
fn port_from_env() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000)
}

async fn index() -> impl IntoResponse {
    "Axum Resource Server (Strategy Mode). Use a Bearer token to access /api/protected"
}

/// Protected endpoint using the `Auth` extractor.
/// This extractor uses the `Guard` from the state to validate the request.
async fn protected(Auth(user): Auth<UserIdentity>) -> impl IntoResponse {
    tracing::debug!(sub = %user.sub, "bearer token accepted by guard");
    Json(json!({
        "message": "Access granted via Resource Server Strategy!",
        "user": user,
    }))
}
