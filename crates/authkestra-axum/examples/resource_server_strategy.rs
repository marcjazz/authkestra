//! # Axum Resource Server Strategy Example
//!
//! This example demonstrates how to use the Resource Server strategy with `Guard`
//! and the `Auth` extractor to protect an API.

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

/// AppState using Authkestra's `Guard`.
#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(store)]
    guard: Arc<Guard<UserIdentity>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("📡 Resource Server Strategy listening on http://{addr}");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn index() -> impl IntoResponse {
    "Axum Resource Server (Strategy Mode). Use a Bearer token to access /api/protected"
}

/// Protected endpoint using the `Auth` extractor.
/// This extractor uses the `Guard` from the state to validate the request.
async fn protected(Auth(user): Auth<UserIdentity>) -> impl IntoResponse {
    Json(json!({
        "message": "Access granted via Resource Server Strategy!",
        "user": user,
    }))
}
