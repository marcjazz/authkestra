//! # Axum Resource Server Strategy Example
//!
//! This example demonstrates how to use the Resource Server strategy with `AuthEngineGuard`
//! and the `Auth` extractor to protect an API.

use authkestra_axum::Auth;
use authkestra_resource::{jwt::JwtStrategy, jwt::ValidationConfig, ResourceEnforcer};
use axum::{
    extract::FromRef,
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

/// AppState using Authkestra's `AuthEngineGuard` (ResourceEnforcer).
#[derive(Clone)]
struct AppState {
    resource_enforcer: Arc<ResourceEnforcer<UserIdentity>>,
}

impl FromRef<AppState> for Arc<ResourceEnforcer<UserIdentity>> {
    fn from_ref(state: &AppState) -> Self {
        state.resource_enforcer.clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    // 1. Configure the JWT Strategy
    let issuer = std::env::var("OIDC_ISSUER")
        .unwrap_or_else(|_| "https://accounts.google.com".to_string());
    
    let validation_config = ValidationConfig::builder()
        .jwks_url(format!("{}/.well-known/jwks.json", issuer))
        .issuer(issuer)
        .build();

    let jwt_strategy = JwtStrategy::<UserIdentity>::new(validation_config);

    // 2. Configure the Resource Enforcer (Guard)
    let resource_enforcer = ResourceEnforcer::builder()
        .strategy(jwt_strategy)
        .build();

    let state = AppState {
        resource_enforcer: Arc::new(resource_enforcer),
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
/// This extractor uses the `ResourceEnforcer` from the state to validate the request.
async fn protected(Auth(user): Auth<UserIdentity>) -> impl IntoResponse {
    Json(json!({
        "message": "Access granted via Resource Server Strategy!",
        "user": user,
    }))
}
