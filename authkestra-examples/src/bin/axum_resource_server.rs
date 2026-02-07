use authkestra_axum::Jwt;
use authkestra_token::offline_validation::JwksCache;
use axum::{extract::FromRef, response::IntoResponse, routing::get, Router};
use jsonwebtoken::{Algorithm, Validation};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

/// This example demonstrates an Axum resource server that protects its endpoints
/// using JWTs validated against an external OIDC provider's JWKS.

#[derive(Debug, Deserialize)]
struct MyClaims {
    sub: String,
    email: Option<String>,
    // Add other claims you expect from your provider
}

#[derive(Clone)]
struct AppState {
    cache: Arc<JwksCache>,
    validation: Validation,
}

impl FromRef<AppState> for Arc<JwksCache> {
    fn from_ref(state: &AppState) -> Self {
        state.cache.clone()
    }
}

impl FromRef<AppState> for Validation {
    fn from_ref(state: &AppState) -> Self {
        state.validation.clone()
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // 1. Configure the OIDC provider's JWKS URI
    let jwks_uri = std::env::var("OIDC_JWKS_URI")
        .unwrap_or_else(|_| "https://www.googleapis.com/oauth2/v3/certs".to_string());

    println!("🚀 Starting Axum Resource Server...");
    println!("🔑 Using JWKS URI: {}", jwks_uri);

    // 2. Initialize the JWKS Cache
    let cache = Arc::new(JwksCache::new(jwks_uri, Duration::from_secs(3600)));

    // 3. Configure JWT Validation
    let mut validation = Validation::new(Algorithm::RS256);
    if let Ok(issuer) = std::env::var("OIDC_ISSUER") {
        validation.set_issuer(&[issuer]);
    }
    if let Ok(audience) = std::env::var("OIDC_AUDIENCE") {
        validation.set_audience(&[audience]);
    }

    let state = AppState { cache, validation };

    // 4. Build Axum Router
    let app = Router::new()
        .route("/", get(index))
        .route("/api/protected", get(protected))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("📡 Listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> impl IntoResponse {
    "Axum Resource Server. Use a Bearer token to access /api/protected"
}

async fn protected(Jwt(claims): Jwt<MyClaims>) -> impl IntoResponse {
    format!(
        "Hello, {}! Your email is {:?}. You have access to this protected resource.",
        claims.sub, claims.email
    )
}
