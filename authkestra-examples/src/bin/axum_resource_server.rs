use authkestra_axum::Jwt;
use authkestra_core::discovery::ProviderMetadata;
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
    scope: Option<String>,
}

#[derive(Clone)]
struct AppState {
    jwks_cache: Arc<JwksCache>,
    validation: Validation,
}

impl FromRef<AppState> for Arc<JwksCache> {
    fn from_ref(state: &AppState) -> Self {
        state.jwks_cache.clone()
    }
}

impl FromRef<AppState> for Validation {
    fn from_ref(state: &AppState) -> Self {
        state.validation.clone()
    }
}

struct Config {
    issuer: String,
    audience: Option<String>,
    port: u16,
}

impl Config {
    fn from_env() -> Self {
        Self {
            issuer: std::env::var("OIDC_ISSUER")
                .unwrap_or_else(|_| "https://accounts.google.com".to_string()),
            audience: std::env::var("OIDC_AUDIENCE").ok(),
            port: std::env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let config = Config::from_env();

    // 1. Discover OIDC provider metadata
    println!("🔍 Discovering provider metadata for: {}", config.issuer);
    let provider_metadata =
        ProviderMetadata::discover(&config.issuer, reqwest::Client::new()).await?;

    println!("🔑 Using JWKS URI: {}", provider_metadata.jwks_uri);

    // 2. Configure Offline Validation components
    let jwks_cache = Arc::new(JwksCache::new(
        provider_metadata.jwks_uri,
        Duration::from_secs(3600),
    ));

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[config.issuer]);
    if let Some(audience) = config.audience {
        validation.set_audience(&[audience]);
    }

    let state = AppState {
        jwks_cache,
        validation,
    };

    // 3. Build Axum Router
    let app = Router::new()
        .route("/", get(index))
        .route("/api/protected", get(protected))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("📡 Listening on http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn index() -> impl IntoResponse {
    "Axum Resource Server. Use a Bearer token to access /api/protected"
}

async fn protected(Jwt(claims): Jwt<MyClaims>) -> impl IntoResponse {
    let scope_msg = claims
        .scope
        .as_ref()
        .map(|s| format!(" Your scopes: {}", s))
        .unwrap_or_default();

    format!(
        "Hello, {}! Your email is {:?}.{} You have access to this protected resource.",
        claims.sub, claims.email, scope_msg
    )
}

