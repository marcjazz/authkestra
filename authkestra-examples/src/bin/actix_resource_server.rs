use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra_actix::Jwt;
use authkestra_token::offline_validation::JwksCache;
use jsonwebtoken::{Algorithm, Validation};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

/// This example demonstrates an Actix resource server that protects its endpoints
/// using JWTs validated against an external OIDC provider's JWKS.

#[derive(Debug, Deserialize)]
struct MyClaims {
    sub: String,
    email: Option<String>,
    // Add other claims you expect from your provider
}

#[get("/api/protected")]
async fn protected(claims: Jwt<MyClaims>) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Hello, {}! Your email is {:?}. You have access to this protected resource.",
        claims.0.sub, claims.0.email
    ))
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Actix Resource Server. Use a Bearer token to access /api/protected")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    // 1. Configure the OIDC provider's JWKS URI
    // For example, Google's JWKS URI: https://www.googleapis.com/oauth2/v3/certs
    let jwks_uri = std::env::var("OIDC_JWKS_URI")
        .unwrap_or_else(|_| "https://www.googleapis.com/oauth2/v3/certs".to_string());

    println!("🚀 Starting Actix Resource Server...");
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

    let cache_data = web::Data::new(cache);
    let validation_data = web::Data::new(validation);

    println!("📡 Listening on http://localhost:3000");

    HttpServer::new(move || {
        App::new()
            .app_data(cache_data.clone())
            .app_data(validation_data.clone())
            .service(index)
            .service(protected)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}
