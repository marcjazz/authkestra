//! # Actix Resource Server Strategy Example
//!
//! This example demonstrates how to use the Resource Server strategy with `Guard`
//! and the `Auth` extractor to protect an API.

use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra_actix::{ActixState, Auth};
use authkestra_resource::{jwt::JwtStrategy, jwt::ValidationConfig, Guard};
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
#[derive(Clone, ActixState)]
struct AppState {
    #[authkestra(store)]
    guard: Arc<Guard<UserIdentity>>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
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

    println!("📡 Resource Server Strategy listening on http://0.0.0.0:3000");

    HttpServer::new(move || {
        let app_state = state.clone();
        App::new()
            .app_data(web::Data::new(app_state.guard.clone()))
            .service(index)
            .service(protected)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .body("Actix Resource Server (Strategy Mode). Use a Bearer token to access /api/protected")
}

/// Protected endpoint using the `Auth` extractor.
/// This extractor uses the `Guard` from the state to validate the request.
#[get("/api/protected")]
async fn protected(auth: Option<Auth<UserIdentity>>) -> impl Responder {
    match auth {
        Some(Auth(user)) => HttpResponse::Ok().json(json!({
            "message": "Access granted via Resource Server Strategy!",
            "user": user,
        })),
        None => HttpResponse::Unauthorized().json(json!({
            "error": "Authentication failed or token missing/invalid",
        })),
    }
}
