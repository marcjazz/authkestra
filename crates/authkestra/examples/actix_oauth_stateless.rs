//! # Actix Stateless OAuth Example
//!
//! This example demonstrates how to set up Engine for OAuth2 in stateless mode,
//! where the callback returns a JWT instead of creating a server-side session.
//!
//! To run this example, you'll need:
//! - `AUTHKESTRA_GITHUB_CLIENT_ID`
//! - `AUTHKESTRA_GITHUB_CLIENT_SECRET`

use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra_actix::{ActixState, ActixStatelessExt, AuthToken};
use authkestra_engine::flow::{Engine, OAuth2Flow};
use authkestra_engine::AkApiEngine;
use authkestra_providers::github::GithubProvider;
use serde_json::json;

/// Engine state with support for tokens (stateless mode).
#[derive(Clone, ActixState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkApiEngine,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    let client_id = std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID")
        .expect("AUTHKESTRA_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET")
        .expect("AUTHKESTRA_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHKESTRA_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/callback/github".to_string());

    // Support E2E tests pointing to a local mock server
    let github_provider = match std::env::var("AUTHKESTRA_GITHUB_BASE_URL") {
        Ok(base_url) => {
            let api_url =
                std::env::var("AUTHKESTRA_GITHUB_API_URL").unwrap_or_else(|_| base_url.clone());
            GithubProvider::new(client_id, client_secret, redirect_uri).with_test_urls(
                format!("{base_url}/login/oauth/authorize"),
                format!("{base_url}/login/oauth/access_token"),
                format!("{api_url}/user"),
            )
        }
        Err(_) => GithubProvider::new(client_id, client_secret, redirect_uri),
    };

    // Initialize Engine in stateless mode (JWT only).
    let authkestra = Engine::builder()
        .provider(OAuth2Flow::new(github_provider))
        .jwt_secret(b"your-256-bit-secret-key-at-least-32-bytes-long")
        .build();

    let state = AppState { auth: authkestra };

    println!("🚀 Actix Stateless OAuth running on http://localhost:3000");
    println!("1. Login: http://localhost:3000/auth/github");
    println!("2. The callback will return a JSON with a JWT.");
    println!("3. Use the JWT in the 'Authorization: Bearer <token>' header for /api/user");

    HttpServer::new(move || {
        let app_state = state.clone();
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .configure(|cfg| app_state.configure_authkestra(cfg))
            .service(app_state.auth.actix_scope_stateless())
            .service(get_user)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}

/// Protected endpoint using `AuthToken` extractor.
#[get("/api/user")]
async fn get_user(auth: Option<AuthToken>) -> impl Responder {
    match auth {
        Some(AuthToken(claims)) => {
            let identity = claims.identity.as_ref().unwrap();
            HttpResponse::Ok().json(json!({
                "id": identity.external_id,
                "username": identity.username,
                "email": identity.email,
                "provider": identity.provider_id,
            }))
        }
        None => HttpResponse::Unauthorized().json(json!({ "error": "Not authenticated" })),
    }
}
