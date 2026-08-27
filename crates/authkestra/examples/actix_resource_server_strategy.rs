//! # Actix resource server — `Guard` strategy (preferred)
//!
//! Validates bearer tokens issued by *someone else* (any OIDC provider). This
//! is the recommended shape: a [`Guard`] owns one or more strategies, and the
//! `Auth<T>` extractor asks the guard rather than reaching for JWT internals.
//!
//! ```sh
//! OIDC_ISSUER=https://accounts.google.com \
//!   cargo run -p authkestra --example actix_resource_server_strategy --all-features
//! ```

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

/// AppState using Engine's `Guard`.
#[derive(Clone, ActixState)]
struct AppState {
    #[authkestra(store)]
    guard: Arc<Guard<UserIdentity>>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
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

    let port = port_from_env();
    tracing::info!(%port, "Actix resource server (Guard strategy) listening on http://localhost:{port}");

    HttpServer::new(move || {
        let app_state = state.clone();
        App::new()
            .app_data(web::Data::new(app_state.guard.clone()))
            .service(index)
            .service(protected)
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

/// Bind port, overridable via `PORT` so several examples can run without
/// colliding on 3000.
fn port_from_env() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000)
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
        Some(Auth(user)) => {
            tracing::debug!(sub = %user.sub, "bearer token accepted by guard");
            HttpResponse::Ok().json(json!({
                "message": "Access granted via Resource Server Strategy!",
                "user": user,
            }))
        }
        None => {
            tracing::debug!("bearer token missing or rejected by guard");
            HttpResponse::Unauthorized().json(json!({
                "error": "Authentication failed or token missing/invalid",
            }))
        }
    }
}
