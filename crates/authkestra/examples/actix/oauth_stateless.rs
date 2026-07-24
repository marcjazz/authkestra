//! # Actix Stateless OAuth Example
//!
//! This example demonstrates how to set up Engine for OAuth2 in stateless mode,
//! where the callback returns a JWT instead of creating a server-side session.
//!
//! To run this example, you'll need:
//! - `AUTHKESTRA_GITHUB_CLIENT_ID`
//! - `AUTHKESTRA_GITHUB_CLIENT_SECRET`

use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use authkestra::flow::{Engine, OAuth2Flow};
use authkestra_actix::{helpers, ActixState, AuthToken};
use authkestra_engine::{AkApiEngine, TokenManagerState};
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

    let github_provider = GithubProvider::new(client_id, client_secret, redirect_uri);

    // Initialize Authkestra in stateless mode (JWT only).
    let auth_engine = Engine::builder()
        .provider(OAuth2Flow::new(github_provider))
        .jwt_secret(b"your-256-bit-secret-key-at-least-32-bytes-long")
        .build();

    let state = AppState { auth: auth_engine };

    println!("🚀 Actix Stateless OAuth running on http://localhost:3000");
    println!("1. Login: http://localhost:3000/auth/github");
    println!("2. The callback will return a JSON with a JWT.");
    println!("3. Use the JWT in the 'Authorization: Bearer <token>' header for /api/user");

    HttpServer::new(move || {
        let app_state = state.clone();
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .configure(|cfg| app_state.configure_authkestra(cfg))
            // Login route
            .route("/auth/{provider}", web::get().to(login_handler))
            // Callback route (stateless)
            .route("/auth/callback/{provider}", web::get().to(callback_handler))
            .service(get_user)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}

/// Custom login handler using Engine helpers.
async fn login_handler(
    path: web::Path<String>,
    state: web::Data<AppState>,
    params: web::Query<helpers::OAuthLoginParams>,
) -> impl Responder {
    let provider = path.into_inner();
    let flow = match state.auth.providers.get(&provider) {
        Some(f) => f,
        None => {
            return HttpResponse::NotFound().body(format!("Provider {provider} not found"));
        }
    };

    let scopes_str = params.scope.clone().unwrap_or_default();
    let scopes: Vec<&str> = scopes_str
        .split(|c: char| [' ', ','].contains(&c))
        .filter(|s| !s.is_empty())
        .collect();

    helpers::initiate_oauth_login_erased(
        flow.as_ref(),
        &scopes,
        &state.auth.session_config,
        params.success_url.clone(),
    )
}

/// Custom callback handler for stateless mode (returns JWT).
async fn callback_handler(
    req: HttpRequest,
    path: web::Path<String>,
    state: web::Data<AppState>,
    params: web::Query<helpers::OAuthCallbackParams>,
) -> actix_web::Result<impl Responder> {
    let provider = path.into_inner();
    let flow = match state.auth.providers.get(&provider) {
        Some(f) => f,
        None => {
            return Ok(HttpResponse::NotFound().body(format!("Provider {provider} not found")));
        }
    };

    let token_manager = state.auth.token_manager.get_manager();

    let res = helpers::handle_oauth_callback_jwt_erased(
        flow.as_ref(),
        &req,
        params.into_inner(),
        token_manager,
        3600, // 1 hour
        state.auth.session_config.clone(),
    )
    .await?;

    Ok(res)
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
