//! # Actix + Google OIDC (stateful sessions)
//!
//! Same shape as `actix_oauth2_github.rs`, with Google's OIDC provider swapped
//! in — the point being that [`Engine::builder`] treats every provider
//! identically: `.provider(OAuth2Flow::new(..))` and nothing else changes.
//!
//! ```sh
//! AUTHKESTRA_GOOGLE_CLIENT_ID=... AUTHKESTRA_GOOGLE_CLIENT_SECRET=... \
//!   cargo run -p authkestra --example actix_oidc_google --all-features
//! ```
//!
//! Register `http://localhost:3000/auth/callback/google` as an authorised
//! redirect URI in the Google Cloud console — that is the path
//! [`ActixExt::actix_scope`] actually wires. Set `PORT` to bind elsewhere; the
//! default redirect URI follows it.

use actix_files::Files;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra_actix::{ActixExt, ActixState, AuthSession};
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::{AkWebAppEngine, Engine, OAuth2Flow, SessionConfig, SessionStore};
use authkestra_providers::google::GoogleProvider;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone, ActixState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkWebAppEngine,
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

    let port = port_from_env();

    let client_id = std::env::var("AUTHKESTRA_GOOGLE_CLIENT_ID")
        .expect("AUTHKESTRA_GOOGLE_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GOOGLE_CLIENT_SECRET")
        .expect("AUTHKESTRA_GOOGLE_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHKESTRA_GOOGLE_REDIRECT_URI")
        .unwrap_or_else(|_| format!("http://localhost:{port}/auth/callback/google"));

    let google_provider = google_provider(client_id, client_secret, redirect_uri);

    // `SessionStore` is a trait: swap `MemoryStore` for `RedisStore` or
    // `SqlKvStore` without touching anything below this line.
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());

    let engine = Engine::builder()
        .provider(OAuth2Flow::new(google_provider))
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false, // plain HTTP for local development
            ..Default::default()
        })
        .build();

    let state = AppState { auth: engine };

    tracing::info!(%port, "Actix Google OIDC listening on http://localhost:{port}");
    tracing::info!("start the flow at http://localhost:{port}/auth/login/google");

    HttpServer::new(move || {
        let app_state = state.clone();
        let config_state = app_state.clone();
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .configure(move |cfg| config_state.configure_authkestra(cfg))
            .service(get_user)
            .service(list_providers)
            .service(app_state.auth.actix_scope())
            .service(
                Files::new("/", concat!(env!("CARGO_MANIFEST_DIR"), "/examples/static"))
                    .index_file("index.html"),
            )
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

/// Builds the provider, redirecting to a mock server when the e2e harness has
/// set `AUTHKESTRA_GOOGLE_BASE_URL`. Real deployments never set these.
fn google_provider(
    client_id: String,
    client_secret: String,
    redirect_uri: String,
) -> GoogleProvider {
    let provider = GoogleProvider::new(client_id, client_secret, redirect_uri);
    match std::env::var("AUTHKESTRA_GOOGLE_BASE_URL") {
        Ok(base_url) => {
            let api_url =
                std::env::var("AUTHKESTRA_GOOGLE_API_URL").unwrap_or_else(|_| base_url.clone());
            tracing::warn!(%base_url, "using overridden Google endpoints (test mode)");
            provider.with_test_urls(
                format!("{base_url}/login/oauth/authorize"),
                format!("{base_url}/login/oauth/access_token"),
                format!("{api_url}/user"),
            )
        }
        Err(_) => provider,
    }
}

/// Returns the session identity, or 401 when there is no valid session.
#[get("/api/user")]
async fn get_user(session: Option<AuthSession>) -> impl Responder {
    match session {
        Some(AuthSession(session)) => {
            tracing::debug!(user = %session.identity.external_id, "session resolved");
            HttpResponse::Ok().json(json!({
                "id": session.identity.external_id,
                "username": session.identity.username,
                "email": session.identity.email,
                "provider": session.identity.provider_id,
            }))
        }
        None => {
            tracing::debug!("no valid session on request");
            HttpResponse::Unauthorized().json(json!({ "error": "Not authenticated" }))
        }
    }
}

/// Lists the registered OAuth providers so the bundled static page can render
/// a login button per provider.
#[get("/api/providers")]
async fn list_providers(state: web::Data<AppState>) -> impl Responder {
    let providers: Vec<&String> = state.auth.providers.keys().collect();
    HttpResponse::Ok().json(json!({ "providers": providers }))
}

/// Bind port, overridable via `PORT` so several examples (and the e2e test
/// harness, which passes a port it has already confirmed to be free) can run
/// without colliding on 3000.
fn port_from_env() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000)
}
