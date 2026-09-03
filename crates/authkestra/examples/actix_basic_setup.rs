//! # Actix Basic Setup — the smallest useful `Engine`
//!
//! The Actix counterpart of `axum_basic_setup.rs`. The engine construction is
//! byte-for-byte identical; only the adapter call differs
//! ([`ActixExt::actix_scope`] instead of `axum_router`), which is the whole
//! point of the framework-agnostic core.
//!
//! ```sh
//! cargo run -p authkestra --example actix_basic_setup --all-features
//! ```
//!
//! Set `PORT` to bind somewhere other than 3000.

use actix_files::Files;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra::Authkestra;
use authkestra_actix::{ActixExt, ActixState, AuthSession};
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::{AkWebAppEngine, SessionConfig, SessionStore};
use serde_json::json;
use std::sync::Arc;

/// `AkWebAppEngine` is the alias for a session-configured engine. Using the
/// alias (rather than spelling out the typestate generics) keeps the compile
/// error legible when a required builder call is missing.
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

    // 1. Pick a storage backend. `SessionStore` is a trait, so swapping
    //    `MemoryStore` for `RedisStore` is a one-line change.
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());

    // 2. Build the engine. The typestate builder only exposes session APIs
    //    once `session_store` has been supplied.
    let engine = Authkestra::builder()
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false, // plain HTTP for local development
            ..Default::default()
        })
        .build();

    let state = AppState { auth: engine };

    let port = port_from_env();
    tracing::info!(%port, "Actix basic setup listening on http://localhost:{port}");

    HttpServer::new(move || {
        let app_state = state.clone();
        let config_state = app_state.clone();
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            // `configure_authkestra` (from `ActixState`) registers the session
            // store and config as app data for the extractors to find.
            .configure(move |cfg| config_state.configure_authkestra(cfg))
            .service(get_user)
            .service(list_providers)
            // 3. Mount the engine's `/auth/*` scope.
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

/// Lists the OAuth providers registered on the engine so the bundled static
/// page can render one login button per provider. Empty for this example.
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
