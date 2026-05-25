use authkestra::flow::{AuthEngine, OAuth2Flow};
use authkestra_axum::{AuthEngineAxumExt, AuthEngineState, AuthSession};
use authkestra_oidc::OidcProvider;
use authkestra_session_memory::MemoryStore;
use axum::{response::Html, routing::get, Router};
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;

/// AuthEngine state with support for session only.
type AppState =
    AuthEngineState<authkestra_engine::Configured<Arc<dyn authkestra_session::SessionStore>>>;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let client_id = std::env::var("OIDC_CLIENT_ID").expect("OIDC_CLIENT_ID env var must be set");
    let client_secret =
        std::env::var("OIDC_CLIENT_SECRET").expect("OIDC_CLIENT_SECRET env var must be set");
    let issuer_url = std::env::var("OIDC_ISSUER_URL").expect("OIDC_ISSUER_URL env var must be set");
    let redirect_uri = std::env::var("OIDC_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/oidc/callback".to_string());

    let provider = OidcProvider::discover(client_id, client_secret, redirect_uri, &issuer_url)
        .await
        .expect("Failed to initialize OIDC provider");

    let mut builder = AuthEngine::builder().session_store(Arc::new(MemoryStore::default()));

    builder = builder.provider(OAuth2Flow::new(provider));

    let auth_engine = builder.build();

    let state = AppState::from(auth_engine.clone());

    let app = Router::<AppState>::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .merge(auth_engine.axum_router())
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 OIDC Example running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(
        r#"<h1>OIDC Example</h1><a href="/auth/oidc?scope=openid%20profile%20email&success_url=/protected">Login with OIDC</a>"#,
    )
}

async fn protected(AuthSession(session): AuthSession) -> String {
    format!(
        "Hello, {}! Your ID is {}. Authenticated via OIDC.",
        session.identity.username.unwrap_or_default(),
        session.identity.external_id
    )
}
