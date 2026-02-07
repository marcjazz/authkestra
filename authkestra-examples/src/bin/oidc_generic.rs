use authkestra_axum::{AuthSession, Authkestra, AuthkestraAxumExt, AuthkestraState};
use authkestra_core::SessionStore;
use authkestra_flow::OAuth2Flow;
use authkestra_oidc::OidcProvider;
use axum::{response::IntoResponse, routing::get, Router};
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;

#[derive(Clone)]
struct AppState {
    authkestra_state: AuthkestraState,
}

impl axum::extract::FromRef<AppState> for AuthkestraState {
    fn from_ref(state: &AppState) -> Self {
        state.authkestra_state.clone()
    }
}

impl axum::extract::FromRef<AppState> for Authkestra {
    fn from_ref(state: &AppState) -> Self {
        state.authkestra_state.authkestra.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<dyn SessionStore> {
    fn from_ref(state: &AppState) -> Self {
        state.authkestra_state.authkestra.session_store.clone()
    }
}

impl axum::extract::FromRef<AppState> for authkestra_core::SessionConfig {
    fn from_ref(state: &AppState) -> Self {
        state.authkestra_state.authkestra.session_config.clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let issuer = std::env::var("OIDC_ISSUER").expect("OIDC_ISSUER must be set");
    let client_id = std::env::var("OIDC_CLIENT_ID").expect("OIDC_CLIENT_ID must be set");
    let client_secret =
        std::env::var("OIDC_CLIENT_SECRET").expect("OIDC_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("OIDC_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/oidc/callback".to_string());

    println!("Initializing OIDC provider with issuer: {}", issuer);

    // Demonstrate initialization/discovery
    let provider = OidcProvider::discover(client_id, client_secret, redirect_uri, &issuer).await?;

    // Use Redis if REDIS_URL is set, otherwise fallback to MemoryStore
    let session_store: Arc<dyn SessionStore> = if let Ok(redis_url) = std::env::var("REDIS_URL") {
        println!("Using RedisStore at {}", redis_url);
        Arc::new(authkestra_session::RedisStore::new(&redis_url, "authkestra".into()).unwrap())
    } else {
        println!("Using MemoryStore");
        Arc::new(authkestra_core::MemoryStore::default())
    };

    let authkestra = Authkestra::builder()
        .provider(OAuth2Flow::new(provider))
        .session_store(session_store)
        .build();

    let state = AppState {
        authkestra_state: AuthkestraState { authkestra },
    };

    let app = Router::new()
        .route("/", get(index))
        .merge(state.authkestra_state.authkestra.axum_router())
        .route("/protected", get(protected))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

async fn index() -> impl IntoResponse {
    "Welcome! Go to /auth/oidc to login."
}

async fn protected(AuthSession(session): AuthSession) -> impl IntoResponse {
    println!("Identity verified: {:?}", session.identity);

    format!(
        "Hello, {}! Your ID is {}. Your email is {:?}. Attributes: {:?}",
        session.identity.username.unwrap_or_default(),
        session.identity.external_id,
        session.identity.email,
        session.identity.attributes
    )
}
