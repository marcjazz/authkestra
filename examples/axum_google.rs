use authly_axum::{
    handle_oauth_callback, initiate_oauth_login, AuthSession, OAuthCallbackParams, SessionConfig,
};
use authly_flow::OAuth2Flow;
use authly_providers_google::GoogleProvider;
use authly_session::SessionStore;
use axum::{
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_cookies::{CookieManagerLayer, Cookies};

#[derive(Clone)]
struct AppState {
    google_flow: Arc<OAuth2Flow<GoogleProvider>>,
    session_store: Arc<dyn SessionStore>,
    session_config: SessionConfig,
}

// Implement FromRef for Axum
impl axum::extract::FromRef<AppState> for Arc<dyn SessionStore> {
    fn from_ref(state: &AppState) -> Self {
        state.session_store.clone()
    }
}

impl axum::extract::FromRef<AppState> for SessionConfig {
    fn from_ref(state: &AppState) -> Self {
        state.session_config.clone()
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let client_id =
        std::env::var("AUTHLY_GOOGLE_CLIENT_ID").expect("AUTHLY_GOOGLE_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHLY_GOOGLE_CLIENT_SECRET")
        .expect("AUTHLY_GOOGLE_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHLY_GOOGLE_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/google/callback".to_string());

    let provider = GoogleProvider::new(client_id, client_secret, redirect_uri);
    let google_flow = Arc::new(OAuth2Flow::new(provider));

    // Use Redis if REDIS_URL is set, otherwise fallback to MemoryStore
    let session_store: Arc<dyn SessionStore> = if let Ok(redis_url) = std::env::var("REDIS_URL") {
        println!("Using RedisStore at {}", redis_url);
        Arc::new(authly_session::RedisStore::new(&redis_url, "authly".into()).unwrap())
    } else {
        println!("Using MemoryStore");
        Arc::new(authly_session::MemoryStore::default())
    };

    let state = AppState {
        google_flow,
        session_store,
        session_config: SessionConfig::default(),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/google", get(google_login))
        .route("/auth/google/callback", get(google_callback))
        .route("/protected", get(protected))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> impl IntoResponse {
    "Welcome! Go to /auth/google to login."
}

async fn google_login(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    initiate_oauth_login(&state.google_flow, &cookies, &["openid", "email", "profile"])
}

async fn google_callback(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<OAuthCallbackParams>,
) -> impl IntoResponse {
    handle_oauth_callback(
        &state.google_flow,
        cookies,
        params,
        state.session_store.clone(),
        state.session_config.clone(),
        "/protected",
    )
    .await
}

async fn protected(AuthSession(session): AuthSession) -> impl IntoResponse {
    format!(
        "Hello, {}! Your ID is {}. Your email is {:?}. Attributes: {:?}",
        session.identity.username.unwrap_or_default(),
        session.identity.external_id,
        session.identity.email,
        session.identity.attributes
    )
}
