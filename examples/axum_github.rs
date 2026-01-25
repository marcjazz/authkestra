use authly_axum::{
    handle_oauth_callback_jwt, initiate_oauth_login, logout, AuthToken, OAuthCallbackParams,
    SessionConfig,
};
use authly_flow::OAuth2Flow;
use authly_providers_github::GithubProvider;
use authly_session::{SessionStore, SqlStore};
use authly_token::TokenManager;
use axum::{
    extract::{FromRef, Query, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use tower_cookies::{CookieManagerLayer, Cookies};

#[derive(Clone)]
struct AppState {
    github_flow: Arc<OAuth2Flow<GithubProvider>>,
    token_manager: Arc<TokenManager>,
    session_store: Arc<dyn SessionStore>,
}

impl FromRef<AppState> for Arc<TokenManager> {
    fn from_ref(state: &AppState) -> Self {
        state.token_manager.clone()
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let client_id =
        std::env::var("AUTHLY_GITHUB_CLIENT_ID").expect("AUTHLY_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHLY_GITHUB_CLIENT_SECRET")
        .expect("AUTHLY_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHLY_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/github/callback".to_string());
    let jwt_secret = std::env::var("AUTHLY_JWT_SECRET")
        .unwrap_or_else(|_| "super-secret-key-change-me-in-production".to_string());

    let provider = GithubProvider::new(client_id, client_secret, redirect_uri);
    let github_flow = Arc::new(OAuth2Flow::new(provider));
    let token_manager = Arc::new(TokenManager::new(
        jwt_secret.as_bytes(),
        Some("authly-rs".to_string()),
    ));
    // For this example, we'll use SQLite for session persistence.
    let db_url = "sqlite::memory:";
    let pool = SqlitePool::connect(db_url)
        .await
        .expect("Failed to connect to SQLite");

    // Initialize the sessions table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS authly_sessions (
            id VARCHAR(128) PRIMARY KEY,
            provider_id VARCHAR(255) NOT NULL,
            external_id VARCHAR(255) NOT NULL,
            email VARCHAR(255),
            name VARCHAR(255),
            claims TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create sessions table");

    let session_store: Arc<dyn SessionStore> = Arc::new(SqlStore::new(pool));

    let state = AppState {
        github_flow,
        token_manager,
        session_store,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/github", get(github_login))
        .route("/auth/github/callback", get(github_callback))
        .route("/auth/logout", get(github_logout))
        .route("/protected", get(protected))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    println!("Starting server on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> impl IntoResponse {
    "Welcome! Go to /auth/github to login (Stateless JWT mode)."
}

async fn github_login(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    initiate_oauth_login(&state.github_flow, &cookies, &["user:email"])
}

async fn github_callback(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<OAuthCallbackParams>,
) -> impl IntoResponse {
    handle_oauth_callback_jwt(
        &state.github_flow,
        cookies,
        params,
        state.token_manager.clone(),
        3600,
    )
    .await
}

async fn github_logout(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    logout(cookies, state.session_store, SessionConfig::default(), "/").await
}

async fn protected(AuthToken(claims): AuthToken) -> impl IntoResponse {
    let name = claims
        .identity
        .as_ref()
        .and_then(|i| i.username.clone())
        .unwrap_or_else(|| "Unknown".to_string());
    format!(
        "Hello, {}! Your ID is {}. You are authenticated via the new AuthToken extractor.",
        name, claims.sub
    )
}
