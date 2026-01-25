use authly_axum::{
    handle_oauth_callback, initiate_oauth_login, AuthSession, OAuthCallbackParams, SessionConfig,
};
use authly_flow::OAuth2Flow;
use authly_oidc::OidcProvider;
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
    oidc_flow: Arc<OAuth2Flow<OidcProvider>>,
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let issuer = std::env::var("OIDC_ISSUER").expect("OIDC_ISSUER must be set");
    let client_id = std::env::var("OIDC_CLIENT_ID").expect("OIDC_CLIENT_ID must be set");
    let client_secret = std::env::var("OIDC_CLIENT_SECRET").expect("OIDC_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("OIDC_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/oidc/callback".to_string());

    println!("Initializing OIDC provider with issuer: {}", issuer);
    
    // Demonstrate initialization/discovery
    let provider = OidcProvider::discover(client_id, client_secret, redirect_uri, &issuer).await?;
    let oidc_flow = Arc::new(OAuth2Flow::new(provider));

    // Use Redis if REDIS_URL is set, otherwise fallback to MemoryStore
    let session_store: Arc<dyn SessionStore> = if let Ok(redis_url) = std::env::var("REDIS_URL") {
        println!("Using RedisStore at {}", redis_url);
        Arc::new(authly_session::RedisStore::new(&redis_url, "authly".into()).unwrap())
    } else {
        println!("Using MemoryStore");
        Arc::new(authly_session::MemoryStore::default())
    };

    let state = AppState {
        oidc_flow,
        session_store,
        session_config: SessionConfig::default(),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/oidc", get(oidc_login))
        .route("/auth/oidc/callback", get(oidc_callback))
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

async fn oidc_login(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    // Note: Some providers have specific scope requirements.
    // For example, Discord does not support the standard 'profile' scope and requires 'identify' instead.
    // If using Discord OIDC, you should use: &["openid", "email", "identify"]
    let scopes = std::env::var("OIDC_SCOPES")
        .unwrap_or_else(|_| "openid email profile".to_string());
    let scope_list: Vec<&str> = scopes.split_whitespace().collect();
    
    initiate_oauth_login(&state.oidc_flow, &cookies, &scope_list)
}

async fn oidc_callback(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<OAuthCallbackParams>,
) -> impl IntoResponse {
    handle_oauth_callback(
        &state.oidc_flow,
        cookies,
        params,
        state.session_store.clone(),
        state.session_config.clone(),
        "/protected",
    )
    .await
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
