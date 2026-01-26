use authly_axum::{
    handle_oauth_callback, initiate_oauth_login, logout, AuthSession, OAuthCallbackParams,
    SessionConfig,
};
use authly_flow::OAuth2Flow;
use authly_providers_discord::DiscordProvider;
use authly_providers_github::GithubProvider;
use authly_providers_google::GoogleProvider;
use authly_session::SessionStore;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_cookies::{CookieManagerLayer, Cookies};

#[derive(Clone)]
struct AppState {
    github_flow: Option<Arc<OAuth2Flow<GithubProvider>>>,
    google_flow: Option<Arc<OAuth2Flow<GoogleProvider>>>,
    discord_flow: Option<Arc<OAuth2Flow<DiscordProvider>>>,
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

    // --- GitHub ---
    let github_flow = if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("AUTHLY_GITHUB_CLIENT_ID"),
        std::env::var("AUTHLY_GITHUB_CLIENT_SECRET"),
    ) {
        let redirect_uri = std::env::var("AUTHLY_GITHUB_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:3000/auth/github/callback".to_string());
        let provider = GithubProvider::new(client_id, client_secret, redirect_uri);
        Some(Arc::new(OAuth2Flow::new(provider)))
    } else {
        None
    };

    // --- Google ---
    let google_flow = if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("AUTHLY_GOOGLE_CLIENT_ID"),
        std::env::var("AUTHLY_GOOGLE_CLIENT_SECRET"),
    ) {
        let redirect_uri = std::env::var("AUTHLY_GOOGLE_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:3000/auth/google/callback".to_string());
        let provider = GoogleProvider::new(client_id, client_secret, redirect_uri);
        Some(Arc::new(OAuth2Flow::new(provider)))
    } else {
        None
    };

    // --- Discord ---
    let discord_flow = if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("AUTHLY_DISCORD_CLIENT_ID"),
        std::env::var("AUTHLY_DISCORD_CLIENT_SECRET"),
    ) {
        let redirect_uri = std::env::var("AUTHLY_DISCORD_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:3000/auth/discord/callback".to_string());
        let provider = DiscordProvider::new(client_id, client_secret, redirect_uri);
        Some(Arc::new(OAuth2Flow::new(provider)))
    } else {
        None
    };

    // Session Store
    let session_store: Arc<dyn SessionStore> = if let Ok(redis_url) = std::env::var("REDIS_URL") {
        println!("Using RedisStore at {}", redis_url);
        Arc::new(authly_session::RedisStore::new(&redis_url, "authly".into()).unwrap())
    } else {
        println!("Using MemoryStore");
        Arc::new(authly_session::MemoryStore::default())
    };

    let state = AppState {
        github_flow,
        google_flow,
        discord_flow,
        session_store,
        session_config: SessionConfig::default(),
    };

    let mut app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .route("/auth/logout", get(auth_logout));

    if state.github_flow.is_some() {
        app = app
            .route("/auth/github", get(github_login))
            .route("/auth/github/callback", get(github_callback));
    }
    if state.google_flow.is_some() {
        app = app
            .route("/auth/google", get(google_login))
            .route("/auth/google/callback", get(google_callback));
    }
    if state.discord_flow.is_some() {
        app = app
            .route("/auth/discord", get(discord_login))
            .route("/auth/discord/callback", get(discord_callback));
    }

    let app = app.layer(CookieManagerLayer::new()).with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let mut html = String::from("<h1>Welcome to Authly Axum OAuth Example</h1><ul>");
    if state.github_flow.is_some() {
        html.push_str("<li><a href=\"/auth/github\">Login with GitHub</a></li>");
    }
    if state.google_flow.is_some() {
        html.push_str("<li><a href=\"/auth/google\">Login with Google</a></li>");
    }
    if state.discord_flow.is_some() {
        html.push_str("<li><a href=\"/auth/discord\">Login with Discord</a></li>");
    }
    html.push_str("</ul>");
    Html(html)
}

// --- GitHub Handlers ---
async fn github_login(State(state): State<AppState>, cookies: Cookies) -> Response {
    if let Some(flow) = &state.github_flow {
        initiate_oauth_login(flow, &cookies, &["user:email"]).into_response()
    } else {
        (axum::http::StatusCode::NOT_IMPLEMENTED, "GitHub not configured").into_response()
    }
}

async fn github_callback(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<OAuthCallbackParams>,
) -> Response {
    if let Some(flow) = &state.github_flow {
        handle_oauth_callback(
            flow,
            cookies,
            params,
            state.session_store.clone(),
            state.session_config.clone(),
            "/protected",
        )
        .await
        .into_response()
    } else {
        (axum::http::StatusCode::NOT_IMPLEMENTED, "GitHub not configured").into_response()
    }
}

// --- Google Handlers ---
async fn google_login(State(state): State<AppState>, cookies: Cookies) -> Response {
    if let Some(flow) = &state.google_flow {
        initiate_oauth_login(flow, &cookies, &["openid", "email", "profile"]).into_response()
    } else {
        (axum::http::StatusCode::NOT_IMPLEMENTED, "Google not configured").into_response()
    }
}

async fn google_callback(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<OAuthCallbackParams>,
) -> Response {
    if let Some(flow) = &state.google_flow {
        handle_oauth_callback(
            flow,
            cookies,
            params,
            state.session_store.clone(),
            state.session_config.clone(),
            "/protected",
        )
        .await
        .into_response()
    } else {
        (axum::http::StatusCode::NOT_IMPLEMENTED, "Google not configured").into_response()
    }
}

// --- Discord Handlers ---
async fn discord_login(State(state): State<AppState>, cookies: Cookies) -> Response {
    if let Some(flow) = &state.discord_flow {
        initiate_oauth_login(flow, &cookies, &["identify", "email"]).into_response()
    } else {
        (axum::http::StatusCode::NOT_IMPLEMENTED, "Discord not configured").into_response()
    }
}

async fn discord_callback(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<OAuthCallbackParams>,
) -> Response {
    if let Some(flow) = &state.discord_flow {
        handle_oauth_callback(
            flow,
            cookies,
            params,
            state.session_store.clone(),
            state.session_config.clone(),
            "/protected",
        )
        .await
        .into_response()
    } else {
        (axum::http::StatusCode::NOT_IMPLEMENTED, "Discord not configured").into_response()
    }
}

async fn auth_logout(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    logout(cookies, state.session_store, state.session_config, "/").await
}

async fn protected(AuthSession(session): AuthSession) -> impl IntoResponse {
    format!(
        "Hello, {}! Your ID is {}. Your email is {:?}. Provider: {}. <br><a href=\"/auth/logout\">Logout</a>",
        session.identity.username.unwrap_or_default(),
        session.identity.external_id,
        session.identity.email,
        session.identity.provider_id,
    )
}
