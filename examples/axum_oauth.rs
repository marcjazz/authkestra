use authkestra_axum::{AuthSession, Authkestra, AuthkestraAxumExt, AuthkestraState, SessionConfig};
use authkestra_flow::OAuth2Flow;
use authkestra_providers_discord::DiscordProvider;
use authkestra_providers_github::GithubProvider;
use authkestra_providers_google::GoogleProvider;
use authkestra_session::SessionStore;
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let mut builder = Authkestra::builder();

    // --- GitHub ---
    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID"),
        std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET"),
    ) {
        let redirect_uri = std::env::var("AUTHKESTRA_GITHUB_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:3000/auth/github/callback".to_string());
        let provider = GithubProvider::new(client_id, client_secret, redirect_uri);
        builder = builder.provider(OAuth2Flow::new(provider));
    }

    // --- Google ---
    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("AUTHKESTRA_GOOGLE_CLIENT_ID"),
        std::env::var("AUTHKESTRA_GOOGLE_CLIENT_SECRET"),
    ) {
        let redirect_uri = std::env::var("AUTHKESTRA_GOOGLE_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:3000/auth/google/callback".to_string());
        let provider = GoogleProvider::new(client_id, client_secret, redirect_uri);
        builder = builder.provider(OAuth2Flow::new(provider));
    }

    // --- Discord ---
    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("AUTHKESTRA_DISCORD_CLIENT_ID"),
        std::env::var("AUTHKESTRA_DISCORD_CLIENT_SECRET"),
    ) {
        let redirect_uri = std::env::var("AUTHKESTRA_DISCORD_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:3000/auth/discord/callback".to_string());
        let provider = DiscordProvider::new(client_id, client_secret, redirect_uri);
        builder = builder.provider(OAuth2Flow::new(provider));
    }

    // Session Store
    let session_store: Arc<dyn SessionStore> = if let Ok(redis_url) = std::env::var("REDIS_URL") {
        println!("Using RedisStore at {}", redis_url);
        Arc::new(authkestra_session::RedisStore::new(&redis_url, "authkestra".into()).unwrap())
    } else {
        println!("Using MemoryStore");
        Arc::new(authkestra_session::MemoryStore::default())
    };

    let authkestra = builder
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false,
            ..Default::default()
        })
        .build();

    let state = AuthkestraState {
        authkestra: authkestra.clone(),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .merge(authkestra.axum_router())
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn index(State(state): State<AuthkestraState>) -> impl IntoResponse {
    let mut html = String::from("<h1>Welcome to Authkestra Axum OAuth Example</h1><ul>");
    if state.authkestra.providers.contains_key("github") {
        html.push_str("<li><a href=\"/auth/github?scope=user:email&success_url=/protected\">Login with GitHub</a></li>");
    }
    if state.authkestra.providers.contains_key("google") {
        html.push_str("<li><a href=\"/auth/google?scope=openid%20email%20profile&success_url=/protected\">Login with Google</a></li>");
    }
    if state.authkestra.providers.contains_key("discord") {
        html.push_str("<li><a href=\"/auth/discord?scope=identify%20email&success_url=/protected\">Login with Discord</a></li>");
    }
    html.push_str("</ul>");
    Html(html)
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
