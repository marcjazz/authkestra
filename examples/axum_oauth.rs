use authly_axum::{AuthSession, Authly, AuthlyAxumExt, AuthlyState, SessionConfig};
use authly_flow::OAuth2Flow;
use authly_providers_discord::DiscordProvider;
use authly_providers_github::GithubProvider;
use authly_providers_google::GoogleProvider;
use authly_session::SessionStore;
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

    let mut builder = Authly::builder();

    // --- GitHub ---
    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("AUTHLY_GITHUB_CLIENT_ID"),
        std::env::var("AUTHLY_GITHUB_CLIENT_SECRET"),
    ) {
        let redirect_uri = std::env::var("AUTHLY_GITHUB_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:3000/auth/github/callback".to_string());
        let provider = GithubProvider::new(client_id, client_secret, redirect_uri);
        builder = builder.provider(OAuth2Flow::new(provider));
    }

    // --- Google ---
    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("AUTHLY_GOOGLE_CLIENT_ID"),
        std::env::var("AUTHLY_GOOGLE_CLIENT_SECRET"),
    ) {
        let redirect_uri = std::env::var("AUTHLY_GOOGLE_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:3000/auth/google/callback".to_string());
        let provider = GoogleProvider::new(client_id, client_secret, redirect_uri);
        builder = builder.provider(OAuth2Flow::new(provider));
    }

    // --- Discord ---
    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("AUTHLY_DISCORD_CLIENT_ID"),
        std::env::var("AUTHLY_DISCORD_CLIENT_SECRET"),
    ) {
        let redirect_uri = std::env::var("AUTHLY_DISCORD_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:3000/auth/discord/callback".to_string());
        let provider = DiscordProvider::new(client_id, client_secret, redirect_uri);
        builder = builder.provider(OAuth2Flow::new(provider));
    }

    // Session Store
    let session_store: Arc<dyn SessionStore> = if let Ok(redis_url) = std::env::var("REDIS_URL") {
        println!("Using RedisStore at {}", redis_url);
        Arc::new(authly_session::RedisStore::new(&redis_url, "authly".into()).unwrap())
    } else {
        println!("Using MemoryStore");
        Arc::new(authly_session::MemoryStore::default())
    };

    let authly = builder
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false,
            ..Default::default()
        })
        .build();

    let state = AuthlyState {
        authly: authly.clone(),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .merge(authly.axum_router())
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn index(State(state): State<AuthlyState>) -> impl IntoResponse {
    let mut html = String::from("<h1>Welcome to Authly Axum OAuth Example</h1><ul>");
    if state.authly.providers.contains_key("github") {
        html.push_str("<li><a href=\"/auth/github?scope=user:email&success_url=/protected\">Login with GitHub</a></li>");
    }
    if state.authly.providers.contains_key("google") {
        html.push_str("<li><a href=\"/auth/google?scope=openid%20email%20profile&success_url=/protected\">Login with Google</a></li>");
    }
    if state.authly.providers.contains_key("discord") {
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
