use authkestra::axum::{
    AuthSession, Authkestra, AuthkestraAxumExt, AuthkestraState, SessionConfig,
};
use authkestra::flow::OAuth2Flow;
use authkestra::providers::github::GithubProvider;
use authkestra::session::SessionStore;
use axum::{
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;

#[tokio::main]
async fn main() {
    // In a real app, you'd use dotenvy::dotenv().ok();
    // For this demo, we'll use dummy values if env vars are missing
    let client_id =
        std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID").unwrap_or_else(|_| "dummy_id".to_string());
    let client_secret = std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET")
        .unwrap_or_else(|_| "dummy_secret".to_string());
    let redirect_uri = "http://localhost:3000/auth/github/callback".to_string();

    let provider = GithubProvider::new(client_id, client_secret, redirect_uri);

    let session_store: Arc<dyn SessionStore> =
        Arc::new(authkestra::session::MemoryStore::default());

    let authkestra = Authkestra::builder()
        .provider(OAuth2Flow::new(provider))
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false, // For local dev
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

    println!("Authkestra Demo running on http://localhost:3000");
    println!("This demo uses the 'authkestra' crate instead of individual sub-crates.");

    // We won't actually start the server in a non-interactive environment if we want to just verify compilation
    // but for a real example file, this is what it would look like.
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> impl IntoResponse {
    Html(
        r#"
        <h1>Authkestra Demo</h1>
        <p>This example demonstrates using the <code>authkestra</code> crate.</p>
        <ul>
            <li><a href="/auth/github?success_url=/protected">Login with GitHub</a></li>
        </ul>
    "#,
    )
}

async fn protected(AuthSession(session): AuthSession) -> impl IntoResponse {
    format!(
        "Hello, {}! Your ID is {}. Provider: {}. <br><a href=\"/auth/logout\">Logout</a>",
        session.identity.username.unwrap_or_default(),
        session.identity.external_id,
        session.identity.provider_id,
    )
}
