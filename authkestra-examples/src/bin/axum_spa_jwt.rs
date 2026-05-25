//! # Axum SPA JWT Example
//!
//! This example demonstrates how to set up AuthEngine with Axum for a Single Page Application (SPA)
//! using JWTs for stateless authentication.

use authkestra::flow::{AuthEngine, OAuth2Flow};
use authkestra_axum::{
    helpers::{handle_oauth_callback_jwt_erased, initiate_oauth_login, OAuthCallbackParams},
    AuthToken, AuthkestraState,
};
use authkestra_engine::{Missing, Configured};
use authkestra_engine::TokenManager;
use authkestra_providers_github::GithubProvider;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;

/// AuthEngine state with support for token manager only.
type AppState = AuthkestraState<Missing, Configured<Arc<TokenManager>>>;

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenvy::dotenv().ok();

    let client_id = std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID")
        .expect("AUTHKESTRA_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET")
        .expect("AUTHKESTRA_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHKESTRA_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/".to_string());

    // Setup AuthEngine and TokenManager
    let auth_engine = AuthEngine::builder()
        .jwt_secret(b"a-very-secret-key-that-is-at-least-32-bytes-long!!")
        .provider(OAuth2Flow::new(GithubProvider::new(
            client_id,
            client_secret,
            redirect_uri,
        )))
        .build();

    let state = AppState { authkestra: auth_engine.clone() };

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/github", get(login_handler))
        .route("/auth/github/callback", get(callback_handler))
        .route("/protected", get(protected))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Axum SPA JWT Example running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> impl IntoResponse {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AuthEngine SPA JWT Example</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; }
        .btn { display: inline-block; padding: 0.5rem 1rem; background: #24292e; color: white; text-decoration: none; border-radius: 4px; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="card">
        <h1>AuthEngine SPA</h1>
        <p>Login with GitHub to receive a JWT.</p>
        <a href="/auth/github" class="btn">Login with GitHub</a>
        <div id="result" style="margin-top: 1rem; text-align: left; white-space: pre-wrap; word-break: break-all;"></div>
    </div>

    <script>
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');

        if (code && state) {
            document.getElementById('result').innerText = "Exchanging code...";
            fetch(`/auth/github/callback?code=${code}&state=${state}`)
                .then(res => res.json())
                .then(data => {
                    document.getElementById('result').innerText = "JWT received:\n\n" + JSON.stringify(data, null, 2);
                    window.history.replaceState({}, document.title, "/");
                })
                .catch(err => {
                    document.getElementById('result').innerText = "Error: " + err;
                });
        }
    </script>
</body>
</html>
"#;
    Html(html)
}

async fn login_handler(
    State(state): State<AppState>,
    cookies: tower_cookies::Cookies,
) -> impl IntoResponse {
    let flow = &state.authkestra.providers["github"];
    initiate_oauth_login(flow.as_ref(), &cookies, &["user:email"])
}

async fn callback_handler(
    State(state): State<AppState>,
    cookies: tower_cookies::Cookies,
    Query(params): Query<OAuthCallbackParams>,
) -> impl IntoResponse {
    let flow = &state.authkestra.providers["github"];
    handle_oauth_callback_jwt_erased(
        flow.as_ref(),
        cookies,
        params,
        state.authkestra.token_manager(),
        3600,
    )
    .await
}

async fn protected(AuthToken(claims): AuthToken) -> impl IntoResponse {
    format!(
        "Hello, {}! Your ID is {}. Authenticated via JWT.",
        claims.sub, claims.sub
    )
}
