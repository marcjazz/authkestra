use authkestra_axum::{
    helpers::{handle_oauth_callback_jwt_erased, initiate_oauth_login, OAuthCallbackParams},
    AuthToken, Authkestra, SessionConfig,
};
use authkestra_flow::OAuth2Flow;
use authkestra_providers_github::GithubProvider;
use authkestra_token::TokenManager;
use axum::{
    extract::{FromRef, Query, State},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_cookies::{CookieManagerLayer, Cookies};

/// This example demonstrates a Single Page Application (SPA) authentication flow using JWTs.
///
/// The flow is as follows:
/// 1. The user visits the frontend (served at `/`).
/// 2. The user clicks "Login with GitHub", which redirects them to the backend `/auth/login`.
/// 3. The backend initiates the OAuth flow and redirects the user to GitHub.
/// 4. After authorization, GitHub redirects the user back to the frontend callback page (e.g., `/?code=...&state=...`).
///    IMPORTANT: In SPA use cases, the redirect URI should point to a frontend route, not a backend callback.
/// 5. The frontend extracts the `code` and `state` from the URL and performs a request (e.g., POST) to the backend API `/api/callback`.
/// 6. The backend uses `handle_oauth_callback_jwt` to exchange the code for a JWT and returns it to the frontend.
/// 7. The frontend stores the JWT (e.g., in localStorage) and uses it for subsequent API calls.

#[derive(Clone)]
struct AppState {
    authkestra: Authkestra,
}

impl FromRef<AppState> for Arc<TokenManager> {
    fn from_ref(state: &AppState) -> Self {
        state.authkestra.token_manager.clone()
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // 1. Setup GitHub Provider
    let client_id = std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID")
        .expect("AUTHKESTRA_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET")
        .expect("AUTHKESTRA_GITHUB_CLIENT_SECRET must be set");

    // IMPORTANT: For SPA flow, the redirect URI should point back to your frontend!
    // In this example, our frontend is served at http://localhost:3000/
    let redirect_uri = std::env::var("AUTHKESTRA_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/".to_string());

    // 2. Setup Authkestra and TokenManager
    let token_manager = Arc::new(TokenManager::new(
        b"a-very-secret-key-that-is-at-least-32-bytes-long!!",
        None,
    ));
    let authkestra = Authkestra::builder()
        .provider(OAuth2Flow::new(GithubProvider::new(
            client_id,
            client_secret,
            redirect_uri,
        )))
        .token_manager(token_manager)
        .build();

    let _session_config = SessionConfig {
        secure: false, // Set to true in production
        ..Default::default()
    };

    let state = AppState { authkestra };

    // 3. Build Axum Router
    let app = Router::new()
        .route("/", get(frontend))
        .route("/auth/login", get(login_handler))
        .route("/auth/logout", get(logout_handler))
        .route("/api/callback", get(callback_handler).post(callback_handler))
        .route("/api/protected", get(protected_resource))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 SPA Example running at http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn protected_resource(AuthToken(claims): AuthToken) -> impl IntoResponse {
    let identity = claims.identity.unwrap();
    format!(
        "Hello, {}! Your ID is {}. Your email is {:?}. Provider: {}. <br><a href=\"/auth/logout\">Logout</a>",
        identity.username.unwrap_or_default(),
        identity.external_id,
        identity.email,
        identity.provider_id,
    )
}

/// Serves a simple SPA frontend.
async fn frontend() -> impl IntoResponse {
    Html(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Authkestra SPA JWT Example</title>
    <style>
        body { font-family: sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f0f2f5; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        button { background: #24292e; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-size: 1rem; }
        pre { background: #eee; padding: 1rem; border-radius: 4px; text-align: left; max-width: 500px; overflow-x: auto; }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Authkestra SPA</h1>
        
        <div id="login-section">
            <p>Not logged in.</p>
            <button onclick="window.location.href='/auth/login'">Login with GitHub</button>
        </div>

        <div id="user-section" class="hidden">
            <p>Logged in!</p>
            <h3>JWT Token:</h3>
            <pre id="token-display"></pre>
            <button onclick="logout()">Logout</button>
        </div>

        <p id="status"></p>
    </div>

    <script>
        const statusEl = document.getElementById('status');
        const loginSection = document.getElementById('login-section');
        const userSection = document.getElementById('user-section');
        const tokenDisplay = document.getElementById('token-display');

        // 1. Check if we are returning from OAuth (URL has code and state)
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');

        if (code && state) {
            statusEl.innerText = 'Exchanging code for token...';
            
            // 2. Call backend to exchange code for JWT
            // In a real SPA, this should ideally be a POST request to avoid leaking code/state in logs
            fetch(`/api/callback?code=${code}&state=${state}`, { method: 'POST' })
                .then(res => {
                    if (!res.ok) throw new Error('Failed to exchange code');
                    return res.json();
                })
                .then(data => {
                    // 3. Store JWT and update UI
                    localStorage.setItem('jwt', data.access_token);
                    window.history.replaceState({}, document.title, "/"); // Clean URL
                    showLoggedIn(data.access_token);
                })
                .catch(err => {
                    statusEl.innerText = 'Error: ' + err.message;
                });
        } else {
            // 4. Check if we already have a token
            const token = localStorage.getItem('jwt');
            if (token) {
                showLoggedIn(token);
            }
        }

        function showLoggedIn(token) {
            loginSection.classList.add('hidden');
            userSection.classList.remove('hidden');
            tokenDisplay.innerText = token;
            statusEl.innerText = '';
        }

        function logout() {
            localStorage.removeItem('jwt');
            window.location.reload();
        }
    </script>
</body>
</html>
"#,
    )
}

/// Initiates the OAuth login flow.
/// This endpoint is called by the frontend to start the process.
async fn login_handler(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    let flow = &state.authkestra.providers["github"];

    // We request 'user:email' scope
    initiate_oauth_login(
        flow,
        &state.authkestra.session_config,
        &cookies,
        &["user:email"],
    )
}

async fn logout_handler() -> impl IntoResponse {
    Html("Logged out. <a href=\"/\">Go back</a>")
}

/// Backend API endpoint that exchanges the OAuth code for a JWT.
/// This is called by the frontend via AJAX/fetch.
async fn callback_handler(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<OAuthCallbackParams>,
) -> impl IntoResponse {
    let flow = &state.authkestra.providers["github"];

    // handle_oauth_callback_jwt:
    // 1. Validates the CSRF state from the cookie.
    // 2. Exchanges the code for an access token from GitHub.
    // 3. Fetches user info from GitHub.
    // 4. Issues a JWT signed by our TokenManager.
    // 5. Returns the JWT as JSON.
    let res = handle_oauth_callback_jwt_erased(
        flow,
        cookies,
        params,
        state.authkestra.token_manager.clone(),
        3600, // JWT expires in 1 hour
        &state.authkestra.session_config,
    )
    .await;

    match &res {
        Ok(_) => println!("DEBUG: callback_handler succeeded"),
        Err((status, msg)) => println!("DEBUG: callback_handler failed: {} - {}", status, msg),
    }

    res
}
