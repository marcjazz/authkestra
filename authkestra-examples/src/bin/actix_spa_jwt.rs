/// This example demonstrates a Single Page Application (SPA) authentication flow using JWTs with Actix.
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
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra_actix::{
    handle_oauth_callback_jwt_erased, initiate_oauth_login_erased, AuthToken, OAuthCallbackParams,
};
use authkestra_flow::{Authkestra, OAuth2Flow};
use authkestra_providers_github::GithubProvider;
use authkestra_token::TokenManager;
use std::sync::Arc;

struct AppState {
    authkestra: Authkestra,
}

#[get("/")]
async fn frontend() -> impl Responder {
    HttpResponse::Ok().body(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Authkestra Actix SPA JWT Example</title>
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
        <h1>Authkestra Actix SPA</h1>
        
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

#[get("/auth/login")]
async fn login_handler(data: web::Data<AppState>) -> impl Responder {
    let flow = &data.authkestra.providers["github"];
    initiate_oauth_login_erased(flow, &data.authkestra.session_config, &["user:email"])
}

#[actix_web::route("/api/callback", method = "GET", method = "POST")]
async fn callback_handler(
    data: web::Data<AppState>,
    params: web::Query<OAuthCallbackParams>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    let flow = &data.authkestra.providers["github"];

    let res = handle_oauth_callback_jwt_erased(
        flow,
        &req,
        params.into_inner(),
        data.authkestra.token_manager.clone(),
        3600,
        &data.authkestra.session_config,
    )
    .await;

    match res {
        Ok(token_resp) => token_resp,
        Err(err) => HttpResponse::from_error(err),
    }
}

#[get("/api/protected")]
async fn protected_resource(AuthToken(claims): AuthToken) -> impl Responder {
    let identity = claims.identity.unwrap();
    HttpResponse::Ok().body(format!(
        "Hello, {}! Your ID is {}. Your email is {:?}. Provider: {}.",
        identity.username.unwrap_or_default(),
        identity.external_id,
        identity.email,
        identity.provider_id,
    ))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    let client_id = std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID")
        .expect("AUTHKESTRA_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET")
        .expect("AUTHKESTRA_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHKESTRA_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/".to_string());

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
        .token_manager(token_manager.clone())
        .build();

    let app_state = web::Data::new(AppState {
        authkestra: authkestra.clone(),
    });

    println!("🚀 Actix SPA Example running at http://localhost:3000");

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(web::Data::new(token_manager.clone()))
            .app_data(web::Data::new(authkestra.session_config.clone()))
            .service(frontend)
            .service(login_handler)
            .service(callback_handler)
            .service(protected_resource)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}
