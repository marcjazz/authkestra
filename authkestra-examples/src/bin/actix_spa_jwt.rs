//! # Actix SPA JWT Example
//!
//! This example demonstrates how to set up AuthEngine with Actix Web for a Single Page Application (SPA)
//! using JWTs for stateless authentication.

use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, HttpRequest};
use authkestra::flow::{AuthEngine, OAuth2Flow, StatelessAuthkestra};
use authkestra_actix::{
    helpers::{handle_oauth_callback_jwt_erased, initiate_oauth_login_erased, OAuthCallbackParams},
    AuthToken,
};
use authkestra_providers_github::GithubProvider;

struct AppState {
    auth_engine: StatelessAuthkestra,
}

#[get("/")]
async fn index() -> impl Responder {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AuthEngine Actix SPA JWT Example</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; }
        .btn { display: inline-block; padding: 0.5rem 1rem; background: #24292e; color: white; text-decoration: none; border-radius: 4px; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="card">
        <h1>AuthEngine Actix SPA</h1>
        <p>Login with GitHub to receive a JWT.</p>
        <a href="/auth/github" class="btn">Login with GitHub</a>
        <div id="result" style="margin-top: 1rem; text-align: left; white-space: pre-wrap; word-break: break-all;"></div>
    </div>

    <script>
        // Check for callback
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
    HttpResponse::Ok().content_type("text/html").body(html)
}

#[get("/auth/github")]
async fn login(data: web::Data<AppState>) -> impl Responder {
    let flow = &data.auth_engine.providers["github"];
    initiate_oauth_login_erased(flow.as_ref(), &["user:email"])
}

#[get("/auth/github/callback")]
async fn callback(
    req: HttpRequest,
    data: web::Data<AppState>,
    params: web::Query<OAuthCallbackParams>,
) -> impl Responder {
    let flow = &data.auth_engine.providers["github"];
    handle_oauth_callback_jwt_erased(
        flow.as_ref(),
        &req,
        params.into_inner(),
        data.auth_engine.token_manager(),
        3600,
    )
    .await
}

#[get("/protected")]
async fn protected(token: AuthToken) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Hello, {}! Your ID is {}. Authenticated via JWT.",
        token.0.sub, token.0.sub
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

    let provider = GithubProvider::new(client_id, client_secret, redirect_uri);

    // Setup AuthEngine and TokenManager
    let auth_engine = AuthEngine::builder()
        .jwt_secret(b"a-very-secret-key-that-is-at-least-32-bytes-long!!")
        .provider(OAuth2Flow::new(provider))
        .build();

    let app_state = web::Data::new(AppState {
        auth_engine: auth_engine.clone(),
    });

    println!("🚀 Actix SPA JWT Example running at http://localhost:3000");

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(web::Data::new(auth_engine.clone()))
            .app_data(web::Data::new(auth_engine.token_manager()))
            .service(index)
            .service(login)
            .service(callback)
            .service(protected)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}
