use authkestra::flow::{Authkestra, OAuth2Flow};
use authkestra_axum::{AuthSession, AuthkestraAxumExt, AuthkestraState};
use authkestra_oidc::OidcProvider;
use authkestra_session::{MemoryStore, RedisStore};
use axum::{response::IntoResponse, routing::get, Router};
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let issuer = std::env::var("OIDC_ISSUER").expect("OIDC_ISSUER must be set");
    let client_id = std::env::var("OIDC_CLIENT_ID").expect("OIDC_CLIENT_ID must be set");
    let client_secret =
        std::env::var("OIDC_CLIENT_SECRET").expect("OIDC_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("OIDC_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/oidc/callback".to_string());

    println!("Initializing OIDC provider with issuer: {issuer}");

    // Demonstrate initialization/discovery
    let provider = OidcProvider::discover(client_id, client_secret, redirect_uri, &issuer).await?;

    let mut builder = Authkestra::builder().session_store(Arc::new(MemoryStore::default()));

    // Use Redis if REDIS_URL is set
    if let Ok(redis_url) = std::env::var("REDIS_URL") {
        println!("Using RedisStore at {redis_url}");
        let redis_store = Arc::new(RedisStore::new(&redis_url, "authkestra".into()).unwrap());
        builder = builder.session_store(redis_store);
    } else {
        println!("Using MemoryStore");
    }

    let authkestra = builder.provider(OAuth2Flow::new(provider)).build();

    let state = AuthkestraState::from(authkestra);

    let app = Router::new()
        .route("/", get(index))
        .merge(state.authkestra.axum_router())
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
