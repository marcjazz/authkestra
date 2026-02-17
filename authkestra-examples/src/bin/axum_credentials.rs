use async_trait::async_trait;
use authkestra::flow::{Authkestra, CredentialsFlow};
use authkestra_axum::AuthSession;
use authkestra_core::{error::AuthError, state::Identity, CredentialsProvider, UserMapper};
use authkestra_flow::{Configured, Missing};
use authkestra_session::{MemoryStore, SessionStore};
use axum::{
    extract::{Form, State},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tower_cookies::{CookieManagerLayer, Cookies};

// 1. Define Credentials
#[derive(Deserialize)]
pub struct LoginCredentials {
    pub username: String,
    pub password: String,
}

// 2. Implement a Mock CredentialsProvider
pub struct MyCredentialsProvider;

#[async_trait]
impl CredentialsProvider for MyCredentialsProvider {
    type Credentials = LoginCredentials;

    async fn authenticate(&self, creds: Self::Credentials) -> Result<Identity, AuthError> {
        // In a real app, you would verify password hash here
        if creds.username == "admin" && creds.password == "password" {
            Ok(Identity {
                provider_id: "credentials".to_string(),
                external_id: "admin-id-123".to_string(),
                email: Some("admin@example.com".to_string()),
                username: Some("admin".to_string()),
                attributes: HashMap::new(),
            })
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }
}

// 3. Define Local User and SQLx-like Mapper
#[derive(Debug, Clone, serde::Serialize)]
pub struct LocalUser {
    pub id: i32,
    pub username: String,
    pub role: String,
}

pub struct SqlxUserMapper {
    // pool: sqlx::PgPool
}

#[async_trait]
impl UserMapper for SqlxUserMapper {
    type LocalUser = LocalUser;

    async fn map_user(&self, identity: &Identity) -> Result<Self::LocalUser, AuthError> {
        // Mocking SQLx query
        // let user = sqlx::query_as!(LocalUser, "SELECT id, username, role FROM users WHERE external_id = $1", identity.external_id)
        //     .fetch_one(&self.pool).await?;

        println!("Mapping identity {} to local user", identity.external_id);

        Ok(LocalUser {
            id: 1,
            username: identity.username.clone().unwrap_or_default(),
            role: "admin".to_string(),
        })
    }
}

// 4. App State
use authkestra_axum::AuthkestraFromRef;

#[derive(Clone, AuthkestraFromRef)]
struct AppState<S = Missing, T = Missing> {
    auth_flow: Arc<CredentialsFlow<MyCredentialsProvider, SqlxUserMapper>>,
    #[authkestra]
    authkestra: Authkestra<S, T>,
}

#[tokio::main]
async fn main() {
    let provider = MyCredentialsProvider;
    let mapper = SqlxUserMapper {};
    let auth_flow = Arc::new(CredentialsFlow::with_mapper(provider, mapper));

    let session_store = Arc::new(MemoryStore::default());

    let authkestra = Authkestra::builder().session_store(session_store).build();

    let state = AppState {
        auth_flow,
        authkestra,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/login", post(login))
        .route("/protected", get(protected))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    println!("Starting server on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> impl IntoResponse {
    axum::response::Html(
        r#"
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username" />
            <input type="password" name="password" placeholder="Password" />
            <button type="submit">Login</button>
        </form>
    "#,
    )
}

async fn login(
    State(state): State<AppState<Configured<Arc<dyn SessionStore>>>>,
    cookies: Cookies,
    Form(creds): Form<LoginCredentials>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    println!("Login attempt for user: {}", creds.username);
    let (identity, local_user) = state
        .auth_flow
        .authenticate(creds)
        .await
        .map_err(|e| (axum::http::StatusCode::UNAUTHORIZED, e.to_string()))?;

    // local_user is Some(LocalUser { ... }) because we used with_mapper
    if let Some(user) = &local_user {
        println!("Logged in as local user: {user:?}");
    }

    println!("Creating session for identity: {:?}", identity.external_id);
    let session = state
        .authkestra
        .create_session(identity)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    println!("Session created: {}", session.id);

    let cookie =
        authkestra_axum::helpers::create_axum_cookie(&state.authkestra.session_config, session.id);
    cookies.add(cookie);

    Ok(Redirect::to("/protected"))
}

async fn protected(AuthSession(session): AuthSession) -> impl IntoResponse {
    println!("Accessing protected route with session: {}", session.id);
    format!(
        "Hello, {}! Your ID is {}. Session ID: {}",
        session.identity.username.unwrap_or_default(),
        session.identity.external_id,
        session.id
    )
}
