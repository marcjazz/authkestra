use authly_axum::AuthSession;
use authly_flow::OAuth2Flow;
use authly_providers_google::GoogleProvider;
use authly_session::{Session, SessionStore};
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    routing::get,
    Router,
};
use std::collections::HashMap;
use std::sync::Arc;
use tower_cookies::{cookie::SameSite, Cookie, Cookies, CookieManagerLayer};

#[derive(Clone)]
struct AppState {
    google_flow: Arc<OAuth2Flow<GoogleProvider>>,
    session_store: Arc<dyn SessionStore>,
}

// Implement FromRef for Axum
impl axum::extract::FromRef<AppState> for Arc<dyn SessionStore> {
    fn from_ref(state: &AppState) -> Self {
        state.session_store.clone()
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let client_id = std::env::var("AUTHLY_GOOGLE_CLIENT_ID")
        .expect("AUTHLY_GOOGLE_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHLY_GOOGLE_CLIENT_SECRET")
        .expect("AUTHLY_GOOGLE_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHLY_GOOGLE_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/google/callback".to_string());

    let provider = GoogleProvider::new(
        client_id,
        client_secret,
        redirect_uri,
    );
    let google_flow = Arc::new(OAuth2Flow::new(provider));
    
    // Use Redis if REDIS_URL is set, otherwise fallback to MemoryStore
    let session_store: Arc<dyn SessionStore> = if let Ok(redis_url) = std::env::var("REDIS_URL") {
        println!("Using RedisStore at {}", redis_url);
        Arc::new(authly_session::RedisStore::new(&redis_url, "authly".into()).unwrap())
    } else {
        println!("Using MemoryStore");
        Arc::new(MemoryStore::default())
    };

    let state = AppState {
        google_flow,
        session_store,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/google", get(google_login))
        .route("/auth/google/callback", get(google_callback))
        .route("/protected", get(protected))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> impl IntoResponse {
    "Welcome! Go to /auth/google to login."
}

async fn google_login(
    State(state): State<AppState>,
    cookies: Cookies,
) -> impl IntoResponse {
    let (url, csrf_state) = state.google_flow.initiate_login();
    
    let mut cookie = Cookie::new("oauth_state", csrf_state);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    
    cookies.add(cookie);
    
    Redirect::to(&url)
}

#[derive(serde::Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

async fn google_callback(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    let expected_state = cookies
        .get("oauth_state")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    // Remove the state cookie after use
    let mut remove_cookie = Cookie::new("oauth_state", "");
    remove_cookie.set_path("/");
    cookies.remove(remove_cookie);

    let (mut identity, token) = match state
        .google_flow
        .finalize_login(&params.code, &params.state, &expected_state)
        .await
    {
        Ok((identity, token)) => (identity, token),
        Err(e) => return format!("Authentication failed: {}", e).into_response(),
    };

    // Store tokens in identity attributes
    identity.attributes.insert("access_token".to_string(), token.access_token);
    
    if let Some(expires_in) = token.expires_in {
        let expires_at = chrono::Utc::now().timestamp() + expires_in as i64;
        identity.attributes.insert("expires_at".to_string(), expires_at.to_string());
    }

    if let Some(rt) = token.refresh_token {
        identity.attributes.insert("refresh_token".to_string(), rt);
    }

    let session = Session {
        id: uuid::Uuid::new_v4().to_string(),
        identity,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
    };

    state.session_store.save_session(&session).await.unwrap();
    
    let mut cookie = Cookie::new("authly_session", session.id);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    
    cookies.add(cookie);

    Redirect::to("/protected").into_response()
}

async fn protected(AuthSession(session): AuthSession) -> impl IntoResponse {
    format!(
        "Hello, {}! Your ID is {}. Your email is {:?}. Attributes: {:?}",
        session.identity.username.unwrap_or_default(),
        session.identity.external_id,
        session.identity.email,
        session.identity.attributes
    )
}


// Minimal MemoryStore for example
#[derive(Default)]
struct MemoryStore {
    sessions: std::sync::Mutex<HashMap<String, Session>>,
}

#[async_trait::async_trait]
impl SessionStore for MemoryStore {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, authly_core::AuthError> {
        Ok(self.sessions.lock().unwrap().get(id).cloned())
    }
    async fn save_session(&self, session: &Session) -> Result<(), authly_core::AuthError> {
        self.sessions.lock().unwrap().insert(session.id.clone(), session.clone());
        Ok(())
    }
    async fn delete_session(&self, id: &str) -> Result<(), authly_core::AuthError> {
        self.sessions.lock().unwrap().remove(id);
        Ok(())
    }
}
