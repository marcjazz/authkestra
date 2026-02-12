use authkestra_axum::Auth;
use authkestra_core::error::AuthError;
use authkestra_core::strategy::{
    AuthPolicy, Authenticator, BasicAuthenticator, BasicStrategy, TokenStrategy, TokenValidator,
};
use authkestra_token::offline_validation::OfflineValidationBuilder;
use axum::{extract::FromRef, response::IntoResponse, routing::get, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// --- Custom Identity ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: String,
    pub method: String,
}

// --- Mock Credentials Provider ---

#[derive(Clone)]
pub struct MyCredentialsProvider;

#[async_trait::async_trait]
impl BasicAuthenticator for MyCredentialsProvider {
    type Identity = User;

    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<User>, AuthError> {
        if username == "admin" && password == "password" {
            Ok(Some(User {
                id: username.to_string(),
                method: "basic".to_string(),
            }))
        } else {
            Ok(None)
        }
    }
}

// --- Mock Token Validator (for Opaque Tokens) ---

pub struct OpaqueTokenValidator;

#[async_trait::async_trait]
impl TokenValidator for OpaqueTokenValidator {
    type Identity = User;

    async fn validate(&self, token: &str) -> Result<Option<Self::Identity>, AuthError> {
        if token == "opaque-token" {
            Ok(Some(User {
                id: "opaque-user".to_string(),
                method: "opaque".to_string(),
            }))
        } else {
            Ok(None)
        }
    }
}

// --- App State ---

#[derive(Clone)]
struct AppState {
    authenticator: Arc<Authenticator<User>>,
}

impl FromRef<AppState> for Arc<Authenticator<User>> {
    fn from_ref(state: &AppState) -> Self {
        state.authenticator.clone()
    }
}

// --- Handlers ---

async fn index() -> impl IntoResponse {
    "Custom Auth Example v2. Try Basic Auth, JWT, or Opaque Token on /protected"
}

async fn protected(Auth(user): Auth<User>) -> impl IntoResponse {
    format!("Welcome, {}! Authenticated via {}.", user.id, user.method)
}

// --- Main ---

#[tokio::main]
async fn main() {
    // 1. Setup JWT Offline Validation
    let jwt_validator =
        OfflineValidationBuilder::new("https://www.googleapis.com/oauth2/v3/certs").build::<User>();

    // 2. Setup Basic Auth
    let basic_strategy = BasicStrategy::new(MyCredentialsProvider);

    // 3. Setup Opaque Token Auth
    let opaque_strategy = TokenStrategy::new(OpaqueTokenValidator);

    // 4. Build Authenticator with FirstSuccess policy (default)
    let authenticator = Authenticator::builder()
        .policy(AuthPolicy::FirstSuccess)
        .with_strategy(TokenStrategy::new(jwt_validator))
        .with_strategy(opaque_strategy)
        .with_strategy(basic_strategy)
        .build();

    let state = AppState {
        authenticator: Arc::new(authenticator),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("📡 Listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

// --- Testing ---

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{header::AUTHORIZATION, Request, StatusCode},
    };
    use base64::{engine::general_purpose, Engine as _};
    use tower::ServiceExt;
    

    async fn setup_app(policy: AuthPolicy) -> Router {
        let jwt_validator = OfflineValidationBuilder::new("https://www.googleapis.com/oauth2/v3/certs")
                .build::<User>();

        let authenticator = Authenticator::builder()
            .policy(policy)
            .with_strategy(TokenStrategy::new(jwt_validator))
            .with_strategy(TokenStrategy::new(OpaqueTokenValidator))
            .with_strategy(BasicStrategy::new(MyCredentialsProvider))
            .build();

        let state = AppState {
            authenticator: Arc::new(authenticator),
        };

        Router::new()
            .route("/protected", get(protected))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_first_success_policy() {
        let app = setup_app(AuthPolicy::FirstSuccess).await;
        let auth = general_purpose::STANDARD.encode("admin:password");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header(AUTHORIZATION, format!("Basic {}", auth))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_all_success_policy_fails_if_one_missing() {
        // AllSuccess requires ALL strategies to return Some(identity)
        // In our setup, we have JWT, Opaque, and Basic.
        // If we only provide Basic, the others will return None, so AllSuccess should fail.
        let app = setup_app(AuthPolicy::AllSuccess).await;
        let auth = general_purpose::STANDARD.encode("admin:password");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header(AUTHORIZATION, format!("Basic {}", auth))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // It returns UNAUTHORIZED because one of the strategies (JWT) returned Ok(None)
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_fail_fast_policy() {
        let app = setup_app(AuthPolicy::FailFast).await;
        // FailFast only tries the first strategy (JWT in our setup)
        // Providing Basic Auth should fail because it doesn't even try it.
        let auth = general_purpose::STANDARD.encode("admin:password");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header(AUTHORIZATION, format!("Basic {}", auth))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
