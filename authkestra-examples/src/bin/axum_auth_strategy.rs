use async_trait::async_trait;
use authkestra_axum::Auth;
use authkestra_core::error::AuthError;
use authkestra_core::strategy::{AuthenticationStrategy, BasicAuthenticator, BasicStrategy};
use authkestra_guard::AuthGuard;
use axum::{http::request::Parts, routing::get, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A simple user identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: String,
    pub username: String,
}

/// 1. Implement `CustomHeaderStrategy`
///
/// This strategy looks for an `X-API-Key` header and validates it.
pub struct CustomHeaderStrategy {
    api_key: String,
}

impl CustomHeaderStrategy {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
        }
    }
}

#[async_trait]
impl AuthenticationStrategy<User> for CustomHeaderStrategy {
    async fn authenticate(&self, parts: &Parts) -> Result<Option<User>, AuthError> {
        // Look for the X-API-Key header
        if let Some(value) = parts.headers.get("X-API-Key") {
            if let Ok(value_str) = value.to_str() {
                // Validate the header value
                if value_str == self.api_key {
                    return Ok(Some(User {
                        id: "1".to_string(),
                        username: "api_user".to_string(),
                    }));
                } else {
                    // If the header is present but invalid, we return an error
                    return Err(AuthError::InvalidCredentials);
                }
            }
        }

        // If the header is missing, we return Ok(None) to allow other strategies in the chain to try
        Ok(None)
    }
}

/// A simple Basic Authenticator for demonstration.
pub struct MyBasicAuthenticator;

#[async_trait]
impl BasicAuthenticator for MyBasicAuthenticator {
    type Identity = User;

    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<Self::Identity>, AuthError> {
        if username == "admin" && password == "password" {
            Ok(Some(User {
                id: "2".to_string(),
                username: "admin".to_string(),
            }))
        } else {
            Ok(None)
        }
    }
}

/// 3. Axum App
///
/// Protected route using `Auth<User>`.
async fn protected_route(Auth(user): Auth<User>) -> String {
    format!("Hello, {}! Your ID is {}.", user.username, user.id)
}

fn app(guard: Arc<AuthGuard<User>>) -> Router {
    Router::new()
        .route("/protected", get(protected_route))
        .with_state(guard)
}

#[tokio::main]
async fn main() {
    // 2. Integrate with Guard
    // We chain CustomHeaderStrategy and BasicStrategy to show flexibility.
    let guard = AuthGuard::<User>::builder()
        .strategy(CustomHeaderStrategy::new("secret-api-key"))
        .strategy(BasicStrategy::new(MyBasicAuthenticator))
        .build();

    let shared_guard = Arc::new(guard);

    let app = app(shared_guard);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use authkestra_core::strategy::TokenStrategy;
    use authkestra_guard::{
        jwt::{JwksCache, OfflineValidator},
        AuthPolicy,
    };
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::Engine;
    use tower::ServiceExt;

    fn setup_app() -> Router {
        let guard = Arc::new(
            AuthGuard::<User>::builder()
                .strategy(CustomHeaderStrategy::new("secret-api-key"))
                .strategy(BasicStrategy::new(MyBasicAuthenticator))
                .strategy(TokenStrategy::new(OfflineValidator::new(
                    JwksCache::new(
                        "https://www.googleapis.com/oauth2/v3/certs".to_string(),
                        std::time::Duration::from_secs(3600),
                    ),
                    jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256),
                )))
                .policy(AuthPolicy::FirstSuccess)
                .build(),
        );
        app(guard)
    }

    #[tokio::test]
    async fn test_valid_api_key() {
        let app = setup_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("X-API-Key", "secret-api-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_valid_basic_auth() {
        let app = setup_app();

        let auth = base64::engine::general_purpose::STANDARD.encode("admin:password");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("Authorization", format!("Basic {}", auth))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_invalid_api_key() {
        let app = setup_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("X-API-Key", "wrong-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_missing_header() {
        let app = setup_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
