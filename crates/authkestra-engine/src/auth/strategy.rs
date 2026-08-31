use crate::error::AuthError;
use async_trait::async_trait;
use http::request::Parts;
use std::marker::PhantomData;

/// Trait for an authentication strategy.
///
/// A strategy is responsible for extracting credentials from a request
/// and validating them to produce an identity.
#[async_trait]
pub trait AuthenticationStrategy<I>: Send + Sync {
    /// Attempt to authenticate the request.
    ///
    /// Returns:
    /// - `Ok(Some(identity))` if authentication was successful.
    /// - `Ok(None)` if the strategy did not find relevant credentials (e.g., missing header).
    /// - `Err(AuthError)` if authentication failed (e.g., invalid token, DB error).
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError>;
}

/// Trait for a provider that validates username and password (Basic Auth).
#[async_trait]
pub trait BasicAuthenticator: Send + Sync {
    /// The type of identity returned by this authenticator.
    type Identity;
    /// Validate the credentials.
    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<Self::Identity>, AuthError>;
}

/// Strategy for Basic authentication.
#[non_exhaustive]
pub struct BasicStrategy<P, I> {
    authenticator: P,
    _marker: PhantomData<I>,
}

impl<P, I> BasicStrategy<P, I> {
    /// Create a new BasicStrategy with the given authenticator.
    pub fn new(authenticator: P) -> Self {
        Self {
            authenticator,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<P, I> AuthenticationStrategy<I> for BasicStrategy<P, I>
where
    P: BasicAuthenticator<Identity = I> + Send + Sync,
    I: Send + Sync + 'static,
{
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        if let Some((username, password)) = utils::extract_basic_credentials(&parts.headers) {
            self.authenticator.authenticate(&username, &password).await
        } else {
            Ok(None)
        }
    }
}

/// Trait for a validator that verifies a token.
#[async_trait]
pub trait TokenValidator: Send + Sync {
    /// The type of identity returned by this validator.
    type Identity;
    /// Validate the token.
    async fn validate(&self, token: &str) -> Result<Option<Self::Identity>, AuthError>;
}

/// Strategy for Token (Bearer) authentication.
#[non_exhaustive]
pub struct TokenStrategy<V, I> {
    validator: V,
    _marker: PhantomData<I>,
}

impl<V, I> TokenStrategy<V, I> {
    /// Create a new TokenStrategy with the given validator.
    pub fn new(validator: V) -> Self {
        Self {
            validator,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<V, I> AuthenticationStrategy<I> for TokenStrategy<V, I>
where
    V: TokenValidator<Identity = I> + Send + Sync,
    I: Send + Sync + 'static,
{
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        if let Some(token) = utils::extract_bearer_token(&parts.headers) {
            self.validator.validate(token).await
        } else {
            Ok(None)
        }
    }
}

/// Strategy for custom header authentication.
#[non_exhaustive]
pub struct HeaderStrategy<F, I> {
    header_name: http::header::HeaderName,
    validator: F,
    _marker: PhantomData<I>,
}

impl<F, I> HeaderStrategy<F, I> {
    /// Create a new HeaderStrategy.
    pub fn new(header_name: http::header::HeaderName, validator: F) -> Self {
        Self {
            header_name,
            validator,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<F, I, Fut> AuthenticationStrategy<I> for HeaderStrategy<F, I>
where
    F: Fn(String) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<Option<I>, AuthError>> + Send,
    I: Send + Sync + 'static,
{
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        if let Some(value) = parts.headers.get(&self.header_name) {
            if let Ok(value_str) = value.to_str() {
                return (self.validator)(value_str.to_string()).await;
            }
        }
        Ok(None)
    }
}

/// Trait for a session store that can load an identity.
#[async_trait]
pub trait SessionProvider: Send + Sync {
    /// The type of identity returned by this provider.
    type Identity;
    /// Load the identity associated with the session ID.
    async fn load_session(&self, session_id: &str) -> Result<Option<Self::Identity>, AuthError>;
}

/// Strategy for Session authentication.
#[non_exhaustive]
pub struct SessionStrategy<P, I> {
    provider: P,
    cookie_name: String,
    _marker: PhantomData<I>,
}

impl<P, I> SessionStrategy<P, I> {
    /// Create a new SessionStrategy.
    pub fn new(provider: P, cookie_name: impl Into<String>) -> Self {
        Self {
            provider,
            cookie_name: cookie_name.into(),
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<P, I> AuthenticationStrategy<I> for SessionStrategy<P, I>
where
    P: SessionProvider<Identity = I> + Send + Sync,
    I: Send + Sync + 'static,
{
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        if let Some(session_id) = utils::extract_cookie(&parts.headers, &self.cookie_name) {
            self.provider.load_session(session_id).await
        } else {
            Ok(None)
        }
    }
}

/// Utility functions for common authentication tasks.
pub mod utils {
    use http::header::{HeaderMap, AUTHORIZATION};

    /// Extract the Bearer token from the Authorization header.
    pub fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
        headers
            .get(AUTHORIZATION)?
            .to_str()
            .ok()?
            .strip_prefix("Bearer ")
            .map(|s| s.trim())
    }

    /// Extract Basic credentials from the Authorization header.
    pub fn extract_basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
        let auth_header = headers.get(AUTHORIZATION)?.to_str().ok()?;
        if !auth_header.starts_with("Basic ") {
            return None;
        }
        let encoded = auth_header.strip_prefix("Basic ")?.trim();
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        let mut parts = decoded_str.splitn(2, ':');
        let username = parts.next()?.to_string();
        let password = parts.next()?.to_string();
        Some((username, password))
    }

    /// Extract a cookie value by name.
    pub fn extract_cookie<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
        let cookie_header = headers.get(http::header::COOKIE)?.to_str().ok()?;
        for cookie in cookie_header.split(';') {
            let mut parts = cookie.splitn(2, '=');
            let k = parts.next()?.trim();
            let v = parts.next()?.trim();
            if k == name {
                return Some(v);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{
        header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, COOKIE},
        Request,
    };

    #[derive(Debug, PartialEq)]
    struct DummyIdentity(String);

    struct DummyBasic;
    #[async_trait]
    impl BasicAuthenticator for DummyBasic {
        type Identity = DummyIdentity;
        async fn authenticate(
            &self,
            u: &str,
            p: &str,
        ) -> Result<Option<Self::Identity>, AuthError> {
            if u == "user" && p == "pass" {
                Ok(Some(DummyIdentity(u.to_string())))
            } else {
                Ok(None)
            }
        }
    }

    struct DummyToken;
    #[async_trait]
    impl TokenValidator for DummyToken {
        type Identity = DummyIdentity;
        async fn validate(&self, t: &str) -> Result<Option<Self::Identity>, AuthError> {
            if t == "valid_token" {
                Ok(Some(DummyIdentity("user".to_string())))
            } else {
                Ok(None)
            }
        }
    }

    struct DummySession;
    #[async_trait]
    impl SessionProvider for DummySession {
        type Identity = DummyIdentity;
        async fn load_session(&self, sid: &str) -> Result<Option<Self::Identity>, AuthError> {
            if sid == "valid_sid" {
                Ok(Some(DummyIdentity("user".to_string())))
            } else {
                Ok(None)
            }
        }
    }

    #[tokio::test]
    async fn test_basic_strategy() {
        let strategy = BasicStrategy::new(DummyBasic);
        let mut req = Request::builder().uri("/").body(()).unwrap();

        let res = strategy.authenticate(&req.into_parts().0).await.unwrap();
        assert_eq!(res, None);

        let mut req2 = Request::builder()
            .uri("/")
            .header(AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(())
            .unwrap();
        let res2 = strategy.authenticate(&req2.into_parts().0).await.unwrap();
        assert_eq!(res2.unwrap(), DummyIdentity("user".to_string()));
    }

    #[tokio::test]
    async fn test_token_strategy() {
        let strategy = TokenStrategy::new(DummyToken);
        let mut req = Request::builder().uri("/").body(()).unwrap();

        let res = strategy.authenticate(&req.into_parts().0).await.unwrap();
        assert_eq!(res, None);

        let mut req2 = Request::builder()
            .uri("/")
            .header(AUTHORIZATION, "Bearer valid_token")
            .body(())
            .unwrap();
        let res2 = strategy.authenticate(&req2.into_parts().0).await.unwrap();
        assert_eq!(res2.unwrap(), DummyIdentity("user".to_string()));
    }

    #[tokio::test]
    async fn test_header_strategy() {
        let strategy = HeaderStrategy::new(
            HeaderName::from_static("x-api-key"),
            |key: String| async move {
                if key == "secret" {
                    Ok(Some(DummyIdentity("user".to_string())))
                } else {
                    Ok(None)
                }
            },
        );
        let mut req = Request::builder().uri("/").body(()).unwrap();

        let res = strategy.authenticate(&req.into_parts().0).await.unwrap();
        assert_eq!(res, None);

        let mut req2 = Request::builder()
            .uri("/")
            .header("x-api-key", "secret")
            .body(())
            .unwrap();
        let res2 = strategy.authenticate(&req2.into_parts().0).await.unwrap();
        assert_eq!(res2.unwrap(), DummyIdentity("user".to_string()));
    }

    #[tokio::test]
    async fn test_session_strategy() {
        let strategy = SessionStrategy::new(DummySession, "sid");
        let mut req = Request::builder().uri("/").body(()).unwrap();

        let res = strategy.authenticate(&req.into_parts().0).await.unwrap();
        assert_eq!(res, None);

        let mut req2 = Request::builder()
            .uri("/")
            .header(COOKIE, "sid=valid_sid")
            .body(())
            .unwrap();
        let res2 = strategy.authenticate(&req2.into_parts().0).await.unwrap();
        assert_eq!(res2.unwrap(), DummyIdentity("user".to_string()));
    }

    #[test]
    fn test_utils_extractors() {
        let mut headers = HeaderMap::new();
        assert_eq!(utils::extract_bearer_token(&headers), None);
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        assert_eq!(utils::extract_bearer_token(&headers), Some("token"));

        let mut headers2 = HeaderMap::new();
        headers2.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(
            utils::extract_basic_credentials(&headers2),
            Some(("user".to_string(), "pass".to_string()))
        );

        let mut headers3 = HeaderMap::new();
        headers3.insert(COOKIE, HeaderValue::from_static("foo=bar; sid=123"));
        assert_eq!(utils::extract_cookie(&headers3, "sid"), Some("123"));
    }
}
