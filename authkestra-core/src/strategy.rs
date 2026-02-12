use async_trait::async_trait;
use http::request::Parts;
use crate::error::AuthError;
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

/// Policy for controlling the behavior of chained authentication strategies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthPolicy {
    /// Try strategies in order, return the first success.
    /// If a strategy returns an error, the whole chain fails.
    /// If all strategies return `None`, the chain returns `None`.
    #[default]
    FirstSuccess,
    /// All strategies must succeed. If any fails or returns `None`, the whole chain fails.
    /// Returns the identity from the last strategy.
    AllSuccess,
    /// If the first strategy fails or returns `None`, stop immediately.
    FailFast,
}

/// A service that orchestrates multiple authentication strategies.
pub struct Authenticator<I> {
    strategies: Vec<Box<dyn AuthenticationStrategy<I>>>,
    policy: AuthPolicy,
}

impl<I> Authenticator<I> {
    /// Create a new builder for the Authenticator.
    pub fn builder() -> AuthenticatorBuilder<I> {
        AuthenticatorBuilder::default()
    }

    /// Attempt to authenticate the request using the configured strategies and policy.
    pub async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        match self.policy {
            AuthPolicy::FirstSuccess => {
                for strategy in &self.strategies {
                    match strategy.authenticate(parts).await {
                        Ok(Some(identity)) => return Ok(Some(identity)),
                        Ok(None) => continue,
                        Err(e) => return Err(e),
                    }
                }
                Ok(None)
            }
            AuthPolicy::AllSuccess => {
                let mut last_identity = None;
                for strategy in &self.strategies {
                    match strategy.authenticate(parts).await {
                        Ok(Some(identity)) => last_identity = Some(identity),
                        Ok(None) => return Ok(None),
                        Err(e) => return Err(e),
                    }
                }
                Ok(last_identity)
            }
            AuthPolicy::FailFast => {
                if let Some(strategy) = self.strategies.first() {
                    strategy.authenticate(parts).await
                } else {
                    Ok(None)
                }
            }
        }
    }
}

/// Builder for the `Authenticator`.
pub struct AuthenticatorBuilder<I> {
    strategies: Vec<Box<dyn AuthenticationStrategy<I>>>,
    policy: AuthPolicy,
}

impl<I> Default for AuthenticatorBuilder<I> {
    fn default() -> Self {
        Self {
            strategies: Vec::new(),
            policy: AuthPolicy::default(),
        }
    }
}

impl<I> AuthenticatorBuilder<I> {
    /// Add an authentication strategy to the chain.
    pub fn with_strategy<S>(mut self, strategy: S) -> Self
    where
        S: AuthenticationStrategy<I> + 'static,
    {
        self.strategies.push(Box::new(strategy));
        self
    }

    /// Set the authentication policy.
    pub fn policy(mut self, policy: AuthPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Build the `Authenticator`.
    pub fn build(self) -> Authenticator<I> {
        Authenticator {
            strategies: self.strategies,
            policy: self.policy,
        }
    }
}

/// Trait for a provider that validates username and password (Basic Auth).
#[async_trait]
pub trait BasicAuthenticator: Send + Sync {
    /// The type of identity returned by this authenticator.
    type Identity;
    /// Validate the credentials.
    async fn authenticate(&self, username: &str, password: &str) -> Result<Option<Self::Identity>, AuthError>;
}

/// Strategy for Basic authentication.
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
    use http::header::{AUTHORIZATION, HeaderMap};

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
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            encoded,
        ).ok()?;
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

