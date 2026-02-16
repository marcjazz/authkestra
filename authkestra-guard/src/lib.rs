use authkestra_core::error::AuthError;
use authkestra_core::strategy::AuthenticationStrategy;
use http::request::Parts;

pub mod jwt;

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
pub struct AuthkestraGuard<I> {
    strategies: Vec<Box<dyn AuthenticationStrategy<I>>>,
    policy: AuthPolicy,
}

impl<I> AuthkestraGuard<I> {
    /// Create a new builder for the Guard.
    pub fn builder() -> AuthkestraGuardBuilder<I> {
        AuthkestraGuardBuilder::default()
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

/// Builder for the `AuthkestraGuard`.
pub struct AuthkestraGuardBuilder<I> {
    strategies: Vec<Box<dyn AuthenticationStrategy<I>>>,
    policy: AuthPolicy,
}

impl<I> Default for AuthkestraGuardBuilder<I> {
    fn default() -> Self {
        Self {
            strategies: Vec::new(),
            policy: AuthPolicy::default(),
        }
    }
}

impl<I> AuthkestraGuardBuilder<I>
where
    I: Send + Sync + 'static,
{
    /// Add an authentication strategy to the chain.
    pub fn strategy<S>(mut self, strategy: S) -> Self
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

    /// Build the `AuthkestraGuard`.
    pub fn build(self) -> AuthkestraGuard<I> {
        AuthkestraGuard {
            strategies: self.strategies,
            policy: self.policy,
        }
    }
}
