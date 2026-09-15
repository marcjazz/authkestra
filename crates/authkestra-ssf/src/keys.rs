//! Where the verification key comes from.
//!
//! RFC 8935 §2 says the mechanism for validating a SET's authenticity "is deployment specific";
//! this crate therefore takes no position on it beyond a trait. A deployment with one long-lived
//! transmitter key configures a single [`jsonwebtoken::DecodingKey`]; a deployment that follows
//! the transmitter's JWKS implements [`SetKeyResolver`] over its own cache.

use std::collections::HashMap;

use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use thiserror::Error;

/// Why a verification key could not be produced for a SET.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KeyResolveError {
    /// No key is known for the token's `kid` (or for a token with no `kid` at all).
    #[error("no key for kid {0:?}")]
    UnknownKid(Option<String>),

    /// The key source itself failed — a JWKS fetch timed out, a cache was unreachable, etc.
    ///
    /// Deliberately distinct from [`KeyResolveError::UnknownKid`] so that an outage is
    /// distinguishable in logs from a genuinely unknown key, even though both reject the SET.
    #[error("key source unavailable: {0}")]
    Unavailable(String),
}

/// Resolves the key a SET's signature should be verified against.
///
/// `async` because the realistic implementation consults a JWKS cache that may need to refresh
/// over the network. Implementations must never fall back to "no key means accept": returning
/// `Err` is the only way to signal that no key could be found, and [`crate::SetVerifier`] treats
/// every `Err` as a rejection.
#[async_trait]
pub trait SetKeyResolver: Send + Sync + 'static {
    /// Resolves a key for `issuer` and the token's `kid` header (absent for tokens that carry
    /// none).
    ///
    /// `issuer` is passed as well as `kid` because `kid` is only unique within one issuer's key
    /// set; a resolver serving several transmitters needs both to avoid one transmitter's key ID
    /// selecting another transmitter's key.
    async fn resolve(
        &self,
        issuer: &str,
        kid: Option<&str>,
    ) -> Result<DecodingKey, KeyResolveError>;
}

/// A [`SetKeyResolver`] that returns the same key for every `kid`.
///
/// This is what [`crate::SetVerifierBuilder::key`] installs. It ignores `kid` entirely, which is
/// correct for a single-key deployment and wrong the moment the transmitter rotates keys — at
/// which point the deployment wants a JWKS-backed resolver, not a second static key.
pub struct SingleKeyResolver {
    key: DecodingKey,
}

impl SingleKeyResolver {
    /// Wraps `key` so that it is returned for every resolution request.
    pub fn new(key: DecodingKey) -> Self {
        Self { key }
    }
}

#[async_trait]
impl SetKeyResolver for SingleKeyResolver {
    async fn resolve(
        &self,
        _issuer: &str,
        _kid: Option<&str>,
    ) -> Result<DecodingKey, KeyResolveError> {
        Ok(self.key.clone())
    }
}

/// A [`SetKeyResolver`] backed by a fixed `kid` to key map.
///
/// Useful for a deployment that pins a transmitter's published keys in configuration, and for
/// tests. A token with no `kid` is rejected rather than matched against a sole entry: guessing
/// which key an unlabelled token meant is how algorithm/key-confusion bugs start.
#[derive(Default)]
pub struct StaticKeyResolver {
    keys: HashMap<String, DecodingKey>,
}

impl StaticKeyResolver {
    /// Creates an empty resolver.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Adds `key` under `kid`, replacing any previous entry for that `kid`.
    pub fn with_key(mut self, kid: impl Into<String>, key: DecodingKey) -> Self {
        self.keys.insert(kid.into(), key);
        self
    }
}

#[async_trait]
impl SetKeyResolver for StaticKeyResolver {
    async fn resolve(
        &self,
        _issuer: &str,
        kid: Option<&str>,
    ) -> Result<DecodingKey, KeyResolveError> {
        let kid = kid.ok_or(KeyResolveError::UnknownKid(None))?;
        self.keys
            .get(kid)
            .cloned()
            .ok_or_else(|| KeyResolveError::UnknownKid(Some(kid.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn single_key_resolver_ignores_kid() {
        let resolver = SingleKeyResolver::new(DecodingKey::from_secret(b"secret"));
        assert!(resolver.resolve("https://iss/", None).await.is_ok());
        assert!(resolver.resolve("https://iss/", Some("any")).await.is_ok());
    }

    #[tokio::test]
    async fn static_key_resolver_matches_on_kid() {
        let resolver = StaticKeyResolver::new().with_key("k1", DecodingKey::from_secret(b"secret"));
        assert!(resolver.resolve("https://iss/", Some("k1")).await.is_ok());
        assert_eq!(
            resolver
                .resolve("https://iss/", Some("k2"))
                .await
                .unwrap_err(),
            KeyResolveError::UnknownKid(Some("k2".into()))
        );
        assert_eq!(
            resolver.resolve("https://iss/", None).await.unwrap_err(),
            KeyResolveError::UnknownKid(None)
        );
    }

    #[tokio::test]
    async fn static_key_resolver_replaces_a_duplicate_kid() {
        let resolver = StaticKeyResolver::default()
            .with_key("k1", DecodingKey::from_secret(b"first"))
            .with_key("k1", DecodingKey::from_secret(b"second"));
        assert!(resolver.resolve("https://iss/", Some("k1")).await.is_ok());
    }

    #[test]
    fn key_resolve_errors_describe_themselves() {
        assert!(KeyResolveError::UnknownKid(Some("k".into()))
            .to_string()
            .contains("k"));
        assert!(KeyResolveError::Unavailable("timeout".into())
            .to_string()
            .contains("timeout"));
    }
}
