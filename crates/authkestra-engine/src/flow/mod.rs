//! # Engine Flow
//!
//! `authkestra-flow` orchestrates authentication flows, such as OAuth2 Authorization Code,
//! PKCE, Client Credentials, and Device Flow. It acts as the bridge between the core traits
//! and the framework-specific adapters.
//!
//! ## Key Components
//!
//! - **[`OAuth2Flow`]**: Orchestrates the standard OAuth2 Authorization Code flow.
//! - **[`Engine`]**: The main service that holds providers, session stores, and token managers.
//! - **[`EngineBuilder`]**: A builder for configuring and creating an [`Engine`] instance.
//! - **[`CredentialsFlow`]**: Orchestrates direct credentials-based authentication (e.g., email/password).

#![warn(missing_docs)]

use crate::auth::{error::AuthError, state::Identity, CredentialsProvider, UserMapper};
pub use crate::auth::{ErasedOAuthFlow, Session, SessionConfig, SessionStore};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use chrono;

/// Context for an authentication flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FlowContext {
    /// The current state identifier.
    pub state: String,
    /// Parameters associated with the flow.
    pub params: HashMap<String, String>,
    /// The parsed JSON body of a protocol that speaks JSON end-to-end, such
    /// as GNAP (RFC 9635 §2: every grant request is a single JSON object).
    /// `None` for the form/query-encoded OAuth2 flows, which populate
    /// `params` instead. See RFC-004 §4.2 (G1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

impl FlowContext {
    /// Construct a new context with no JSON body.
    ///
    /// `FlowContext` is `#[non_exhaustive]`, so struct-literal construction
    /// is unavailable outside this crate; this is the supported entry point
    /// for building one, including from tests in this crate.
    pub fn new(state: impl Into<String>, params: HashMap<String, String>) -> Self {
        Self {
            state: state.into(),
            params,
            body: None,
        }
    }

    /// Attach a parsed JSON body, for protocols that carry one (RFC-004 §4.2, G1).
    pub fn with_body(mut self, body: serde_json::Value) -> Self {
        self.body = Some(body);
        self
    }
}

/// Result of an authentication flow execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FlowResult {
    /// The flow is complete and has returned an identity.
    Complete(Identity),
    /// The flow requires a redirect to another URL.
    Redirect(String),
    /// The flow is pending (e.g., waiting for user interaction).
    Pending,
    /// A protocol response that is a JSON document rather than a redirect
    /// or a bare identity — for example, a GNAP grant response (RFC 9635
    /// §3), which may carry `continue`, `interact`, `access_token` and
    /// `subject` simultaneously and so does not fit a three-way enum.
    /// Deliberately untyped (`serde_json::Value`) rather than a new generic
    /// parameter on `Flow`, to keep `Flow` trait-object friendly; see
    /// RFC-004 §5, Q2.
    Document(serde_json::Value),
}

/// Transport-level facts about the inbound HTTP request that produced a
/// [`FlowContext`].
///
/// Deliberately **not** folded into `FlowContext`: `FlowContext` derives
/// `Serialize`/`Deserialize` so it can round-trip through encrypted state
/// cookies, and `http::HeaderMap` does not implement `Serialize`. A [`Flow`]
/// that needs to see the method, URI, headers or *exact raw bytes* of the
/// request — for example, a GNAP key-proofing check (RFC 9635 §7.3), which
/// signs over the literal request body — overrides
/// [`Flow::execute_with_parts`] instead of [`Flow::execute`].
#[non_exhaustive]
pub struct RequestParts<'a> {
    /// The HTTP method of the inbound request.
    pub method: &'a http::Method,
    /// The HTTP URI of the inbound request.
    pub uri: &'a http::Uri,
    /// The headers of the inbound request.
    pub headers: &'a http::HeaderMap,
    /// The raw request body, before any deserialization. Key-proofing
    /// schemes sign over these exact bytes, so a parsed representation
    /// (e.g. `FlowContext::body`) is not sufficient for verifying them.
    pub body: &'a [u8],
}

/// Orchestrates the steps of an authentication protocol (e.g., OAuth2, Device Flow).
#[async_trait]
pub trait Flow: Send + Sync {
    /// Returns the unique identifier for the flow.
    fn id(&self) -> &str;

    /// Executes the flow with the given context.
    async fn execute(&self, ctx: FlowContext) -> Result<FlowResult, AuthError>;

    /// Like [`execute`](Self::execute), but also given the raw transport
    /// facts of the inbound request via [`RequestParts`].
    ///
    /// Defaulted to ignore `parts` and delegate to `execute`, so every
    /// existing implementor of `Flow` keeps compiling and behaving exactly
    /// as before without any change. Override this for a protocol whose
    /// security model depends on the request's exact method, URI, headers
    /// or body bytes — GNAP key proofing (RFC 9635 §7.3) is the motivating
    /// case; see RFC-004.
    async fn execute_with_parts(
        &self,
        ctx: FlowContext,
        _parts: RequestParts<'_>,
    ) -> Result<FlowResult, AuthError> {
        self.execute(ctx).await
    }
}

use std::collections::HashMap;

pub use crate::engine::{Configured, Engine, EngineBuilder, Missing};

/// Client Credentials flow implementation.
pub mod client_credentials_flow;
/// Device Authorization flow implementation.
pub mod device_flow;
/// OAuth2 Authorization Code flow implementation.
pub mod oauth2;

pub use client_credentials_flow::ClientCredentialsFlow;
pub use device_flow::{DeviceAuthorizationResponse, DeviceFlow};
pub use oauth2::OAuth2Flow;

/// Orchestrates a direct credentials flow.
#[non_exhaustive]
pub struct CredentialsFlow<P: CredentialsProvider, M: UserMapper = ()> {
    provider: P,
    mapper: Option<M>,
}

impl<P: CredentialsProvider> CredentialsFlow<P, ()> {
    /// Create a new `CredentialsFlow` with the given provider.
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            mapper: None,
        }
    }
}

impl<P: CredentialsProvider, M: UserMapper> CredentialsFlow<P, M> {
    /// Create a new `CredentialsFlow` with the given provider and user mapper.
    pub fn with_mapper(provider: P, mapper: M) -> Self {
        Self {
            provider,
            mapper: Some(mapper),
        }
    }

    /// Authenticate using the given credentials.
    pub async fn authenticate(
        &self,
        creds: P::Credentials,
    ) -> Result<(Identity, Option<M::LocalUser>), AuthError> {
        let identity = self.provider.authenticate(creds).await?;

        let local_user = if let Some(mapper) = &self.mapper {
            Some(mapper.map_user(&identity).await?)
        } else {
            None
        };

        Ok((identity, local_user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    #[derive(Debug, PartialEq, Clone)]
    struct DummyCreds(String);

    struct DummyProvider;
    #[async_trait]
    impl CredentialsProvider for DummyProvider {
        type Credentials = DummyCreds;
        async fn authenticate(&self, creds: Self::Credentials) -> Result<Identity, AuthError> {
            if creds.0 == "valid" {
                Ok(Identity {
                    provider_id: "dummy".to_string(),
                    external_id: "user_123".to_string(),
                    email: None,
                    username: None,
                    attributes: std::collections::HashMap::new(),
                })
            } else {
                Err(AuthError::InvalidCredentials)
            }
        }
    }

    #[derive(Debug, PartialEq)]
    struct DummyUser(String);

    struct DummyMapper;
    #[async_trait]
    impl UserMapper for DummyMapper {
        type LocalUser = DummyUser;
        async fn map_user(&self, identity: &Identity) -> Result<Self::LocalUser, AuthError> {
            Ok(DummyUser(identity.external_id.clone()))
        }
    }

    #[tokio::test]
    async fn test_credentials_flow() {
        let flow = CredentialsFlow::new(DummyProvider);
        let res = flow
            .authenticate(DummyCreds("valid".to_string()))
            .await
            .unwrap();
        assert_eq!(res.0.external_id, "user_123");
        assert!(res.1.is_none());

        let err = flow.authenticate(DummyCreds("invalid".to_string())).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_credentials_flow_with_mapper() {
        let flow = CredentialsFlow::with_mapper(DummyProvider, DummyMapper);
        let res = flow
            .authenticate(DummyCreds("valid".to_string()))
            .await
            .unwrap();
        assert_eq!(res.0.external_id, "user_123");
        assert_eq!(res.1.unwrap(), DummyUser("user_123".to_string()));
    }

    // --- GNAP-compatibility additions to `Flow` (RFC-004) ---

    #[test]
    fn flow_context_new_has_no_body() {
        let ctx = FlowContext::new("state123", HashMap::new());
        assert_eq!(ctx.state, "state123");
        assert!(ctx.body.is_none());
    }

    #[test]
    fn flow_context_with_body_attaches_json() {
        let body = serde_json::json!({"access_token": {"access": ["read"]}});
        let ctx = FlowContext::new("s", HashMap::new()).with_body(body.clone());
        assert_eq!(ctx.body, Some(body));
    }

    #[test]
    fn flow_context_serde_round_trip_preserves_body() {
        let ctx = FlowContext::new("s", HashMap::new())
            .with_body(serde_json::json!({"interact": {"start": ["redirect"]}}));
        let encoded = serde_json::to_string(&ctx).unwrap();
        let decoded: FlowContext = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.body, ctx.body);
    }

    #[test]
    fn flow_context_without_body_omits_the_field_on_the_wire() {
        // OAuth2-style contexts never carry a JSON body; the field must not
        // show up in the serialized form for them (`#[serde(skip_serializing_if)]`),
        // so a context built before this change round-trips identically.
        let ctx = FlowContext::new("s", HashMap::new());
        let encoded = serde_json::to_value(&ctx).unwrap();
        assert!(encoded.get("body").is_none());
    }

    #[test]
    fn flow_result_document_round_trips() {
        let doc = serde_json::json!({"continue": {"uri": "https://as.example/continue"}});
        let result = FlowResult::Document(doc.clone());
        let encoded = serde_json::to_string(&result).unwrap();
        let decoded: FlowResult = serde_json::from_str(&encoded).unwrap();
        match decoded {
            FlowResult::Document(v) => assert_eq!(v, doc),
            other => panic!("expected FlowResult::Document, got {other:?}"),
        }
    }

    /// A minimal `Flow` that does not override `execute_with_parts`, standing
    /// in for `OAuth2Flow` and every other pre-existing implementor: the
    /// default delegation must behave exactly like calling `execute`
    /// directly, so this change costs them nothing.
    struct LegacyFlow;
    #[async_trait]
    impl Flow for LegacyFlow {
        fn id(&self) -> &str {
            "legacy"
        }
        async fn execute(&self, ctx: FlowContext) -> Result<FlowResult, AuthError> {
            Ok(FlowResult::Redirect(format!(
                "https://example/{}",
                ctx.state
            )))
        }
    }

    #[tokio::test]
    async fn execute_with_parts_default_delegates_to_execute() {
        let flow = LegacyFlow;
        let ctx = FlowContext::new("abc", HashMap::new());
        let method = http::Method::POST;
        let uri: http::Uri = "https://as.example/gnap".parse().unwrap();
        let headers = http::HeaderMap::new();
        let parts = RequestParts {
            method: &method,
            uri: &uri,
            headers: &headers,
            body: b"{}",
        };

        let via_parts = flow.execute_with_parts(ctx.clone(), parts).await.unwrap();
        let via_execute = flow.execute(ctx).await.unwrap();

        match (via_parts, via_execute) {
            (FlowResult::Redirect(a), FlowResult::Redirect(b)) => assert_eq!(a, b),
            other => panic!("expected matching Redirect results, got {other:?}"),
        }
    }

    /// A `Flow` that *does* care about the raw request — standing in for a
    /// GNAP flow's key-proofing check (RFC 9635 §7.3), which must see the
    /// method, URI and exact body bytes rather than the parsed `FlowContext`.
    struct KeyProofedFlow;
    #[async_trait]
    impl Flow for KeyProofedFlow {
        fn id(&self) -> &str {
            "gnap-like"
        }
        async fn execute(&self, _ctx: FlowContext) -> Result<FlowResult, AuthError> {
            panic!("this flow only makes sense through execute_with_parts");
        }
        async fn execute_with_parts(
            &self,
            _ctx: FlowContext,
            parts: RequestParts<'_>,
        ) -> Result<FlowResult, AuthError> {
            if parts.method != http::Method::POST {
                return Err(AuthError::InvalidInput);
            }
            Ok(FlowResult::Document(serde_json::json!({
                "body_len": parts.body.len(),
            })))
        }
    }

    #[tokio::test]
    async fn execute_with_parts_override_sees_raw_request() {
        let flow = KeyProofedFlow;
        let ctx = FlowContext::new("s", HashMap::new());
        let method = http::Method::POST;
        let uri: http::Uri = "https://as.example/gnap".parse().unwrap();
        let headers = http::HeaderMap::new();
        let body = b"{\"hello\":true}";
        let parts = RequestParts {
            method: &method,
            uri: &uri,
            headers: &headers,
            body,
        };

        let result = flow.execute_with_parts(ctx, parts).await.unwrap();
        match result {
            FlowResult::Document(v) => assert_eq!(v["body_len"], body.len()),
            other => panic!("expected FlowResult::Document, got {other:?}"),
        }
    }
}
