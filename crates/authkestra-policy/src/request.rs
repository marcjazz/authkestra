//! The framework-side authorization request, and the decision that comes back.
//!
//! [`AuthorizationRequest`] is intentionally *not* `cedar_policy::Request`: it keeps its context
//! as a plain `serde_json::Value` so that a caller can assemble it from token claims, HTTP
//! metadata, or a request body without first learning Cedar's `RestrictedExpression` API. The
//! conversion to a Cedar request happens inside [`crate::PolicyEngine::is_authorized`], where
//! the schema (if any) is available to type-check the context.

use cedar_policy::EntityUid;
use std::str::FromStr;

use crate::error::PolicyError;

/// Parse a Cedar entity UID such as `User::"alice"` or `MyApp::Document::"42"`.
///
/// Exposed because callers building an [`AuthorizationRequest`] from string identifiers (a `sub`
/// claim, a path parameter) need it, and it maps Cedar's parse error onto [`PolicyError`] so
/// that request construction and evaluation share one error type.
pub fn parse_entity_uid(uid: &str) -> Result<EntityUid, PolicyError> {
    EntityUid::from_str(uid)
        .map_err(|e| PolicyError::InvalidRequest(format!("invalid entity uid `{uid}`: {e}")))
}

/// A single authorization question: may `principal` do `action` to `resource`, given `context`?
///
/// No `Eq`: the context is a `serde_json::Value`, which is only `PartialEq` (JSON numbers may be
/// floats).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct AuthorizationRequest {
    /// Who is asking — typically derived from the authenticated identity.
    pub principal: EntityUid,
    /// What they want to do, e.g. `Action::"viewDocument"`.
    pub action: EntityUid,
    /// What they want to do it to.
    pub resource: EntityUid,
    /// Free-form request context (IP, MFA state, time of day, request body fields …). Must be a
    /// JSON *object*; anything else is rejected at evaluation time by Cedar.
    pub context: serde_json::Value,
}

impl AuthorizationRequest {
    /// A request with an empty context.
    pub fn new(principal: EntityUid, action: EntityUid, resource: EntityUid) -> Self {
        Self {
            principal,
            action,
            resource,
            context: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    /// Start building a request from string UIDs and/or a JSON context.
    pub fn builder() -> AuthorizationRequestBuilder {
        AuthorizationRequestBuilder::default()
    }
}

/// Builder for [`AuthorizationRequest`].
///
/// Parse failures are captured and surfaced from [`AuthorizationRequestBuilder::build`] rather
/// than from each setter, so that a caller can write one straight-line chain and handle a single
/// `Result` — the same shape the rest of the workspace's builders use.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct AuthorizationRequestBuilder {
    principal: Option<Result<EntityUid, PolicyError>>,
    action: Option<Result<EntityUid, PolicyError>>,
    resource: Option<Result<EntityUid, PolicyError>>,
    context: Option<serde_json::Value>,
}

impl AuthorizationRequestBuilder {
    /// Set the principal from an already-parsed UID.
    pub fn principal(mut self, principal: EntityUid) -> Self {
        self.principal = Some(Ok(principal));
        self
    }

    /// Set the principal from Cedar UID source text, e.g. `User::"alice"`.
    pub fn principal_str(mut self, principal: &str) -> Self {
        self.principal = Some(parse_entity_uid(principal));
        self
    }

    /// Set the action from an already-parsed UID.
    pub fn action(mut self, action: EntityUid) -> Self {
        self.action = Some(Ok(action));
        self
    }

    /// Set the action from Cedar UID source text, e.g. `Action::"view"`.
    pub fn action_str(mut self, action: &str) -> Self {
        self.action = Some(parse_entity_uid(action));
        self
    }

    /// Set the resource from an already-parsed UID.
    pub fn resource(mut self, resource: EntityUid) -> Self {
        self.resource = Some(Ok(resource));
        self
    }

    /// Set the resource from Cedar UID source text, e.g. `Document::"42"`.
    pub fn resource_str(mut self, resource: &str) -> Self {
        self.resource = Some(parse_entity_uid(resource));
        self
    }

    /// Set the request context. Must be a JSON object.
    pub fn context(mut self, context: serde_json::Value) -> Self {
        self.context = Some(context);
        self
    }

    /// Finish the request, or report the first missing/unparsable field.
    pub fn build(self) -> Result<AuthorizationRequest, PolicyError> {
        fn take(
            field: Option<Result<EntityUid, PolicyError>>,
            name: &str,
        ) -> Result<EntityUid, PolicyError> {
            field.unwrap_or_else(|| {
                Err(PolicyError::Configuration(format!(
                    "authorization request is missing its {name}"
                )))
            })
        }

        Ok(AuthorizationRequest {
            principal: take(self.principal, "principal")?,
            action: take(self.action, "action")?,
            resource: take(self.resource, "resource")?,
            context: self
                .context
                .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())),
        })
    }
}

/// The outcome of evaluating one [`AuthorizationRequest`].
///
/// The diagnostics are carried as `String`s rather than `cedar_policy::PolicyId` /
/// `AuthorizationError` for the same API-stability reason described on [`PolicyError`], and
/// because both are headed for a log line or an audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Decision {
    allowed: bool,
    reasons: Vec<String>,
    errors: Vec<String>,
}

impl Decision {
    /// Construct a decision. Public so that callers can fake one in their own tests without
    /// standing up an engine.
    pub fn new(allowed: bool, reasons: Vec<String>, errors: Vec<String>) -> Self {
        Self {
            allowed,
            reasons,
            errors,
        }
    }

    /// `true` only for an explicit Cedar `Allow`. Cedar is deny-by-default: no matching `permit`
    /// means `false`, and any matching `forbid` wins over every `permit`.
    pub fn is_allowed(&self) -> bool {
        self.allowed
    }

    /// The ids of the policies that determined this decision — the satisfied `forbid`s for a
    /// deny, the satisfied `permit`s for an allow. Empty on a default deny, which is precisely
    /// how "no policy matched" is distinguished from "a forbid matched".
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }

    /// Errors raised while evaluating individual policies (a missing attribute, a type error).
    ///
    /// A non-empty list alongside an allow or a deny means *some policies did not evaluate*, so
    /// the decision was made on a subset of the policy set. Cedar's default error handling skips
    /// the erroring policy and continues; the engine logs each one at `warn`.
    pub fn errors(&self) -> &[String] {
        &self.errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_accepts_string_uids_and_defaults_the_context() {
        let request = AuthorizationRequest::builder()
            .principal_str(r#"User::"alice""#)
            .action_str(r#"Action::"view""#)
            .resource_str(r#"Document::"readme""#)
            .build()
            .expect("valid request");

        assert_eq!(request.principal.to_string(), r#"User::"alice""#);
        assert_eq!(request.action.to_string(), r#"Action::"view""#);
        assert_eq!(request.resource.to_string(), r#"Document::"readme""#);
        assert_eq!(request.context, serde_json::json!({}));
    }

    #[test]
    fn builder_accepts_parsed_uids_and_a_context() {
        let request = AuthorizationRequest::builder()
            .principal(parse_entity_uid(r#"User::"bob""#).expect("uid"))
            .action(parse_entity_uid(r#"Action::"edit""#).expect("uid"))
            .resource(parse_entity_uid(r#"Document::"notes""#).expect("uid"))
            .context(serde_json::json!({ "mfa": true }))
            .build()
            .expect("valid request");

        assert_eq!(request.context, serde_json::json!({ "mfa": true }));
    }

    #[test]
    fn new_defaults_to_an_empty_context() {
        let request = AuthorizationRequest::new(
            parse_entity_uid(r#"User::"bob""#).expect("uid"),
            parse_entity_uid(r#"Action::"edit""#).expect("uid"),
            parse_entity_uid(r#"Document::"notes""#).expect("uid"),
        );
        assert_eq!(request.context, serde_json::json!({}));
    }

    #[test]
    fn builder_reports_a_missing_field() {
        let error = AuthorizationRequest::builder()
            .principal_str(r#"User::"alice""#)
            .build()
            .expect_err("action and resource are missing");
        assert_eq!(error.code(), "configuration");
        assert!(error.to_string().contains("action"), "{error}");
    }

    #[test]
    fn builder_reports_an_unparsable_uid() {
        let error = AuthorizationRequest::builder()
            .principal_str("not a uid")
            .action_str(r#"Action::"view""#)
            .resource_str(r#"Document::"readme""#)
            .build()
            .expect_err("principal does not parse");
        assert_eq!(error.code(), "invalid_request");
    }

    #[test]
    fn decision_exposes_its_diagnostics() {
        let decision = Decision::new(false, vec!["forbid-pii".into()], vec!["boom".into()]);
        assert!(!decision.is_allowed());
        assert_eq!(decision.reasons(), ["forbid-pii"]);
        assert_eq!(decision.errors(), ["boom"]);
    }
}
