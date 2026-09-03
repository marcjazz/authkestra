//! Failure modes of the Cedar policy engine.
//!
//! Every variant carries its detail as a pre-rendered `String` rather than the originating
//! `cedar_policy` error type. That is deliberate: Cedar's error enums are `#[non_exhaustive]`
//! and change shape between minor releases, so re-exporting them through *our* public API would
//! make a `cedar-policy` point upgrade a breaking change for every downstream caller. The one
//! exception is [`PolicyError::Loader`], which keeps the caller's own error as a `source` —
//! there the caller owns the type, so nothing of ours is coupled to it.

use thiserror::Error;

/// Why a policy could not be loaded, or a request could not be decided.
///
/// Note what is *not* here: "denied". A deny is a successful evaluation
/// ([`crate::Decision::is_allowed`] returning `false`), never an error. Callers that treat any
/// `Err` as a deny still fail closed, but they lose the ability to distinguish "the policies say
/// no" from "the entity store was unreachable" — which is exactly the distinction an operator
/// needs at 3am.
///
/// One variant is a refusal rather than a failure: [`PolicyError::UnreliableDecision`] means
/// evaluation *succeeded* and produced `Allow`, but a `forbid` was skipped along the way, so
/// that `Allow` is not answerable.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// The Cedar policy source text could not be parsed into a `PolicySet`.
    #[error("policy_parse: {0}")]
    PolicyParse(String),

    /// The Cedar schema source could not be parsed.
    #[error("schema_parse: {0}")]
    SchemaParse(String),

    /// A policy's `@id` annotation claims a name Cedar reserves for its own positional ids
    /// (`policy0`, `policy1`, …).
    ///
    /// Its own variant rather than a [`PolicyError::PolicyParse`] because the policy text is
    /// perfectly well-formed — the *name* is the problem, and an admin API accepting
    /// operator-authored policies wants to say so precisely.
    #[error("reserved_policy_id: `@id(\"{0}\")` is reserved: Cedar names un-annotated policies `policy0`, `policy1`, … by source position, so an explicit id of that shape would collide with whichever policy happens to land on that line")]
    ReservedPolicyId(String),

    /// The policy set parsed, but does not validate against the configured schema (e.g. it
    /// references an entity type or action the schema does not declare).
    #[error("validation: {0}")]
    Validation(String),

    /// The request could not be turned into a Cedar request: a malformed entity UID, a context
    /// that is not a JSON object, or — when a schema is configured — a principal/action/resource
    /// combination the schema forbids.
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    /// A `forbid` policy could not be evaluated, so an `Allow` cannot be trusted.
    ///
    /// Cedar *skips* a policy that raises an evaluation error (a missing attribute, a type
    /// error) and finishes the request with the remaining ones. For a skipped `permit` that is
    /// harmless — the worst case is an Allow you were not going to get anyway. For a skipped
    /// `forbid` it is a **fail-open**: the one rule that would have denied the request never
    /// ran, and the caller is handed a plain `Allow` with no signal that anything went wrong.
    ///
    /// So this crate refuses to answer instead. The rule is:
    ///
    /// - `Allow` + an errored `forbid` → this error;
    /// - `Allow` + errored `permit`s only → the `Allow` stands (some *other* permit matched),
    ///   with the errors still listed in [`crate::Decision::errors`];
    /// - `Deny` + any errors → still a `Deny`, since no skipped policy could have turned a Deny
    ///   into an Allow.
    ///
    /// An errored policy whose id cannot be resolved back to a policy in the current set counts
    /// as a `forbid`: it cannot be *proven* harmless, so it fails closed.
    #[error("unreliable_decision: a forbid policy could not be evaluated, so Allow cannot be trusted: {}", errors.join("; "))]
    UnreliableDecision {
        /// Every evaluation error Cedar reported for this request, not only the `forbid` ones,
        /// so an operator sees the whole picture in one place.
        errors: Vec<String>,
    },

    /// The entity set returned by a [`crate::ResourceLoader`] could not be assembled (duplicate
    /// UIDs, an attribute that is not a valid restricted expression, or a schema mismatch).
    #[error("entities: {0}")]
    Entities(String),

    /// The [`crate::ResourceLoader`] itself failed — the storage behind it was unreachable, the
    /// query timed out, and so on. The engine never talks to storage directly, so this is the
    /// only way a storage fault can reach it.
    #[error("loader: {0}")]
    Loader(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The engine was built without a mandatory component, or a request was built without one of
    /// principal/action/resource.
    #[error("configuration: {0}")]
    Configuration(String),
}

impl PolicyError {
    /// A machine-readable code (e.g. `"policy_parse"`), stable across rewording of the
    /// `Display` messages. Suitable for metrics labels and structured log fields.
    pub fn code(&self) -> &'static str {
        match self {
            PolicyError::PolicyParse(_) => "policy_parse",
            PolicyError::SchemaParse(_) => "schema_parse",
            PolicyError::ReservedPolicyId(_) => "reserved_policy_id",
            PolicyError::Validation(_) => "validation",
            PolicyError::InvalidRequest(_) => "invalid_request",
            PolicyError::UnreliableDecision { .. } => "unreliable_decision",
            PolicyError::Entities(_) => "entities",
            PolicyError::Loader(_) => "loader",
            PolicyError::Configuration(_) => "configuration",
        }
    }

    /// Wrap a caller-side error (a database failure, an HTTP failure, …) as a
    /// [`PolicyError::Loader`].
    pub fn loader<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        PolicyError::Loader(Box::new(error))
    }

    /// Wrap a bare message as a [`PolicyError::Loader`], for loaders whose failure is not itself
    /// an `Error` (a missing row, a tenant with no entities provisioned, …).
    pub fn loader_msg(message: impl Into<String>) -> Self {
        PolicyError::Loader(message.into().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_and_distinct() {
        let errors = [
            PolicyError::PolicyParse("x".into()),
            PolicyError::SchemaParse("x".into()),
            PolicyError::ReservedPolicyId("policy0".into()),
            PolicyError::Validation("x".into()),
            PolicyError::InvalidRequest("x".into()),
            PolicyError::UnreliableDecision {
                errors: vec!["x".into()],
            },
            PolicyError::Entities("x".into()),
            PolicyError::loader_msg("x"),
            PolicyError::Configuration("x".into()),
        ];
        let codes: Vec<_> = errors.iter().map(PolicyError::code).collect();
        assert_eq!(
            codes,
            [
                "policy_parse",
                "schema_parse",
                "reserved_policy_id",
                "validation",
                "invalid_request",
                "unreliable_decision",
                "entities",
                "loader",
                "configuration",
            ]
        );
        // Every message is prefixed with its own code, so a log line carries the code even when
        // only the `Display` form is recorded.
        for (error, code) in errors.iter().zip(codes) {
            assert!(error.to_string().starts_with(code), "{error}");
        }
    }

    #[test]
    fn loader_keeps_the_callers_error_as_source() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "db is down");
        let error = PolicyError::loader(io);
        assert_eq!(error.code(), "loader");
        let source = std::error::Error::source(&error).expect("loader error keeps its source");
        assert!(source.to_string().contains("db is down"));
    }
}
