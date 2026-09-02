//! The evaluation core: parse policies, ask the loader for entities, run Cedar, log the result.

use std::str::FromStr;
use std::sync::{Arc, RwLock};

use cedar_policy::{
    Authorizer, Context, PolicyId, PolicySet, Request, Schema, ValidationMode, Validator,
};

use crate::error::PolicyError;
use crate::loader::ResourceLoader;
use crate::request::{AuthorizationRequest, Decision};

/// Parse Cedar policy source text into a policy set, naming each policy after its `@id`
/// annotation where it has one.
///
/// **This deviates from `cedar_policy::PolicySet::from_str`**, which names policies `policy0`,
/// `policy1`, … by source order. Those ids are what come back in [`Decision::reasons`] and go
/// into audit logs, and they are positional: inserting a policy at the top of the file silently
/// renumbers every id below it, so yesterday's "denied by policy3" no longer refers to the same
/// rule. Honouring `@id("no-confidential-exports")` makes the diagnostic name the *rule*, which
/// survives reordering and a reload. Policies with no `@id` keep Cedar's generated id.
///
/// Two policies sharing one `@id` are rejected here rather than one silently displacing the
/// other.
///
/// Split out of the engine so that a caller can validate operator-supplied policy text (an admin
/// API, a config reload hook) *before* handing it to [`PolicyEngine::reload`] and having to
/// interpret a failure after the fact.
pub fn parse_policies(cedar_source: &str) -> Result<PolicySet, PolicyError> {
    let parsed = PolicySet::from_str(cedar_source)
        .map_err(|e| PolicyError::PolicyParse(format!("could not parse policy set: {e}")))?;

    let mut renamed = PolicySet::new();
    // Templates are carried over untouched: this crate does not link templates yet (see
    // RFC-005), but dropping them silently would be worse than not supporting them.
    for template in parsed.templates() {
        renamed.add_template(template.clone()).map_err(|e| {
            PolicyError::PolicyParse(format!("could not add template {}: {e}", template.id()))
        })?;
    }
    for policy in parsed.policies() {
        let policy = match policy.annotation("id") {
            Some(id) => policy.new_id(PolicyId::new(id)),
            None => policy.clone(),
        };
        let id = policy.id().clone();
        renamed.add(policy).map_err(|e| {
            PolicyError::PolicyParse(format!(
                "could not add policy {id}: {e} (is `@id(\"{id}\")` used twice?)"
            ))
        })?;
    }
    Ok(renamed)
}

/// Parse a Cedar schema in the human-readable Cedar schema format.
pub fn parse_schema(schema_source: &str) -> Result<Schema, PolicyError> {
    schema_source
        .parse::<Schema>()
        .map_err(|e| PolicyError::SchemaParse(format!("could not parse schema: {e}")))
}

/// Check a policy set against a schema, rejecting policies that can never apply.
fn validate(schema: &Schema, policies: &PolicySet) -> Result<(), PolicyError> {
    let result = Validator::new(schema.clone()).validate(policies, ValidationMode::Strict);
    if result.validation_passed() {
        return Ok(());
    }
    let errors = result
        .validation_errors()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    Err(PolicyError::Validation(errors))
}

/// Evaluates Cedar policies against entities supplied by a [`ResourceLoader`].
///
/// The engine owns three things and no more: the current policy set, an optional schema, and the
/// loader. It performs no I/O of its own — every byte of entity data arrives through
/// [`ResourceLoader::load_entities`], which is what makes authkestra#21's "no direct DB queries
/// from the engine" criterion structural rather than a convention someone has to remember.
///
/// `is_authorized` takes `&self`, and so does [`PolicyEngine::reload`]: an engine is meant to be
/// wrapped in an `Arc` and shared by every request handler, with policy updates applied in place.
pub struct PolicyEngine {
    /// `RwLock<Arc<PolicySet>>` rather than `RwLock<PolicySet>` so that evaluation clones an
    /// `Arc` under the lock and releases it immediately — the (potentially long) `await` on the
    /// loader and the Cedar evaluation both happen with no lock held. `arc_swap` would do the
    /// same job; the std lock avoids a dependency for a swap that happens once per policy
    /// deploy, not once per request.
    policies: RwLock<Arc<PolicySet>>,
    schema: Option<Schema>,
    loader: Box<dyn ResourceLoader>,
    authorizer: Authorizer,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("policies", &self.policy_count())
            .field("schema", &self.schema.is_some())
            .finish_non_exhaustive()
    }
}

impl PolicyEngine {
    /// Start building an engine.
    pub fn builder() -> PolicyEngineBuilder {
        PolicyEngineBuilder::default()
    }

    /// The current policy set. Cloning the `Arc` is what keeps the read lock's scope to a single
    /// statement.
    fn current_policies(&self) -> Arc<PolicySet> {
        // Poison recovery: the policy set behind the lock is immutable once published (it is
        // only ever replaced wholesale), so a panic in an unrelated task cannot have left it
        // inconsistent. Failing every authorization afterwards would be strictly worse.
        Arc::clone(&self.policies.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// How many policies are currently loaded.
    pub fn policy_count(&self) -> usize {
        self.current_policies().policies().count()
    }

    /// Whether a schema is configured (and therefore whether policy loads are validated).
    pub fn has_schema(&self) -> bool {
        self.schema.is_some()
    }

    /// Replace the policy set from Cedar source text, atomically.
    ///
    /// Failure is total and leaves the previous policy set serving traffic: the new text is
    /// parsed and (if a schema is configured) validated *before* the write lock is taken, so a
    /// typo in an operator's policy update can never leave the engine with an empty or partial
    /// policy set. That property is the reason this is one call rather than
    /// `clear()` + `add()`.
    ///
    /// In-flight requests that already cloned the old `Arc` finish against the old policies;
    /// every request that starts after this returns sees the new ones.
    pub fn reload(&self, cedar_source: &str) -> Result<(), PolicyError> {
        let policies = parse_policies(cedar_source).inspect_err(|e| {
            tracing::warn!(
                error = %e,
                "policy reload rejected: keeping the previously loaded policy set"
            );
        })?;
        self.reload_policy_set(policies)
    }

    /// [`PolicyEngine::reload`] for an already-parsed policy set (e.g. one assembled from
    /// several files, or from Cedar's JSON policy format).
    ///
    /// Policy ids are taken exactly as the caller built them — the `@id` handling described on
    /// [`parse_policies`] only applies to source text this crate parses itself.
    pub fn reload_policy_set(&self, policies: PolicySet) -> Result<(), PolicyError> {
        if let Some(schema) = &self.schema {
            validate(schema, &policies).inspect_err(|e| {
                tracing::warn!(
                    error = %e,
                    "policy reload failed schema validation: keeping the previously loaded policy set"
                );
            })?;
        }

        let count = policies.policies().count();
        {
            let mut guard = self.policies.write().unwrap_or_else(|e| e.into_inner());
            *guard = Arc::new(policies);
        }
        tracing::info!(policy_count = count, "policy set reloaded");
        Ok(())
    }

    /// Decide one request.
    ///
    /// Returns `Err` only when the question could not be *asked* (a malformed context, a loader
    /// failure); a policy saying "no" is `Ok` with [`Decision::is_allowed`] `== false`.
    pub async fn is_authorized(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<Decision, PolicyError> {
        let policies = self.current_policies();

        let entities = self.loader.load_entities(request).await.inspect_err(|e| {
            tracing::warn!(
                error = %e,
                principal = %request.principal,
                action = %request.action,
                resource = %request.resource,
                "resource loader failed; no authorization decision was made"
            );
        })?;

        // The context is type-checked against the schema for *this action* when one is
        // configured, which is what turns a typo'd context key into a rejected request instead
        // of a silently unsatisfied `when` clause.
        let context = Context::from_json_value(
            request.context.clone(),
            self.schema.as_ref().map(|s| (s, &request.action)),
        )
        .map_err(|e| PolicyError::InvalidRequest(format!("invalid context: {e}")))?;

        let cedar_request = Request::new(
            request.principal.clone(),
            request.action.clone(),
            request.resource.clone(),
            context,
            self.schema.as_ref(),
        )
        .map_err(|e| PolicyError::InvalidRequest(format!("request rejected by schema: {e}")))?;

        let response = self
            .authorizer
            .is_authorized(&cedar_request, &policies, &entities);

        let allowed = matches!(response.decision(), cedar_policy::Decision::Allow);
        let reasons: Vec<String> = response
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect();
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect();

        for error in &errors {
            // Not fatal — Cedar skips the erroring policy and keeps going — but it means the
            // decision was made on a subset of the policy set, which an operator must be able to
            // see without a redeploy.
            tracing::warn!(
                error = %error,
                principal = %request.principal,
                action = %request.action,
                resource = %request.resource,
                "policy evaluation error; that policy did not contribute to the decision"
            );
        }

        tracing::debug!(
            allowed,
            principal = %request.principal,
            action = %request.action,
            resource = %request.resource,
            reasons = %reasons.join(","),
            policy_count = policies.policies().count(),
            "policy decision"
        );

        Ok(Decision::new(allowed, reasons, errors))
    }
}

/// Builder for [`PolicyEngine`].
#[derive(Default)]
#[non_exhaustive]
pub struct PolicyEngineBuilder {
    policies: Option<Result<PolicySet, PolicyError>>,
    schema: Option<Result<Schema, PolicyError>>,
    loader: Option<Box<dyn ResourceLoader>>,
}

impl std::fmt::Debug for PolicyEngineBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEngineBuilder")
            .field("has_policies", &self.policies.is_some())
            .field("has_schema", &self.schema.is_some())
            .field("has_loader", &self.loader.is_some())
            .finish_non_exhaustive()
    }
}

impl PolicyEngineBuilder {
    /// Set the policy set from Cedar source text.
    pub fn policies(mut self, cedar_source: &str) -> Self {
        self.policies = Some(parse_policies(cedar_source));
        self
    }

    /// Set an already-parsed policy set.
    pub fn policy_set(mut self, policies: PolicySet) -> Self {
        self.policies = Some(Ok(policies));
        self
    }

    /// Set the schema from Cedar schema source text.
    ///
    /// Supplying one is optional, and doing so switches policy loading from "parses" to
    /// "parses *and* validates" — see [`PolicyEngineBuilder::build`].
    pub fn schema(mut self, schema_source: &str) -> Self {
        self.schema = Some(parse_schema(schema_source));
        self
    }

    /// Set an already-parsed schema.
    pub fn schema_parsed(mut self, schema: Schema) -> Self {
        self.schema = Some(Ok(schema));
        self
    }

    /// Set the resource loader.
    pub fn loader<L>(mut self, loader: L) -> Self
    where
        L: ResourceLoader + 'static,
    {
        self.loader = Some(Box::new(loader));
        self
    }

    /// Set an already-boxed resource loader, for callers that select one at runtime.
    pub fn boxed_loader(mut self, loader: Box<dyn ResourceLoader>) -> Self {
        self.loader = Some(loader);
        self
    }

    /// Build the engine.
    ///
    /// When a schema was supplied, the policy set is validated against it here and an invalid
    /// policy is rejected at *load* time rather than silently never matching at request time.
    /// Whether that validation should be mandatory rather than opt-in is left open — see the
    /// "maintainer decisions" section of `docs/rfc-005-policy-engine.md`.
    pub fn build(self) -> Result<PolicyEngine, PolicyError> {
        let policies = self.policies.unwrap_or_else(|| {
            Err(PolicyError::Configuration(
                "policy engine requires a policy set: call .policies(..) or .policy_set(..)".into(),
            ))
        })?;
        let schema = self.schema.transpose()?;
        let loader = self.loader.ok_or_else(|| {
            PolicyError::Configuration(
                "policy engine requires a resource loader: call .loader(..)".into(),
            )
        })?;

        if let Some(schema) = &schema {
            validate(schema, &policies)?;
        }

        tracing::debug!(
            policy_count = policies.policies().count(),
            schema = schema.is_some(),
            "policy engine built"
        );

        Ok(PolicyEngine {
            policies: RwLock::new(Arc::new(policies)),
            schema,
            loader,
            authorizer: Authorizer::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::StaticResourceLoader;

    #[test]
    fn engine_is_shareable_across_tasks() {
        fn assert_send_sync<T: Send + Sync>() {}
        // The whole design assumes one `Arc<PolicyEngine>` behind every handler; if this ever
        // stops holding, the extractor integration in RFC-005 stops being possible.
        assert_send_sync::<PolicyEngine>();
    }

    #[test]
    fn build_requires_a_policy_set() {
        let error = PolicyEngine::builder()
            .loader(StaticResourceLoader::empty())
            .build()
            .expect_err("no policies were supplied");
        assert_eq!(error.code(), "configuration");
        assert!(error.to_string().contains("policy set"), "{error}");
    }

    #[test]
    fn build_requires_a_loader() {
        let error = PolicyEngine::builder()
            .policies("permit(principal, action, resource);")
            .build()
            .expect_err("no loader was supplied");
        assert_eq!(error.code(), "configuration");
        assert!(error.to_string().contains("resource loader"), "{error}");
    }

    #[test]
    fn build_reports_a_policy_parse_error() {
        let error = PolicyEngine::builder()
            .policies("permit(principal") // truncated
            .loader(StaticResourceLoader::empty())
            .build()
            .expect_err("policy source does not parse");
        assert_eq!(error.code(), "policy_parse");
    }

    #[test]
    fn build_reports_a_schema_parse_error() {
        let error = PolicyEngine::builder()
            .policies("permit(principal, action, resource);")
            .schema("entity User {")
            .loader(StaticResourceLoader::empty())
            .build()
            .expect_err("schema source does not parse");
        assert_eq!(error.code(), "schema_parse");
    }

    #[test]
    fn accepts_pre_parsed_policies_and_schema() {
        let policies = parse_policies("permit(principal, action, resource);").expect("parses");
        let schema = parse_schema(
            r#"entity User; entity Doc; action view appliesTo { principal: [User], resource: [Doc] };"#,
        )
        .expect("parses");
        let engine = PolicyEngine::builder()
            .policy_set(policies)
            .schema_parsed(schema)
            .boxed_loader(Box::new(StaticResourceLoader::empty()))
            .build()
            .expect("engine builds");

        assert_eq!(engine.policy_count(), 1);
        assert!(engine.has_schema());
        assert!(format!("{engine:?}").contains("PolicyEngine"));
    }

    #[test]
    fn policies_are_named_after_their_id_annotation() {
        let policies = parse_policies(
            r#"
            @id("admins-may-do-anything")
            permit(principal in Group::"admin", action, resource);

            permit(principal, action == Action::"read", resource);
            "#,
        )
        .expect("parses");

        let ids: Vec<String> = policies.policies().map(|p| p.id().to_string()).collect();
        assert!(
            ids.contains(&"admins-may-do-anything".to_string()),
            "{ids:?}"
        );
        // The un-annotated policy keeps Cedar's positional id.
        assert!(ids.contains(&"policy1".to_string()), "{ids:?}");
    }

    #[test]
    fn a_duplicated_id_annotation_is_rejected() {
        let error = parse_policies(
            r#"
            @id("same")
            permit(principal, action, resource);

            @id("same")
            forbid(principal, action, resource);
            "#,
        )
        .expect_err("two policies claim the same id");
        assert_eq!(error.code(), "policy_parse");
        assert!(error.to_string().contains("same"), "{error}");
    }

    #[test]
    fn templates_survive_parsing() {
        // Not linked by this crate yet, but they must not be silently dropped by the `@id`
        // rewrite above.
        let policies = parse_policies(
            r#"permit(principal == ?principal, action == Action::"read", resource);"#,
        )
        .expect("parses");
        assert_eq!(policies.templates().count(), 1);
        assert_eq!(policies.policies().count(), 0);
    }

    #[test]
    fn builder_debug_reports_which_parts_are_set() {
        let builder = PolicyEngine::builder().policies("permit(principal, action, resource);");
        let rendered = format!("{builder:?}");
        assert!(rendered.contains("has_policies: true"), "{rendered}");
        assert!(rendered.contains("has_loader: false"), "{rendered}");
    }
}
