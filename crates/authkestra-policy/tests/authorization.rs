//! End-to-end behaviour of the Cedar proof of concept, from the outside of the crate.
//!
//! These cover the acceptance criteria of
//! [authkestra#21](https://github.com/marcjazz/authkestra/issues/21): that Cedar policies are
//! actually evaluated, that the engine reaches data only through a [`ResourceLoader`], and that
//! policies can be replaced at runtime — including the failure case, where a bad update must
//! *not* take the old policies out of service.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use authkestra_policy::cedar_policy::{Entities, RestrictedExpression};
use authkestra_policy::{
    parse_entity_uid, AuthorizationRequest, EntityRecord, MemoryResourceLoader, PolicyEngine,
    PolicyError, ResourceLoader, StaticResourceLoader,
};

/// A small RBAC world: alice is an engineer, bob is not, and two documents are owned by the
/// engineering group and the sales group respectively.
fn rbac_loader() -> MemoryResourceLoader {
    let loader = MemoryResourceLoader::new();
    loader.extend([
        EntityRecord::new(uid(r#"User::"alice""#)).parent(uid(r#"Group::"eng""#)),
        EntityRecord::new(uid(r#"User::"bob""#)).parent(uid(r#"Group::"sales""#)),
        EntityRecord::new(uid(r#"Group::"eng""#)),
        EntityRecord::new(uid(r#"Group::"sales""#)),
        EntityRecord::new(uid(r#"Doc::"design""#)).attribute(
            "owner",
            RestrictedExpression::new_entity_uid(uid(r#"Group::"eng""#)),
        ),
        EntityRecord::new(uid(r#"Doc::"pricing""#))
            .attribute(
                "owner",
                RestrictedExpression::new_entity_uid(uid(r#"Group::"sales""#)),
            )
            .attribute("confidential", RestrictedExpression::new_bool(true)),
    ]);
    loader
}

fn uid(source: &str) -> authkestra_policy::cedar_policy::EntityUid {
    parse_entity_uid(source).expect("valid entity uid")
}

fn request(principal: &str, action: &str, resource: &str) -> AuthorizationRequest {
    AuthorizationRequest::builder()
        .principal_str(principal)
        .action_str(action)
        .resource_str(resource)
        .build()
        .expect("valid request")
}

const OWNER_POLICY: &str = r#"
    @id("eng-reads-own-docs")
    permit(principal in Group::"eng", action == Action::"read", resource)
    when { resource.owner == Group::"eng" };
"#;

#[tokio::test]
async fn allows_a_request_matching_a_permit() {
    let engine = PolicyEngine::builder()
        .policies(OWNER_POLICY)
        .loader(rbac_loader())
        .build()
        .expect("engine builds");

    let decision = engine
        .is_authorized(&request(
            r#"User::"alice""#,
            r#"Action::"read""#,
            r#"Doc::"design""#,
        ))
        .await
        .expect("evaluation succeeds");

    assert!(decision.is_allowed());
    assert_eq!(decision.reasons(), ["eng-reads-own-docs"]);
    assert!(decision.errors().is_empty());
}

#[tokio::test]
async fn denies_by_default_when_no_permit_matches() {
    let engine = PolicyEngine::builder()
        .policies(OWNER_POLICY)
        .loader(rbac_loader())
        .build()
        .expect("engine builds");

    // bob is in sales, so the `principal in Group::"eng"` scope does not match.
    let decision = engine
        .is_authorized(&request(
            r#"User::"bob""#,
            r#"Action::"read""#,
            r#"Doc::"design""#,
        ))
        .await
        .expect("evaluation succeeds");

    assert!(!decision.is_allowed());
    // A default deny names no policy — this is what distinguishes it from a forbid.
    assert!(decision.reasons().is_empty(), "{:?}", decision.reasons());
}

#[tokio::test]
async fn a_permit_condition_reads_the_request_context() {
    let policy = r#"
        @id("read-with-mfa")
        permit(principal, action == Action::"read", resource)
        when { context.mfa == true };
    "#;
    let engine = PolicyEngine::builder()
        .policies(policy)
        .loader(rbac_loader())
        .build()
        .expect("engine builds");

    let mut with_mfa = request(r#"User::"alice""#, r#"Action::"read""#, r#"Doc::"design""#);
    with_mfa.context = serde_json::json!({ "mfa": true });
    assert!(engine
        .is_authorized(&with_mfa)
        .await
        .expect("evaluation succeeds")
        .is_allowed());

    let mut without_mfa = with_mfa.clone();
    without_mfa.context = serde_json::json!({ "mfa": false });
    assert!(!engine
        .is_authorized(&without_mfa)
        .await
        .expect("evaluation succeeds")
        .is_allowed());
}

#[tokio::test]
async fn a_forbid_overrides_a_matching_permit() {
    let policy = format!(
        r#"
        {OWNER_POLICY}

        @id("no-confidential-without-mfa")
        forbid(principal, action, resource)
        when {{ resource has confidential && resource.confidential }}
        unless {{ context has mfa && context.mfa == true }};

        @id("anyone-reads-anything")
        permit(principal, action == Action::"read", resource);
        "#
    );
    let engine = PolicyEngine::builder()
        .policies(&policy)
        .loader(rbac_loader())
        .build()
        .expect("engine builds");

    let mut req = request(r#"User::"bob""#, r#"Action::"read""#, r#"Doc::"pricing""#);

    // The permit matches, but the forbid wins: Cedar is forbid-overrides-permit.
    let denied = engine
        .is_authorized(&req)
        .await
        .expect("evaluation succeeds");
    assert!(!denied.is_allowed());
    assert_eq!(denied.reasons(), ["no-confidential-without-mfa"]);

    // With MFA the forbid's `unless` clause holds, so only the permit remains.
    req.context = serde_json::json!({ "mfa": true });
    let allowed = engine
        .is_authorized(&req)
        .await
        .expect("evaluation succeeds");
    assert!(allowed.is_allowed());
    assert_eq!(allowed.reasons(), ["anyone-reads-anything"]);
}

#[tokio::test]
async fn an_unknown_principal_is_denied_with_diagnostics() {
    // `mallory` exists in no entity store, so she is in no group and has no attributes. Cedar
    // does not error on that: she simply matches no permit.
    let engine = PolicyEngine::builder()
        .policies(OWNER_POLICY)
        .loader(rbac_loader())
        .build()
        .expect("engine builds");

    let decision = engine
        .is_authorized(&request(
            r#"User::"mallory""#,
            r#"Action::"read""#,
            r#"Doc::"design""#,
        ))
        .await
        .expect("evaluation succeeds");

    assert!(!decision.is_allowed());
    assert!(decision.reasons().is_empty());
    assert!(decision.errors().is_empty());
}

#[tokio::test]
async fn a_policy_reading_a_missing_attribute_reports_an_evaluation_error() {
    // `Doc::"design"` has no `confidential` attribute, and this policy reads it without a `has`
    // guard: Cedar records an evaluation error, skips the policy, and the request falls through
    // to the default deny. The error must reach the caller — a policy that never runs is a
    // silent hole in the rule set.
    let engine = PolicyEngine::builder()
        .policies(r#"permit(principal, action, resource) when { resource.confidential };"#)
        .loader(rbac_loader())
        .build()
        .expect("engine builds");

    let decision = engine
        .is_authorized(&request(
            r#"User::"alice""#,
            r#"Action::"read""#,
            r#"Doc::"design""#,
        ))
        .await
        .expect("evaluation succeeds");

    assert!(!decision.is_allowed());
    assert_eq!(decision.errors().len(), 1, "{:?}", decision.errors());
}

const SCHEMA: &str = r#"
    entity User in [Group];
    entity Group;
    entity Doc { owner: Group };
    action read appliesTo { principal: [User], resource: [Doc] };
"#;

#[tokio::test]
async fn schema_validation_rejects_an_invalid_policy_at_load() {
    // `Action::"delete"` is not declared by the schema, so this policy could never match. With a
    // schema configured that is a load-time failure rather than a rule that silently never fires.
    let error = PolicyEngine::builder()
        .policies(r#"permit(principal, action == Action::"delete", resource);"#)
        .schema(SCHEMA)
        .loader(rbac_loader())
        .build()
        .expect_err("the policy does not validate against the schema");

    assert_eq!(error.code(), "validation");
}

#[tokio::test]
async fn a_schema_validated_engine_still_decides_requests() {
    let engine = PolicyEngine::builder()
        .policies(OWNER_POLICY)
        .schema(SCHEMA)
        .loader(rbac_loader())
        .build()
        .expect("valid policy against the schema");

    assert!(engine.has_schema());
    assert!(engine
        .is_authorized(&request(
            r#"User::"alice""#,
            r#"Action::"read""#,
            r#"Doc::"design""#,
        ))
        .await
        .expect("evaluation succeeds")
        .is_allowed());
}

#[tokio::test]
async fn a_schema_rejects_a_request_it_does_not_describe() {
    let engine = PolicyEngine::builder()
        .policies(OWNER_POLICY)
        .schema(SCHEMA)
        .loader(rbac_loader())
        .build()
        .expect("engine builds");

    // The schema says `read` applies to a `Doc` resource, not to a `Group`.
    let error = engine
        .is_authorized(&request(
            r#"User::"alice""#,
            r#"Action::"read""#,
            r#"Group::"eng""#,
        ))
        .await
        .expect_err("the request does not conform to the schema");

    assert_eq!(error.code(), "invalid_request");
}

#[tokio::test]
async fn reload_with_a_bad_policy_keeps_the_previous_policy_set() {
    let engine = PolicyEngine::builder()
        .policies(OWNER_POLICY)
        .loader(rbac_loader())
        .build()
        .expect("engine builds");
    let allowed = request(r#"User::"alice""#, r#"Action::"read""#, r#"Doc::"design""#);
    assert!(engine
        .is_authorized(&allowed)
        .await
        .expect("evaluation succeeds")
        .is_allowed());

    let error = engine
        .reload("permit(principal, action")
        .expect_err("truncated policy source");
    assert_eq!(error.code(), "policy_parse");

    // Still one policy, still the old one, still allowing.
    assert_eq!(engine.policy_count(), 1);
    let decision = engine
        .is_authorized(&allowed)
        .await
        .expect("evaluation succeeds");
    assert!(decision.is_allowed());
    assert_eq!(decision.reasons(), ["eng-reads-own-docs"]);
}

#[tokio::test]
async fn reload_that_fails_validation_keeps_the_previous_policy_set() {
    let engine = PolicyEngine::builder()
        .policies(OWNER_POLICY)
        .schema(SCHEMA)
        .loader(rbac_loader())
        .build()
        .expect("engine builds");

    let error = engine
        .reload(r#"permit(principal, action == Action::"delete", resource);"#)
        .expect_err("undeclared action");
    assert_eq!(error.code(), "validation");

    assert!(engine
        .is_authorized(&request(
            r#"User::"alice""#,
            r#"Action::"read""#,
            r#"Doc::"design""#,
        ))
        .await
        .expect("evaluation succeeds")
        .is_allowed());
}

#[tokio::test]
async fn reload_with_a_good_policy_takes_effect_for_the_next_request() {
    let engine = PolicyEngine::builder()
        .policies(OWNER_POLICY)
        .loader(rbac_loader())
        .build()
        .expect("engine builds");

    let bob_reads_design = request(r#"User::"bob""#, r#"Action::"read""#, r#"Doc::"design""#);
    assert!(!engine
        .is_authorized(&bob_reads_design)
        .await
        .expect("evaluation succeeds")
        .is_allowed());

    engine
        .reload(
            r#"
            @id("everyone-reads")
            permit(principal, action == Action::"read", resource);

            @id("sales-writes")
            permit(principal in Group::"sales", action == Action::"write", resource);
            "#,
        )
        .expect("valid policy source");

    assert_eq!(engine.policy_count(), 2);
    let decision = engine
        .is_authorized(&bob_reads_design)
        .await
        .expect("evaluation succeeds");
    assert!(decision.is_allowed());
    assert_eq!(decision.reasons(), ["everyone-reads"]);
}

/// A loader that always fails, standing in for an unreachable database.
struct FailingLoader {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl ResourceLoader for FailingLoader {
    async fn load_entities(
        &self,
        _request: &AuthorizationRequest,
    ) -> Result<Entities, PolicyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(PolicyError::loader(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "entity store unreachable",
        )))
    }
}

#[tokio::test]
async fn a_loader_failure_surfaces_as_an_error_not_a_deny() {
    let calls = Arc::new(AtomicUsize::new(0));
    let engine = PolicyEngine::builder()
        .policies(OWNER_POLICY)
        .loader(FailingLoader {
            calls: Arc::clone(&calls),
        })
        .build()
        .expect("engine builds");

    let error = engine
        .is_authorized(&request(
            r#"User::"alice""#,
            r#"Action::"read""#,
            r#"Doc::"design""#,
        ))
        .await
        .expect_err("the loader failed");

    // Deliberately *not* a `Decision` with `is_allowed() == false`: the caller must be able to
    // tell "the policies say no" apart from "we could not find out".
    assert_eq!(error.code(), "loader");
    assert!(error.to_string().contains("entity store unreachable"));
    // The engine asked the loader exactly once, and evaluated nothing afterwards.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reloading_while_evaluating_never_panics_or_deadlocks() {
    let engine = Arc::new(
        PolicyEngine::builder()
            .policies(OWNER_POLICY)
            .loader(rbac_loader())
            .build()
            .expect("engine builds"),
    );

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let engine = Arc::clone(&engine);
        tasks.push(tokio::spawn(async move {
            for _ in 0..250 {
                // The decision flips as policies are swapped underneath; what matters is that
                // every call returns a decision rather than panicking, and that no evaluation
                // ever observes a partially-applied policy set.
                let decision = engine
                    .is_authorized(&request(
                        r#"User::"alice""#,
                        r#"Action::"read""#,
                        r#"Doc::"design""#,
                    ))
                    .await
                    .expect("evaluation succeeds");
                assert!(decision.errors().is_empty());
            }
        }));
    }

    for i in 0..8 {
        let engine = Arc::clone(&engine);
        tasks.push(tokio::spawn(async move {
            for _ in 0..50 {
                if i % 2 == 0 {
                    engine.reload(OWNER_POLICY).expect("valid policy");
                } else {
                    // Interleave failing reloads: these must leave a usable policy set behind.
                    let _ = engine.reload("permit(principal");
                }
                tokio::task::yield_now().await;
            }
        }));
    }

    for task in tasks {
        task.await.expect("no task panicked");
    }

    assert_eq!(engine.policy_count(), 1);
}

#[tokio::test]
async fn a_static_loader_serves_entities_from_cedar_json() {
    // The JSON entity format is what a database column or an admin API would realistically hold.
    let loader = StaticResourceLoader::from_json_str(
        r#"[
            { "uid": { "type": "User", "id": "alice" },
              "attrs": {},
              "parents": [{ "type": "Group", "id": "eng" }] },
            { "uid": { "type": "Group", "id": "eng" }, "attrs": {}, "parents": [] },
            { "uid": { "type": "Doc", "id": "design" },
              "attrs": { "owner": { "__entity": { "type": "Group", "id": "eng" } } },
              "parents": [] }
        ]"#,
        None,
    )
    .expect("valid entity json");

    let engine = PolicyEngine::builder()
        .policies(OWNER_POLICY)
        .loader(loader)
        .build()
        .expect("engine builds");

    assert!(engine
        .is_authorized(&request(
            r#"User::"alice""#,
            r#"Action::"read""#,
            r#"Doc::"design""#,
        ))
        .await
        .expect("evaluation succeeds")
        .is_allowed());
}

#[tokio::test]
async fn a_non_object_context_is_rejected() {
    let engine = PolicyEngine::builder()
        .policies(OWNER_POLICY)
        .loader(rbac_loader())
        .build()
        .expect("engine builds");

    let mut req = request(r#"User::"alice""#, r#"Action::"read""#, r#"Doc::"design""#);
    req.context = serde_json::json!("not an object");

    let error = engine
        .is_authorized(&req)
        .await
        .expect_err("context must be a JSON object");
    assert_eq!(error.code(), "invalid_request");
}
