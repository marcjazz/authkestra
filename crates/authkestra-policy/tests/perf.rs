//! Latency smoke test for policy evaluation (authkestra#21's "performance metrics" DoD item).
//!
//! `#[ignore]`d on purpose. This is a *measurement*, not an assertion about the machine it runs
//! on: CI runners are shared and noisy, so a latency threshold here would be a flaky test rather
//! than a useful guard. It is also not a `benches/` harness, because nothing in this workspace
//! runs benchmarks — an ignored test is the shape that stays runnable without new tooling.
//!
//! ```text
//! cargo test -p authkestra-policy --all-features -- --ignored --nocapture perf_smoke
//! ```
//!
//! The recorded numbers, the machine they came from, and what they imply for a per-request guard
//! live in `docs/rfc-005-policy-engine.md`.

use std::time::{Duration, Instant};

use authkestra_policy::cedar_policy::RestrictedExpression;
use authkestra_policy::{
    parse_entity_uid, AuthorizationRequest, EntityRecord, MemoryResourceLoader, PolicyEngine,
    ResourceLoader,
};

/// Requests per measured loop. Large enough that a p99 means something, small enough that the
/// whole test stays under a couple of seconds in a debug build.
const ITERATIONS: usize = 5_000;

/// A plausible mid-size RBAC deployment: 200 users spread over 10 teams, 3 of which roll up into
/// a `staff` group, and 200 documents each owned by a team.
const USERS: usize = 200;
const TEAMS: usize = 10;
const DOCS: usize = 200;

fn uid(source: &str) -> authkestra_policy::cedar_policy::EntityUid {
    parse_entity_uid(source).expect("valid entity uid")
}

/// Ten policies of the kind an application actually writes: role scopes, ownership conditions,
/// a context guard, and two `forbid`s that must be evaluated on every request.
const POLICIES: &str = r#"
    @id("staff-read-team-docs")
    permit(principal in Group::"staff", action == Action::"read", resource)
    when { resource.owner in Group::"staff" };

    @id("team-members-read-own")
    permit(principal, action == Action::"read", resource)
    when { principal in resource.owner };

    @id("team-members-write-own")
    permit(principal, action == Action::"write", resource)
    when { principal in resource.owner && context has mfa && context.mfa };

    @id("admins-do-anything")
    permit(principal in Group::"admins", action, resource);

    @id("auditors-read-anything")
    permit(principal in Group::"auditors", action == Action::"read", resource);

    @id("owners-delete-own")
    permit(principal, action == Action::"delete", resource)
    when { principal in resource.owner && principal in Group::"team3" };

    @id("read-during-business-hours")
    permit(principal in Group::"contractors", action == Action::"read", resource)
    when { context has hour && context.hour >= 9 && context.hour <= 17 };

    @id("no-confidential-without-mfa")
    forbid(principal, action, resource)
    when { resource has confidential && resource.confidential }
    unless { context has mfa && context.mfa };

    @id("no-writes-from-untrusted-networks")
    forbid(principal, action == Action::"write", resource)
    unless { context has trusted_network && context.trusted_network };

    @id("suspended-users-do-nothing")
    forbid(principal, action, resource)
    when { principal has suspended && principal.suspended };
"#;

fn build_loader() -> MemoryResourceLoader {
    let loader = MemoryResourceLoader::new();

    for team in 0..TEAMS {
        let record = EntityRecord::new(uid(&format!(r#"Group::"team{team}""#)));
        // Three of the ten teams roll up into `staff`, so the `in` checks walk a real hierarchy
        // rather than a flat one.
        let record = if team < 3 {
            record.parent(uid(r#"Group::"staff""#))
        } else {
            record
        };
        loader.insert(record);
    }
    loader.insert(EntityRecord::new(uid(r#"Group::"staff""#)));
    loader.insert(EntityRecord::new(uid(r#"Group::"admins""#)));
    loader.insert(EntityRecord::new(uid(r#"Group::"auditors""#)));
    loader.insert(EntityRecord::new(uid(r#"Group::"contractors""#)));

    for user in 0..USERS {
        loader.insert(
            EntityRecord::new(uid(&format!(r#"User::"user{user}""#)))
                .parent(uid(&format!(r#"Group::"team{}""#, user % TEAMS)))
                .attribute("suspended", RestrictedExpression::new_bool(false)),
        );
    }

    for doc in 0..DOCS {
        loader.insert(
            EntityRecord::new(uid(&format!(r#"Doc::"doc{doc}""#)))
                .attribute(
                    "owner",
                    RestrictedExpression::new_entity_uid(uid(&format!(
                        r#"Group::"team{}""#,
                        doc % TEAMS
                    ))),
                )
                .attribute("confidential", RestrictedExpression::new_bool(doc % 7 == 0)),
        );
    }

    loader
}

fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
    debug_assert!(!sorted.is_empty());
    let index = ((sorted.len() as f64 * fraction) as usize).min(sorted.len() - 1);
    sorted[index]
}

fn report(label: &str, mut samples: Vec<Duration>) {
    samples.sort_unstable();
    let total: Duration = samples.iter().sum();
    println!(
        "{label:<28} n={n} mean={mean:>8.1}us p50={p50:>8.1}us p90={p90:>8.1}us p99={p99:>8.1}us max={max:>8.1}us",
        n = samples.len(),
        mean = total.as_secs_f64() * 1e6 / samples.len() as f64,
        p50 = percentile(&samples, 0.50).as_secs_f64() * 1e6,
        p90 = percentile(&samples, 0.90).as_secs_f64() * 1e6,
        p99 = percentile(&samples, 0.99).as_secs_f64() * 1e6,
        max = samples.last().copied().unwrap_or_default().as_secs_f64() * 1e6,
    );
}

#[tokio::test]
#[ignore = "measurement, not an assertion: run explicitly with --ignored --nocapture"]
async fn perf_smoke() {
    let loader = build_loader();
    let engine = PolicyEngine::builder()
        .policies(POLICIES)
        .loader(build_loader())
        .build()
        .expect("engine builds");

    let requests: Vec<AuthorizationRequest> = (0..ITERATIONS)
        .map(|i| {
            let mut request = AuthorizationRequest::builder()
                .principal_str(&format!(r#"User::"user{}""#, i % USERS))
                .action_str(if i % 3 == 0 {
                    r#"Action::"write""#
                } else {
                    r#"Action::"read""#
                })
                .resource_str(&format!(r#"Doc::"doc{}""#, i % DOCS))
                .build()
                .expect("valid request");
            request.context = serde_json::json!({
                "mfa": i % 2 == 0,
                "trusted_network": i % 5 != 0,
                "hour": 13,
            });
            request
        })
        .collect();

    // Warm up: first-call costs (allocator growth, branch predictors) are not what we want to
    // report as a steady-state p50.
    for request in requests.iter().take(200) {
        engine
            .is_authorized(request)
            .await
            .expect("evaluation succeeds");
    }

    let mut end_to_end = Vec::with_capacity(ITERATIONS);
    let mut allowed = 0usize;
    let wall = Instant::now();
    for request in &requests {
        let start = Instant::now();
        let decision = engine
            .is_authorized(request)
            .await
            .expect("evaluation succeeds");
        end_to_end.push(start.elapsed());
        if decision.is_allowed() {
            allowed += 1;
        }
    }
    let wall = wall.elapsed();

    // Hydration alone, so that the split between "fetching entities" and "running Cedar" is
    // visible rather than inferred. Both use the same loader contents.
    let mut hydration = Vec::with_capacity(ITERATIONS);
    for request in &requests {
        let start = Instant::now();
        loader
            .load_entities(request)
            .await
            .expect("hydration succeeds");
        hydration.push(start.elapsed());
    }

    println!();
    println!(
        "perf_smoke: {ITERATIONS} requests, {} policies, {} entities in the store",
        POLICIES.matches("@id(").count(),
        USERS + DOCS + TEAMS + 4,
    );
    println!(
        "  allowed={allowed}/{ITERATIONS}, wall={:.3}s, throughput={:.0} req/s (single task)",
        wall.as_secs_f64(),
        ITERATIONS as f64 / wall.as_secs_f64(),
    );
    report("is_authorized (end-to-end)", end_to_end);
    report("  of which: load_entities", hydration);
    println!(
        "  build profile: {}",
        if cfg!(debug_assertions) {
            "debug (unoptimized) — release is several times faster"
        } else {
            "release"
        }
    );

    // The only assertion: the policy set really is exercising both outcomes, so the numbers
    // above are not measuring a trivially short-circuited evaluation.
    assert!(allowed > 0 && allowed < ITERATIONS, "allowed={allowed}");
}
