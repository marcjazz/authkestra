# RFC-005: Policy Engine (AWS Cedar)

Status: **proof of concept landed, full integration not started.**
Tracking issue: [authkestra#21](https://github.com/marcjazz/authkestra/issues/21).
Code: `crates/authkestra-policy`.

## 1. Summary

This RFC proposes adding *authorization* — "may this principal do this to that?" — to
Authkestra as a first-class, policy-driven concern, using [AWS Cedar](https://www.cedarpolicy.com/)
as the policy language. It records the proof of concept that now exists in
`crates/authkestra-policy`, measures it, and designs the integration into
`authkestra-resource`'s `Guard` and the Axum/Actix adapters **without building it**, so that the
shape can be argued about before anything depends on it.

Nothing outside `crates/authkestra-policy` changes today: no guard, no extractor, and no route
behaves differently because this crate exists.

## 2. Motivation

Authkestra answers "who are you?" thoroughly — OAuth/OIDC, sessions, tokens, WebAuthn, TOTP,
device signatures — and then stops. Every application built on it re-implements the second half
by hand:

```rust,ignore
let session = auth_session.0;
if session.identity.attributes.get("role").map(String::as_str) != Some("admin") {
    return Err(Forbidden);
}
```

That has the failure modes hand-rolled authorization always has:

- **Rules live in the binary.** Changing "who may export customer data" needs a code review, a
  release, and a deploy — so in practice the rules are coarse, and stay coarse.
- **Rules are not auditable.** There is no artefact to show a reviewer, no list of who can do
  what, and a deny logs nothing beyond an HTTP 403.
- **Rules are inconsistent.** The same predicate is re-expressed slightly differently in twelve
  handlers, and the thirteenth forgets one clause.
- **Rules are untestable in isolation.** Testing a rule means standing up a route.

A policy engine turns these into data: a policy file (or table) that can be reviewed, diffed,
tested, hot-reloaded, and shown to an auditor.

## 3. Why Cedar

The candidates considered were Cedar, Open Policy Agent (Rego), Casbin, and a bespoke DSL.

| | Cedar | OPA / Rego | Casbin | Bespoke |
|---|---|---|---|---|
| Runs in-process, no sidecar | yes | only via `wasm`/HTTP | yes | yes |
| Native Rust implementation | yes (by AWS) | no (Go; Rust bindings are third-party) | `casbin-rs` | n/a |
| License | Apache-2.0 | Apache-2.0 | Apache-2.0 | n/a |
| Decidable / analysable policies | yes, by design | no (Rego is Turing-ish) | limited | no |
| Schema + static validation of policies | yes | partial (`opa check`) | no | no |
| Sub-100µs evaluation | yes (§7) | network hop if sidecar | yes | yes |
| Concept fit (principal/action/resource/context) | exact | general-purpose | ACL/RBAC matcher | n/a |

Cedar wins on the combination that matters here: it is a *native Rust library* (no sidecar, no
FFI, no network hop on the request path), its evaluation is guaranteed to terminate, and its
principal/action/resource/context model is the same model Authkestra already speaks. Its
validator can reject a policy that references an action that does not exist — a class of "rule
silently never fires" bug that Rego and Casbin will not catch for you.

The costs are real and worth stating: Cedar is one more language for an operator to learn, it
adds ~40 crates to the dependency graph, and one of them (`ar_archive_writer`, a *build*
dependency of `psm` ← `stacker` ← `cedar-policy-core`) is `Apache-2.0 WITH LLVM-exception`,
which is not on this workspace's `deny.toml` allow list and needed a per-crate exception. See
§9.

## 4. What exists today (the proof of concept)

```text
   AuthorizationRequest ──▶ PolicyEngine ──▶ ResourceLoader ──▶ your database
                                 │                              (unreachable from the engine)
                                 ▼
                          cedar_policy::Authorizer ──▶ Decision
```

### 4.1 `ResourceLoader`

```rust,ignore
#[async_trait]
pub trait ResourceLoader: Send + Sync {
    async fn load_entities(&self, request: &AuthorizationRequest)
        -> Result<cedar_policy::Entities, PolicyError>;
}
```

The engine holds a `Box<dyn ResourceLoader>` (per `AGENTS.md`'s `Box<dyn Trait>` preference for
I/O-bound paths) and owns no storage handle of any kind. This is what makes authkestra#21's "no
direct DB queries from the engine" criterion *structural*: the engine cannot query a database by
accident, because there is nothing there to query with. It is the same rule `UserStore` and
`SessionStore` follow.

Two implementations ship: `StaticResourceLoader` (a fixed entity set — right for small
config-file hierarchies and tests) and `MemoryResourceLoader`, which walks parent edges
breadth-first from the request's principal/action/resource and returns only that sub-graph. The
latter is the worked example of what a SQL-backed loader would do: a recursive CTE over the
membership table, not `SELECT *`.

### 4.2 `AuthorizationRequest` and `Decision`

```rust,ignore
pub struct AuthorizationRequest {
    pub principal: EntityUid,
    pub action: EntityUid,
    pub resource: EntityUid,
    pub context: serde_json::Value,
}

pub struct Decision { /* is_allowed(), reasons(), errors() */ }
```

The context is plain JSON so that a caller can assemble it from claims and HTTP metadata without
learning Cedar's `RestrictedExpression` API; it is converted (and, when a schema is configured,
type-checked for that action) inside the engine.

`Decision::reasons()` carries the ids of the policies that decided the request — the satisfied
`forbid`s on a deny, the satisfied `permit`s on an allow. **An empty `reasons()` on a deny is
the default deny**, which is what distinguishes "no rule allowed this" from "a rule forbade it"
in an audit log.

### 4.3 Deviation from Cedar: `@id` annotations name policies

`cedar_policy::PolicySet::from_str` names policies `policy0`, `policy1`, … by source order.
Those ids end up in `Decision::reasons()` and therefore in audit logs, and they are *positional*:
inserting a rule at the top of a file renumbers every rule below it, so last week's "denied by
policy3" no longer refers to the same rule. `authkestra_policy::parse_policies` therefore uses a
policy's `@id("...")` annotation as its id where one is present (Cedar's generated id otherwise),
and rejects two policies claiming the same id. This is a deliberate deviation from the upstream
default and the only one.

### 4.4 Runtime updates

```rust,ignore
engine.reload(cedar_source)?;   // &self — the engine is shared behind an Arc
```

The policy set lives in a `RwLock<Arc<PolicySet>>`. Evaluation clones the `Arc` under the read
lock and releases it immediately, so neither the `await` on the loader nor the Cedar evaluation
holds a lock. `reload` parses and validates the new source *before* taking the write lock, so a
failure is total and leaves the previous policy set serving traffic — a typo in an operator's
update can never empty the policy set. In-flight requests finish against the policies they
started with.

`arc_swap` would serve equally well and is marginally faster on the read path; the std lock was
chosen to avoid a dependency for a swap that happens once per policy deploy rather than once per
request. If §7's read-path cost ever matters, this is a one-line change.

## 5. Proposed integration (not built)

### 5.1 Deriving Cedar entities from an authenticated identity

`authkestra_engine::Identity` is:

```rust,ignore
pub struct Identity {
    pub provider_id: String,
    pub external_id: String,
    pub email: Option<String>,
    pub username: Option<String>,
    pub attributes: HashMap<String, String>,
}
```

The principal UID has to be derived from that, and the derivation is a security boundary: it
decides what `principal` means in every policy. The proposal is a trait rather than a fixed
mapping, because `external_id` is only unique *within* a provider:

```rust,ignore
pub trait PrincipalMapper: Send + Sync {
    fn principal(&self, identity: &Identity) -> Result<EntityUid, PolicyError>;
    /// Claims to expose to policies as `context`. Defaults to empty: a claim is only visible to
    /// a policy if someone deliberately puts it there.
    fn context(&self, _identity: &Identity) -> serde_json::Value { json!({}) }
}
```

with a default implementation producing `User::"{provider_id}|{external_id}"`. Two things
deserve maintainer attention:

- **Group membership must come from the `ResourceLoader`, not from the identity.** An
  `attributes["role"]` copied out of a JWT is attacker-influenced in exactly the cases where
  authorization matters most. The loader — reading your own database — is the trustworthy
  source. The default mapper therefore puts *nothing* from `attributes` into the principal's
  Cedar attributes.
- **Token claims into `context` is opt-in.** Same reason.

### 5.2 `authkestra-resource`: a `PolicyGuard`

`authkestra-resource`'s `Guard<I>` is authentication-only: it runs `AuthenticationStrategy<I>`s
and yields an identity. Authorization is a second, separate step, and should not be smuggled
into `AuthenticationStrategy` — a strategy that returns `Ok(None)` means "I could not identify
this request", which is a different thing from "I identified them and they may not do this".

The proposal is a sibling type in `authkestra-resource` (feature-gated `policy`):

```rust,ignore
pub struct PolicyGuard {
    engine: Arc<PolicyEngine>,
    mapper: Box<dyn PrincipalMapper>,
}

impl PolicyGuard {
    pub async fn authorize(
        &self,
        identity: &Identity,
        action: &str,          // e.g. `Action::"read"`
        resource: EntityUid,
    ) -> Result<Decision, AuthError>;
}
```

`authkestra-resource` would gain an optional dependency on `authkestra-policy`, never the
reverse. This crate must stay usable on its own.

### 5.3 Axum and Actix

Both adapters already have the pattern this needs. Axum's `Auth<I>` extractor pulls
`Arc<Guard<I>>` out of state via `FromRef`; Actix's pulls `web::Data<Arc<Guard<I>>>` out of app
data. The policy equivalents follow exactly:

```rust,ignore
// axum
async fn handler(
    Auth(identity): Auth<Identity>,
    Authorized(decision): Authorized<ReadDocument>,   // FromRequestParts, needs Arc<PolicyGuard>
) -> impl IntoResponse { … }
```

The resource UID is the hard part: it usually depends on a path parameter (`/docs/{id}`), which
an extractor cannot know generically. Three options, in increasing order of ergonomics and
implementation cost:

1. **Explicit call in the handler** — no extractor at all; the handler calls
   `policy_guard.authorize(...)` once it has parsed its path parameters. Trivial to build, most
   flexible, easiest to *forget*.
2. **A typed marker** (`Authorized<ReadDocument>`) where the application implements a small
   trait mapping `&Parts` to `(action, resource)`. Compile-time named, still per-route.
3. **A `tower::Layer` / actix middleware** matching route patterns to actions and resources
   from configuration. Catches the forgetting problem, but route-pattern-to-resource mapping in
   config is its own maintenance burden, and it cannot see a resource that is only identifiable
   after a database lookup.

Recommendation: build (1) first because it is unavoidable anyway (it is what (2) and (3) call),
add (2) once there is a real application to shape it, and treat (3) as speculative. Per
`AGENTS.md` this wiring lives in the adapter crates, never in `authkestra-policy`.

### 5.4 Where policies come from

The PoC takes policy *source text* and nothing else, deliberately: file, string, config value,
database column, and admin API all reduce to "a `&str` plus something that decides when to call
`reload`". Sketch of the three realistic sources:

- **File** — `PolicyEngine::reload(&fs::read_to_string(path)?)`, with an optional `notify`-based
  watcher in the *application*, not in this crate.
- **String/config** — startup only; no reload story needed.
- **Remote** (`authkestra-op` table, control-plane HTTP endpoint) — a background
  `tokio::spawn` poll loop calling `reload`, mirroring how OIDC discovery documents are already
  cached per `AGENTS.md`. This is the option that makes "policies can be updated at runtime"
  mean something operationally, and it is the one with real open questions: multi-instance
  consistency (instances reload at different moments), a rollback path, and whether a policy
  change should be an audited event with an author.

## 6. Non-goals

- **Policy templates and template linking.** Cedar supports them; `parse_policies` preserves
  them but the engine never links them. Deliberate: a linking API needs a story for where link
  parameters come from, which needs §5.4 settled first.
- **Partial evaluation / "which resources may this user see?"** (Cedar's `experimental`
  features). This is the natural next ask after a working guard — filtering a list endpoint — and
  is out of scope here.
- **Policy authoring UI.**
- **A migration for policy storage** in `authkestra-op`.

## 7. Performance

Measured with the `#[ignore]`d `perf_smoke` test in `crates/authkestra-policy/tests/perf.rs`:

```bash
cargo test -p authkestra-policy --all-features -- --ignored --nocapture perf_smoke
```

5 000 sequential requests against 10 policies (7 `permit`, 3 `forbid`, with group-hierarchy
`in` checks, attribute conditions, and context guards) and a 414-entity store (200 users, 200
documents, 10 teams rolling up into 4 groups). Machine: 24-core 13th Gen Intel i7-13700KF, Linux
7.0, single task — no concurrency, so these are per-request latencies, not throughput limits.

| Build | mean | p50 | p90 | p99 | throughput (1 task) |
|---|---|---|---|---|---|
| release | 30.6 µs | 23.4 µs | 28.0 µs | 39.9 µs | ~31 600 req/s |
| debug   | 129.8 µs | 119.8 µs | 171.8 µs | 221.0 µs | ~7 700 req/s |

Of the release-build end-to-end time, entity hydration (`MemoryResourceLoader::load_entities`)
accounts for p50 7.9 µs / p99 15.7 µs — **roughly a third of the total, without touching a
database**. Two conclusions:

1. **Cedar evaluation is not the cost.** ~15 µs to evaluate 10 policies is far below the
   latency of the JWT validation that precedes it, let alone a database round trip. Policy
   evaluation on every request is affordable.
2. **Hydration is the cost, and the trait shape makes it worse than it needs to be.**
   `load_entities` returns `Entities` *by value*, so every request pays a full clone of the
   returned set. For a per-tenant store of thousands of entities this dominates. The obvious
   fixes are returning `Arc<Entities>` (cheap for a cached, whole-tenant set) or keeping the
   per-request narrowing that `MemoryResourceLoader` demonstrates. **Maintainer decision** — it
   changes the trait signature, so it should be settled before anything depends on it.

The `max` column is omitted above because it is dominated by one-off allocator behaviour
(4.4 ms debug / 5.3 ms release on the first non-warmed iteration), not by policy evaluation.

## 8. Testing

`crates/authkestra-policy` ships 43 tests: allow, default deny, a `permit` conditioned on
context, a `forbid` overriding a `permit`, an unknown principal denied with empty diagnostics, a
policy erroring on a missing attribute (surfaced in `Decision::errors()`, logged at `warn`),
schema validation rejecting an invalid policy at load, `reload` with bad syntax and with a
schema violation both keeping the old policy set, `reload` with a good policy taking effect on
the next request, a loader failure surfacing as `PolicyError::Loader` rather than a deny, and a
multi-threaded test hammering `is_authorized` from 8 tasks while 8 more reload (half of them
with deliberately broken policy text).

## 9. Dependency and licensing note

`cedar-policy` 4.12 is Apache-2.0. One transitive crate is not on the workspace allow list:

```text
ar_archive_writer (Apache-2.0 WITH LLVM-exception)
  └── (build) psm ← stacker ← cedar-policy-core ← cedar-policy ← authkestra-policy
```

It is a *build* dependency of `psm`'s build script — nothing from it is linked into a shipped
artefact — and `stacker` is a non-optional dependency of `cedar-policy-core`, so it cannot be
dropped by turning Cedar's features off. `Apache-2.0 WITH LLVM-exception` is Apache-2.0 with a
restriction *removed*, but `cargo-deny` matches whole SPDX expressions, so `deny.toml` gained a
per-crate exception rather than a blanket allowance. **Maintainer decision**: accept the
exception as written, or add `Apache-2.0 WITH LLVM-exception` to the general allow list.

## 10. Maintainer decisions

Listed explicitly rather than resolved, per the tracking issue's scope.

1. **Cedar at all?** §3 argues for it; the alternatives are live and the dependency cost
   (~40 crates, a new DSL for operators) is real.
2. **The `deny.toml` licence exception** (§9): per-crate exception, blanket allow, or reject
   Cedar over it.
3. **Should a schema be mandatory?** Today it is optional; supplying one enables load-time
   policy validation and request/context type-checking. Mandatory means safer failures and a
   real authoring burden; optional means a typo'd attribute name is a rule that silently never
   fires.
4. **`load_entities` return type** (§7): `Entities` by value, or `Arc<Entities>`. Changes the
   trait, so decide before there are implementors.
5. **Where do policies live?** (§5.4) File, config, or an `authkestra-op` table with an admin
   API. Determines whether "updated at runtime" means "on SIGHUP" or "from a control plane".
6. **Which extractor shape?** (§5.3) Explicit call, typed marker, or route-configured
   middleware.
7. **Deny semantics at the HTTP edge.** 403 with the deciding policy id in the body is useful in
   development and an information leak in production; the adapters need a policy on this.
8. **Should `authkestra-policy` remain a separate crate**, or eventually merge into
   `authkestra-resource` the way RFC-001 consolidated the authentication crates?

## 11. Status against authkestra#21

| Item | Status |
|---|---|
| PoC with simple policies | done — `crates/authkestra-policy` |
| Performance metrics | done — §7 |
| Design document | this document |
| Policy engine can evaluate Cedar policies | done |
| No direct DB queries from the engine | done — structural, §4.1 |
| Policies can be updated at runtime | done — `reload`, §4.4 |
| `ResourceLoader` trait for data hydration | done |
| Integration into guards/extractors | **not started** — designed in §5, deliberately out of scope |
