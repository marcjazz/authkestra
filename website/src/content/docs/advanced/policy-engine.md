---
title: Policy Engine (Cedar)
description: Proof-of-concept authorization with AWS Cedar policies.
---

:::caution[Proof of concept]
`authkestra-policy` is an experiment tracked in
[authkestra#21](https://github.com/marcjazz/authkestra/issues/21). It evaluates Cedar policies
and is tested, but **nothing calls it yet** — there is no guard, extractor, or middleware wired
to it, and the API will change. The integration design is
[RFC-005](https://github.com/marcjazz/authkestra/blob/main/docs/rfc-005-policy-engine.md).
:::

Authkestra's other crates answer *"who are you?"*. This one answers *"may you do this?"*, using
[AWS Cedar](https://www.cedarpolicy.com/) — so authorization rules live in a policy file you can
review, diff and reload, instead of in `if role == "admin"` branches scattered across handlers.

## Enabling it

```toml
[dependencies]
authkestra = { version = "0.7", features = ["policy"] }
# or the crate on its own:
authkestra-policy = "0.7"
```

## The one rule: the engine never touches your database

Cedar decides using an *entity store* — the principal, the resource, their groups and
attributes. The engine holds no database handle and never fetches any of it. Everything arrives
through a `ResourceLoader` you implement:

```rust
use async_trait::async_trait;
use authkestra_policy::cedar_policy::Entities;
use authkestra_policy::{AuthorizationRequest, PolicyError, ResourceLoader};

struct PostgresLoader { /* your pool */ }

#[async_trait]
impl ResourceLoader for PostgresLoader {
    async fn load_entities(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<Entities, PolicyError> {
        // Fetch just this request's principal, resource, and their group memberships.
        // Storage faults become PolicyError::loader(e) — never a silent deny.
        todo!()
    }
}
```

This is the same database-agnosticism rule as `UserStore` and `SessionStore`: Authkestra never
assumes your schema.

## Evaluating a request

```rust
use authkestra_policy::cedar_policy::RestrictedExpression;
use authkestra_policy::{
    AuthorizationRequest, EntityRecord, MemoryResourceLoader, PolicyEngine, parse_entity_uid,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let loader = MemoryResourceLoader::new();
    loader.extend([
        EntityRecord::new(parse_entity_uid(r#"User::"alice""#)?)
            .parent(parse_entity_uid(r#"Group::"eng""#)?),
        EntityRecord::new(parse_entity_uid(r#"Group::"eng""#)?),
        EntityRecord::new(parse_entity_uid(r#"Doc::"design""#)?).attribute(
            "owner",
            RestrictedExpression::new_entity_uid(parse_entity_uid(r#"Group::"eng""#)?),
        ),
    ]);

    let engine = PolicyEngine::builder()
        .policies(r#"
            @id("eng-reads-own-docs")
            permit(principal in Group::"eng", action == Action::"read", resource)
            when { resource.owner == Group::"eng" };
        "#)
        .loader(loader)
        .build()?;

    let request = AuthorizationRequest::builder()
        .principal_str(r#"User::"alice""#)
        .action_str(r#"Action::"read""#)
        .resource_str(r#"Doc::"design""#)
        .build()?;

    let decision = engine.is_authorized(&request).await?;
    assert!(decision.is_allowed());
    assert_eq!(decision.reasons(), ["eng-reads-own-docs"]);
    Ok(())
}
```

Cedar is **deny by default** and **forbid overrides permit**: a request is allowed only if some
`permit` matches and no `forbid` does.

## Reading a decision

- `decision.is_allowed()` — the answer.
- `decision.reasons()` — the ids of the policies that decided it. Empty on a deny means *no rule
  allowed it* (the default deny); non-empty means a `forbid` matched. Name your rules with
  `@id("...")` so these stay stable when you reorder a policy file. A policy without one keeps
  Cedar's positional id (`policy2` for the third policy in the file), and because those are handed
  out by position, `@id("policy0")` and anything else of the form `policy<digits>` is rejected at
  load time — it would name the wrong rule. `policy-admin-override` and the like are fine.
- `decision.errors()` — policies that failed to evaluate (a missing attribute, a type error).
  Cedar skips those and carries on, so a non-empty list means the decision was made on only part
  of your rule set. They are logged at `warn`.

A `PolicyError` is never a deny. If your loader cannot reach its database you get `Err`, so
"the rules say no" is always distinguishable from "we could not find out".

## Updating policies at runtime

```rust
// A bad update changes nothing: the previous policies keep serving traffic.
assert!(engine.reload("permit(principal").is_err());

// A good one takes effect for the next request. No restart.
engine.reload(new_policy_source)?;
```

The swap is atomic and needs only `&self`, so the engine can sit in an `Arc` shared by every
handler. Requests already in flight finish against the policies they started with.

## Optional: a schema

```rust
let engine = PolicyEngine::builder()
    .policies(policy_source)
    .schema(r#"
        entity User in [Group];
        entity Group;
        entity Doc { owner: Group };
        action read appliesTo { principal: [User], resource: [Doc] };
    "#)
    .loader(loader)
    .build()?;
```

With a schema, a policy referring to an action or attribute the schema does not declare is
rejected **when it is loaded** rather than silently never matching, and each request's context is
type-checked. Without one, nothing is validated — a typo becomes a rule that never fires.

## Performance

On a 24-core i7-13700KF, evaluating 10 policies against a 414-entity store takes p50 23 µs /
p99 40 µs end-to-end in a release build (about a third of which is entity hydration). Policy
evaluation is not the expensive part of your request — see RFC-005 §7 for the method and the
caveats.
