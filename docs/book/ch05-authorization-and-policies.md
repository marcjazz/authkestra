# Chapter 5: Authorization and Policies

Authentication answers "Who are you?". Authorization answers "What are you allowed to do?".

While Authkestra started primarily as an authentication library, modern applications need robust access control. As part of the phased expansion, we are enforcing a dedicated authorization perimeter (e.g. `authkestra-resource`) ensuring identity validation maps seamlessly into permission enforcement.

## Policy Models

We plan to support multiple models, moving from simple setups to enterprise-ready solutions:

- **RBAC (Role-Based Access Control):** Simple, role-to-permission mapping.
- **ABAC-lite:** Supporting dynamic conditions based on user and resource attributes.
- **Policy DSL:** A robust, dynamic Domain Specific Language for advanced, declarative permissions.

## Policy Engine Integration

```rust
pub trait PolicyEngine {
    async fn evaluate(&self, identity: &Identity, resource: &str, action: &str) -> bool;
}
```

### Architectural Decisions & Future Direction

- **DSL vs. Code:** While Rust closures are fast, they require a full server rebuild and redeploy to change a business rule. For an enterprise-grade auth system, a custom DSL (like AWS Cedar) is vastly superior. It allows policies to be updated in a database and evaluated dynamically at runtime, enabling SaaS multi-tenancy and zero-downtime policy updates.
- **Data Hydration for ABAC:** How does the policy engine fetch context (e.g., resource ownership)? The core engine should never touch the database directly for resource hydration. We define a `ResourceLoader` trait. The application implements this trait to query its own database and feed the requested context into the `PolicyEngine`.
