# Chapter 5: Authorization and Policies

Authentication answers "Who are you?". Authorization answers "What are you allowed to do?". In Authkestra, we decouple this logic entirely from your application using **Policy-as-Code**.

## 1. Relationship-Based Access Control (ReBAC)
For complex, deeply nested permissions (like Google Drive folders or GitHub teams), Authkestra provides a **Zanzibar-style** ReBAC engine.
- **Relationship Tuples**: Permissions are modeled as a directed graph of `(user, relation, object)`.
- **Inheritance**: Permissions flow through group memberships and resource hierarchies automatically.

## 2. Attribute-Based Access Control (ABAC)
For context-heavy decisions (e.g., "Allow access only during business hours from an approved IP"), we integrate declarative policy engines.
- **AWS Cedar Integration**: We leverage the Cedar policy language for high-performance, mathematically provable authorization decisions.
- **Attribute Evaluation**: Policies are evaluated against the real-time attributes of the identity, the resource, and the environment.

## 3. Continuous Access Evaluation (CAEP)
A defining feature of Authkestra's authorization model is that it is **never static**.
- **Shared Signals Framework (SSF)**: Authkestra listens for security signals from EDRs, MDMs, and other providers.
- **Real-Time Attenuation**: If a user's device becomes non-compliant or they are terminated, their session is attenuated or revoked **instantly** via CAEP events, without waiting for token expiration.

## Policy Engine Interface

```rust
pub trait PolicyEngine: Send + Sync {
    /// Evaluate if an action is permitted on a resource given the current context
    async fn evaluate(&self, request: AuthorizationRequest) -> Result<Decision, PolicyError>;
}
```
