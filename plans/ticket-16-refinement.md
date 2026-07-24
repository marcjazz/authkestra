# Ticket 16 Refinement Plan

This plan addresses the user feedback regarding the refactored examples in `authkestra-examples`.

## Goals

1. **Basic Setup Use Case Testability**
2. **Resource Server Boilerplate Reduction**
3. **Stateless Session Example**
4. **Resource Server Strategy Example**

## Action Items

### 1. Update `axum_basic_setup.rs` for Testability
- **Context:** The current basic setup example initializes the `Engine` but does not register any `AuthMethod`, leaving developers with no endpoints to actually test a login flow.
- **Action:** Add a mock authentication flow or use the `ClientCredentialsFlow` (or similar simple flow) to the `Engine` builder.
- **Expected Outcome:** Users should be able to run the example, trigger a login via a specific endpoint (e.g., `/auth/mock/login`), and successfully see their session in the `/api/user` endpoint.

### 2. Simplify `axum_resource_server.rs` Boilerplate
- **Context:** The current example requires developers to manually wire up `JwksCache`, `Validation`, and implement `FromRef` for `AppState`.
- **Action:** 
  - Investigate `authkestra-resource` or `authkestra-axum` for existing builder macros/helpers. If none exist, implement a helper such as `ResourceServerState` or a simplified builder in `authkestra-resource` to encapsulate the `JwksCache` and `Validation` initialization.
  - Refactor `axum_resource_server.rs` to use this simplified interface, removing the `FromRef` boilerplate and manual config wiring.
- **Expected Outcome:** A dramatically shorter example file focusing purely on the Axum handlers and a one-liner/two-liner configuration for the resource server.

### 3. Create `axum_stateless_session.rs` Example
- **Context:** Developers frequently build stateless backends using JWTs in cookies, bypassing server-side memory or Redis session stores.
- **Action:** Create a new example file `authkestra-examples/examples/axum_stateless_session.rs`.
- **Implementation Details:**
  - Configure `Engine` with a stateless session manager (e.g., a JWT cookie store instead of `authkestra_session_memory::MemoryStore`).
  - Demonstrate a flow (like OAuth2 or OIDC) that issues these stateless session tokens.
  - Provide an endpoint to read and validate the stateless session.

### 4. Create `axum_resource_server_strategy.rs` Example
- **Context:** We need to explicitly demonstrate the "Resource Server strategy" using `authkestra-resource` to protect APIs.
- **Action:** Create a new example file `authkestra-examples/examples/axum_resource_server_strategy.rs`.
- **Implementation Details:**
  - Show how to register the resource server strategy into the main `Engine` if applicable, or how to use the specific `authkestra-resource` extractors and middlewares.
  - Provide clear dummy data/endpoints to test token validation scopes and claims.

## Execution
Switch to the **Code** mode to execute these steps sequentially.