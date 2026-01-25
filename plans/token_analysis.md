# Token Implementation Analysis: Server-to-Server Authentication

## Conclusion: Partially

The current implementation in `authly-token` and `authly-core` **partially** supports server-to-server authentication (e.g., Client Credentials Flow), but it is primarily designed for user-centric session management. Significant modifications are required to support standard machine-to-machine (M2M) patterns effectively.

## Technical Reasoning

### 1. Token Structure & Coupling to `Identity`
**Current State:**
The JWT claims structure in `authly-token/src/lib.rs` is tightly coupled to the `Identity` struct from `authly-core`.
```rust
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub identity: Identity, // <--- Rigid coupling
}
```
**Issue:**
- **Bloated Payload:** The `Identity` struct includes user-specific fields like `email`, `username`, and `attributes`. For M2M communication, tokens should be minimal, typically containing only `sub` (client_id), `iss`, `aud`, `exp`, and `scope`.
- **Semantics:** Using a user `Identity` to represent a "Service" or "Client" is semantically incorrect (e.g., a service does not have a "username" or "email" in the traditional sense).

### 2. Lack of Scopes in JWT
**Current State:**
The `Claims` struct lacks a `scope` field.
**Issue:**
- Server-to-server authentication relies heavily on **scopes** to define what the client service is allowed to do (e.g., `read:users`, `write:logs`).
- While `OAuthToken` in `authly-core` has a `scope` field, this is not propagated into the JWT `Claims` used for validation. This makes it impossible for resource servers to validate permissions based solely on the token.

### 3. Missing Client Credentials Flow
**Current State:**
The system defines `CredentialsProvider`, but it is currently used for User/Password authentication (Resource Owner Password Credentials).
**Issue:**
- There is no specific abstraction for **Client Credentials Flow** (Client ID + Client Secret -> Token).
- Existing flows assume the result is an `Identity` that leads to a Session. M2M auth typically results in a stateless Access Token, not a session cookie.

### 4. Custom Claims
**Current State:**
The JWT implementation does not support arbitrary custom claims.
**Issue:**
- Use cases often require extra claims (e.g., `tenant_id`, `roles`) at the top level of the JWT.
- Currently, these would have to be stuffed into `Identity.attributes` (HashMap<String, String>), which is nested inside the `identity` claim, making it non-standard for consumers expecting flat JWT claims.

## Recommendations
To fully support Server-to-Server Authentication:

1.  **Refactor `Claims`:** Decouple `Claims` from `Identity`. Make `Claims` generic or capable of handling different subject types (User vs. Client).
    ```rust
    pub struct Claims {
        pub sub: String,
        pub exp: usize,
        pub scope: Option<String>, // Add this
        // ... standard claims
    }
    ```
2.  **Add `scope` support:** Ensure scopes are included in the JWT issuance and validation process.
3.  **Create `ClientCredentialsProvider`:** A dedicated trait or implementation that validates `client_id` and `client_secret` and returns a token structure suitable for M2M (without user session overhead).
