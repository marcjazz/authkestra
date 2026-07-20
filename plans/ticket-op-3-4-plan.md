# OP.3 and OP.4: Authorization and Token Endpoints

## Goal
Implement the core OAuth 2.0 / OIDC Authorization Code grant. This covers the `/authorize` endpoint (which issues short-lived authorization codes) and the `/token` endpoint (which exchanges those codes for ID and Access Tokens).

## Scope
- **`authkestra-op/src/handlers/authorize.rs`**:
  - Accept `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `code_challenge`, and `code_challenge_method`.
  - Validate `client_id` exists via `ClientStore`.
  - Validate `redirect_uri` matches one of the client's registered URIs (exact string equality).
  - Enforce PKCE for public clients.
  - Require the user to be authenticated (Identity context).
  - Issue an `AuthorizationCode` using `AuthorizationCodeStore`.
  - Redirect back to the client's `redirect_uri` with `code` and `state`.
- **`authkestra-op/src/handlers/token.rs`**:
  - Accept `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, and `code_verifier`.
  - Atomically consume the authorization code via `AuthorizationCodeStore::consume_code`.
  - Validate that the code was issued to the requesting `client_id`.
  - Validate that the `redirect_uri` matches the one provided at `/authorize`.
  - Validate PKCE `code_verifier` against the stored `code_challenge`.
  - Issue tokens (ID Token and Access Token) using `authkestra_engine::token::TokenManager`.
- **Tests**:
  - Unit tests for authorization request validation.
  - Unit tests for token exchange validation and PKCE enforcement.
  - Tests ensuring exact string matching for `redirect_uri`.

## Design Notes
- **Structural Links**: Like OP.2, ensure handler initialization takes `&OpConfig` to read capabilities, and takes an `Arc<TokenManager>` and `Arc<dyn ClientStore>`, etc.
- **Stateless OAuth**: Avoid storing ephemeral OAuth state in database schemas. `AuthorizationCodeStore` handles the code exchange mechanism safely and atomically.
- **Framework Agnostic**: Keep these handlers generic (request/response structs and logic) so `OP.6` can easily wrap them in Axum/Actix adapters later.
