# Ticket: OP Token Exchange (RFC 8693)

## Objective
Implement the OAuth 2.0 Token Exchange (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`) in a secure, structurally sound manner that prevents confused-deputy and privilege escalation vulnerabilities. 

## Context & Security Posture
Token Exchange allows a client to exchange a token it possesses for a new token. Without strict validation, a client could exchange a token it passively observed (or received for one purpose) into an arbitrarily scoped token for another purpose. We must enforce strict audience binding and scope narrowing.

## Implementation Plan

### 1. Prerequisite: Access Token Audience (`aud`) and `azp`
Before we can enforce audience binding, access tokens themselves must carry an `aud` claim (or `azp` for client-binding).
- **Action**: Update `TokenManager::issue_user_token` and `TokenManager::issue_client_token` to accept and set an `aud` claim. For standard access token issuance, the `aud` should default to the requesting `client_id` (acting as the Authorized Party `azp`).
- **Clarification**: We must distinguish between client-binding (the client the token was issued to) and resource-audience (the downstream service). Initial access tokens will use `client_id` as their `aud`. Exchanged tokens (Step 6) will receive a separate, later assignment representing the target resource.
- **Validation**: Ensure that when a subject token is validated in the exchange process, we can extract its `aud`.

### 2. OP Configuration Opt-In
Token Exchange is an advanced and potentially dangerous feature. It should not be enabled by default.
- **Action**: Add `token_exchange_enabled: bool` to `OpConfig`, defaulting to `false`.
- **Validation**: If `token_exchange_enabled` is `false`, the `/token` endpoint must immediately reject token exchange requests with `unsupported_grant_type`.

### 3. Audience Binding & Authorized Actor Check
The client requesting the exchange (`client_id`) must have a legitimate relationship to the `subject_token`.
- **Action**: When validating the `subject_token`, check its `aud` or `client_id` claim (or an explicit `azp` / authorized party).
- **Rule**: The presenting client's ID MUST be explicitly listed in the `subject_token`'s intended audience (`aud`), or the client must be the original recipient of the token. If neither is true, reject the request with `invalid_grant` or `invalid_request`.

### 3a. Client Registration: `allowed_audiences`
To properly scope exchanged tokens to specific downstream resources (Step 6), we must know which resources a client is authorized to target.
- **Action**: Add `allowed_audiences: Vec<String>` to the `ClientRegistration` struct in `authkestra-op`.

### 4. Scope Narrowing
Token Exchange is for delegation and narrowing access, never escalation.
- **Action**: Validate the requested `scope` against both the presenting `client.scopes` (the client's registered limits) AND the `subject_token`'s existing scopes.
- **Rule**: The resulting scope must be the intersection of the requested scope, the client's allowed scopes, and the original token's scopes.
- **Behavior (resolved)**: If the client requests a scope not present in the `subject_token`, the OP MUST silently narrow — issue the token with the intersected (reduced) scope, not an error. A client asking for a superset it wasn't entitled to gets a smaller, usable token rather than a hard failure. The OP MUST NEVER grant a scope the `subject_token` did not possess, under any circumstance. If the intersection is empty (no requested scope overlaps what the subject token and client are both permitted), reject with `invalid_scope` rather than issuing a token with no scope at all.

### 5. Explicit Rejection of Unsupported Token Types
RFC 8693 defines `actor_token` for delegation (adding an `act` claim) and specifies `subject_token_type` and `requested_token_type`.
- **Action**: Explicitly reject requests containing an `actor_token` / `actor_token_type` with an `invalid_request` error, stating that composite delegation (actor tokens) is not yet supported.
- **Action**: Explicitly reject requests where `subject_token_type` is anything other than the standard access token or ID token URNs that we support issuing and verifying. Do not let it fall through to generic token validation failures.
- **Action**: Explicitly reject requests where `requested_token_type` is anything other than an access token URN (e.g., if a client asks for a `:refresh_token` or `:id_token` and we only intend to return an access token for now).

### 6. Requested `audience` / `resource`
The request may contain `audience` and/or `resource` parameters to scope the new token to a specific downstream service.
- **Action**: If `audience` is provided, validate it against the `allowed_audiences` field added to the `ClientRegistration` in Step 3a. If valid, set it as the `aud` of the newly issued token. If not provided, default to the OP itself or a configured default.

### 7. Token Consumption (Non-Single-Use)
- **Clarification**: Unlike authorization codes, subject tokens in token exchange are NOT single-use. Exchanging a token does not "consume" it. The subject token remains valid until its natural expiration. This is a deliberate choice.

## Definition of Done (DoD)
- PR includes the structural fix to add `aud` to access tokens.
- `handle_token_exchange` implements the strict audience-binding invariant (client must be authorized to exchange).
- `handle_token_exchange` implements strict scope narrowing (never escalate).
- `OpConfig` gates the feature behind `token_exchange_enabled`.
- Explicit tests for:
  - Happy path (valid exchange).
  - Cross-client exchange attempt (Client A tries to exchange Client B's token) -> MUST FAIL.
  - Scope escalation attempt (requested scope exceeds subject_token's scope) -> MUST silently narrow to the intersection, not fail.
  - Scope request with zero overlap with subject_token's scope -> MUST FAIL with `invalid_scope`.
  - Feature disabled (`token_exchange_enabled: false`) -> MUST FAIL with `unsupported_grant_type`.
  - Inclusion of unsupported `actor_token` -> MUST FAIL.
  - Unsupported `subject_token_type` (not an access/ID token URN we issue) -> MUST FAIL with `invalid_request`, not a generic validation error.
  - Unsupported `requested_token_type` (e.g. `:refresh_token`, `:id_token`) -> MUST FAIL with `invalid_request`.
  - Requested `audience` not present in the client's `allowed_audiences` -> MUST FAIL.
  - Requested `audience` present in `allowed_audiences` -> exchanged token's `aud` matches the requested audience.
  - No `audience` provided -> exchanged token defaults to the OP itself (or configured default) per step 6.
- CI passes locally.
