# Ticket: OP Token Exchange (RFC 8693)

## Objective
Implement the OAuth 2.0 Token Exchange (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`) in a secure, structurally sound manner that prevents confused-deputy and privilege escalation vulnerabilities. 

## Context & Security Posture
Token Exchange allows a client to exchange a token it possesses for a new token. Without strict validation, a client could exchange a token it passively observed (or received for one purpose) into an arbitrarily scoped token for another purpose. We must enforce strict audience binding and scope narrowing.

## Implementation Plan

### 1. Prerequisite: Access Token Audience (`aud`)
Before we can enforce audience binding, access tokens themselves must carry an `aud` claim.
- **Action**: Update `TokenManager::issue_user_token` and `TokenManager::issue_client_token` to accept and set an `aud` claim. (Currently, only `issue_id_token` sets it from previous `#70` work).
- **Validation**: Ensure that when a subject token is validated in the exchange process, we can extract its `aud`.

### 2. OP Configuration Opt-In
Token Exchange is an advanced and potentially dangerous feature. It should not be enabled by default.
- **Action**: Add `token_exchange_enabled: bool` to `OpConfig`, defaulting to `false`.
- **Validation**: If `token_exchange_enabled` is `false`, the `/token` endpoint must immediately reject token exchange requests with `unsupported_grant_type`.

### 3. Audience Binding & Authorized Actor Check
The client requesting the exchange (`client_id`) must have a legitimate relationship to the `subject_token`.
- **Action**: When validating the `subject_token`, check its `aud` or `client_id` claim (or an explicit `azp` / authorized party).
- **Rule**: The presenting client's ID MUST be explicitly listed in the `subject_token`'s intended audience (`aud`), or the client must be the original recipient of the token. If neither is true, reject the request with `invalid_grant` or `invalid_request`.

### 4. Scope Narrowing
Token Exchange is for delegation and narrowing access, never escalation.
- **Action**: Validate the requested `scope` against both the presenting `client.scopes` (the client's registered limits) AND the `subject_token`'s existing scopes.
- **Rule**: The resulting scope must be the intersection of the requested scope, the client's allowed scopes, and the original token's scopes. If the client requests a scope not present in the `subject_token`, the OP MUST reject it or omit it (narrowing). It must NEVER grant a scope the `subject_token` did not possess.

### 5. `actor_token` / `actor_token_type` Explicit Handling
RFC 8693 defines `actor_token` for delegation (adding an `act` claim).
- **Action**: For the initial implementation, explicitly reject requests containing `actor_token` / `actor_token_type` with an `invalid_request` error, stating that composite delegation (actor tokens) is not yet supported. This is safer than silently ignoring it.

### 6. Requested `audience` / `resource`
The request may contain `audience` and/or `resource` parameters to scope the new token to a specific downstream service.
- **Action**: If `audience` is provided, validate it against the OP's known/allowed resources for the client. If valid, set it as the `aud` of the newly issued token. If not provided, default to the OP itself or a configured default.

## Definition of Done (DoD)
- PR includes the structural fix to add `aud` to access tokens.
- `handle_token_exchange` implements the strict audience-binding invariant (client must be authorized to exchange).
- `handle_token_exchange` implements strict scope narrowing (never escalate).
- `OpConfig` gates the feature behind `token_exchange_enabled`.
- Explicit tests for:
  - Happy path (valid exchange).
  - Cross-client exchange attempt (Client A tries to exchange Client B's token) -> MUST FAIL.
  - Scope escalation attempt -> MUST FAIL or strictly narrow.
  - Feature disabled -> MUST FAIL.
  - Inclusion of unsupported `actor_token` -> MUST FAIL.
- CI passes locally.
