# OP.5: UserInfo Endpoint (`/userinfo`)

## 1. Goal
Implement the OIDC UserInfo Endpoint to return claims about the authenticated end-user.

## 2. Specification Context (RFC-003 & OIDC Core 1.0)
- **Endpoint**: `/userinfo`
- **Method**: GET or POST
- **Authentication**: Bearer Token in the `Authorization` header.
- **Response**: JSON object containing user claims (e.g., `sub`, `email`, `username`), based on the scopes granted during the original authorization request.
- **Constraints**: 
  - Must validate the access token.
  - Must return standard OIDC claims if the corresponding scopes were granted (e.g., `email` for the `email` scope).

## 3. Implementation Plan
### Step 1: Request & Response Types
- Define `UserInfoRequest` (though mostly just the extracted bearer token).
- Define `UserInfoResponse` as a generic JSON map (or typed struct for standard OIDC claims like `sub`, `name`, `email`).

### Step 2: The Handler Logic (`authkestra-op/src/handlers/userinfo.rs`)
1. **Extract Token**: Get the Bearer token from the `Authorization` header.
2. **Verify Token**: Use `TokenManager` (or `TokenService`) to validate the access token.
   - If invalid or expired, return `401 Unauthorized` with `WWW-Authenticate: error="invalid_token"`.
3. **Check Scopes**: Ensure the token possesses the `openid` scope (UserInfo is an OIDC feature).
4. **Build Claims**: Construct the JSON response using the `Identity` associated with the validated token. Include standard claims based on granted scopes (e.g., `email`, `profile`).

### Step 3: Tests
- **test_missing_token**: Request without Bearer token -> 401.
- **test_invalid_token**: Request with tampered/expired token -> 401.
- **test_missing_openid_scope**: Valid token but lacks `openid` scope -> 403 (or 401).
- **test_successful_userinfo**: Valid token with `openid profile email` scopes -> 200 OK with expected JSON (`sub`, `email`, etc.).

## 4. Acceptance Criteria
- `/userinfo` correctly decodes Bearer access tokens.
- OIDC standard claims are correctly returned based on the `Identity` object in the token.
- Missing or invalid tokens are correctly rejected with 401.
