# Implementation Plan - Ticket #17: Enforce standard JWT fields and isolate custom claims

This document outlines the plan to refactor the `Claims` struct to ensure standard JWT/OIDC fields are strictly typed and custom claims are isolated into a separate field.

## 1. Analysis of Current State
- `authkestra-engine/src/token/mod.rs`: Contains a `Claims` struct with some standard fields and a flattened `custom` HashMap.
- `authkestra-resource/src/jwt.rs`: Contains a separate `Claims` struct used for validation, which is less comprehensive.
- There is duplication and lack of strict typing for some OIDC standard claims.

## 2. Requirements
- Strictly type standard JWT/OIDC fields: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`.
- Isolate custom claims into an `extra` HashMap.
- Maintain compliance with OIDC and existing serialization/deserialization logic.
- Consolidate `Claims` into `authkestra-engine` as per RFC-001.

## 3. Proposed Changes

### 3.1. `authkestra-engine` Refactoring
- Update `authkestra-engine/src/token/mod.rs`:
    - Refactor `Claims` struct:
        ```rust
        pub struct Claims {
            // Standard OIDC claims
            pub iss: Option<String>,
            pub sub: String,
            pub aud: Option<String>,
            pub exp: usize,
            pub iat: usize,
            pub nbf: Option<usize>,
            pub jti: Option<String>,
            
            // Authkestra-specific core fields
            pub scope: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            pub identity: Option<Identity>,
            
            // Isolated custom claims
            #[serde(flatten)]
            pub extra: HashMap<String, serde_json::Value>,
        }
        ```
    - Update `TokenManager::issue_user_token` and `issue_client_token` to populate new fields.
    - Add unit tests for serialization/deserialization.

### 3.2. `authkestra-resource` Consolidation
- Update `authkestra-resource/src/jwt.rs`:
    - Remove local `Claims` struct.
    - Import and use `authkestra_engine::token::Claims`.
    - Update validation logic if necessary to accommodate the shared struct.

### 3.3. `authkestra-oidc` Alignment
- Ensure `authkestra-oidc` uses the consolidated `Claims` if applicable.

## 4. Acceptance Criteria Verification
- [ ] `Claims` struct has explicit fields for OIDC standard claims.
- [ ] Custom claims are handled via a separate `extra` field.
- [ ] Unit tests in `authkestra-engine` pass.
- [ ] Integration with `authkestra-resource` works (validated via existing or new tests).

## 5. Timeline
1. Update `authkestra-engine` (Claims struct + tests).
2. Update `TokenManager` issuance logic.
3. Consolidate `authkestra-resource` to use shared `Claims`.
4. Final verification.
