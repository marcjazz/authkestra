# Findings for Tickets #22 and #23

## Ticket #22: Standardize Async Traits implementation using #[async_trait]
**Goal:** Use the `#[async_trait]` macro for public traits (`AuthMethod`, `Flow`, `Provider`, `SessionStore`).

**Status:** Partially Implemented

- `AuthMethod`: Implemented. `#[async_trait]` is present on `pub trait AuthMethod` in `authkestra-engine/src/auth/mod.rs`.
- `Flow`: Implemented. `#[async_trait]` is present on `pub trait Flow` in `authkestra-engine/src/flow/mod.rs`.
- `SessionStore`: Implemented. `#[async_trait]` is present on `pub trait SessionStore` in `authkestra-engine/src/auth/session.rs`.
- `Provider`: **NOT Implemented**.
  - `pub trait Provider: Send + Sync` in `authkestra-engine/src/auth/mod.rs` lacks the `#[async_trait]` macro.
  - There is a duplicate, empty `pub trait Provider {}` defined in `authkestra-engine/src/lib.rs` that should be removed.

## Ticket #23: RFC-001 Phase 1: Engine Consolidation
**Goal:** Execute Phase 1 of RFC-001 Architecture Migration.

**Status:** Mostly Implemented

Reviewing the checklist for Phase 1 in the RFC:
- [x] 1. Initialize `authkestra-engine` and merge core crates: Done. `authkestra-engine` exists and contains auth, flow, and token logic.
- [x] 2. Define Core Traits in `authkestra-engine`: Done. `AuthMethod`, `Flow`, `Provider`, and `SessionStore` are defined in the engine.
- [ ] **Standardize Async Traits implementation using #[async_trait] (#22)**: Partially done. `Provider` trait is missing the macro.
- [x] 3. Implement AuthEngine Builder: Done. `AuthEngine` and `AuthEngineBuilder` are present in `authkestra-engine/src/engine/mod.rs`.
- [x] 4. Refactor OAuth Flow: Done. `OAuth2Flow` implements `Flow` and uses the `OAuthProvider` trait in `authkestra-engine/src/flow/oauth2.rs`.
- [ ] Refactor OAuth flow to use stateless encrypted cookies (#18): *Status unclear without checking #18 specifically, but `OAuth2Flow` implementation currently returns errors regarding missing direct flow execution for encrypted state.*
- [x] 5. Refactor Session Crate: Done. `authkestra-session` exists with memory, redis, and sql implementations separated.
- [x] 6. Rename Guard to Resource: Done. The crate is now named `authkestra-resource`.
- [ ] Enforce standard JWT fields and isolate custom claims (#17): *Status unclear without deep diving into #17. There is a plan file for ticket 17 indicating it might need work.*
- [ ] Implement in-memory caching and background refresh for OIDC Discovery (#19): *Status unclear.*
- [x] 7. Create Golden Example: Done. Examples demonstrate the new architecture.

## Conclusion and Next Steps
The primary missing component for Ticket #22 (and subsequently blocking #23) is applying the `#[async_trait]` macro to the `Provider` trait and all its implementations across the workspace. Additionally, the duplicate `Provider` definition in `authkestra-engine/src/lib.rs` needs to be removed.
