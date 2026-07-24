# RFC-001: Authkestra Architecture Migration to Next-Gen Unified Framework

## 1. Summary

This document proposes a comprehensive migration plan to transition Authkestra from its current multi-crate, loosely coupled structure into a unified, modular authentication and authorization engine (`authkestra-engine`). The target architecture will support both embedded application integration (similar to `better-auth`) and standalone server deployment (similar to `Keycloak`), while remaining highly composable, safe for AI-generated integrations, and developer-friendly.

## 2. Motivation

Authkestra currently consists of numerous specialized crates (`authkestra-core`, `authkestra-flow`, `authkestra-token`, `authkestra-session`, `authkestra-guard`, etc.). While this high level of modularity demonstrates the breadth of the project, it suffers from several architectural issues:

- **Blurry Boundaries:** Crates mix protocol concerns, abstractions, state handling, and execution logic.
- **Missing Core Engine:** There is no central orchestrator (`Engine`) to tie flows, providers, sessions, and tokens together.
- **Naming Inconsistencies:** Crates like `authkestra-guard` handle JWT logic rather than just enforcement.
- **Developer Friction:** A steep learning curve prevents users from achieving a simple "golden path" integration in a few lines of code.

To scale the community and build a robust, AI-native authentication platform, Authkestra must consolidate its core logic into a unified engine, expose strict plugin interfaces, and provide a clear DX facade.

## 3. Target Architecture

The new architecture will be split into three distinct zones:

### 3.1. Layer 1: Engine (The Core)

A framework-agnostic runtime that acts as the brain of the system.

- **Crate:** `authkestra-engine` (Merging `core`, `flow`, `token`, and parts of `guard`)
- **Responsibilities:** Identity modeling, trait definitions (`Authenticator`, `Flow`, `Provider`, `SessionStore`), protocol helpers (PKCE, OIDC discovery), and the central `Engine` orchestrator.

### 3.2. Layer 2: Extensions (Plugins)

Pluggable components that implement the traits defined by the engine.

- **Crates:** `authkestra-session-memory`, `authkestra-session-redis`, `authkestra-session-sql`, `authkestra-oidc`, `authkestra-providers-*`.
- **Responsibilities:** Storage backends, specific OAuth/OIDC provider configurations, and advanced auth methods (WebAuthn, TOTP, Magic Links).

### 3.3. Layer 3: Adapters (Integrations)

Framework-specific wrappers that integrate the engine into web applications.

- **Crates:** `authkestra-axum`, `authkestra-actix`, `authkestra-resource` (formerly `guard`).
- **Responsibilities:** Middleware, extractors, route guards, and framework-native APIs.

### 3.4. Layer 4: Platform (Future)

Operator-facing surfaces built on top of the engine.

- **Components:** Admin API, User Management Dashboard, CLI.

---

## 4. Core Concepts & Trait Definitions

To achieve true composability, all components must communicate through strict interfaces defined in `authkestra-engine`.

### 4.1. Identity

The canonical representation of an authenticated subject.

```rust
pub struct Identity {
    pub id: String,
    pub claims: Claims,
}
```

### 4.2. AuthMethod

A mechanism used to authenticate a user.

```rust
#[async_trait]
pub trait AuthMethod {
    async fn authenticate(&self, input: AuthInput) -> Result<Identity, AuthError>;
}
```

### 4.3. Flow

Orchestrates the steps of an authentication protocol (e.g., OAuth2, Device Flow).

```rust
#[async_trait]
pub trait Flow {
    async fn execute(&self, ctx: FlowContext) -> Result<FlowResult, AuthError>;
}
```

### 4.4. Provider

An external identity source (e.g., Google, GitHub). Providers should contain zero business logic—only configuration and mapping.

```rust
#[async_trait]
pub trait Provider: Send + Sync {
    async fn config(&self) -> ProviderConfig;
}
```

### 4.5. SessionStore & TokenService

Interfaces for stateful and stateless identity persistence.

```rust
#[async_trait]
pub trait SessionStore {
    async fn get(&self, id: &str) -> Option<Session>;
    async fn set(&self, session: Session) -> Result<(), AuthError>;
}

pub trait TokenService {
    fn issue(&self, identity: &Identity) -> Token;
    fn verify(&self, token: &str) -> Result<Identity, AuthError>;
}
```

### 4.6. Engine (The Orchestrator)

The central runtime that ties everything together.

```rust
pub struct Engine {
    providers: Vec<Box<dyn Provider>>,
    methods: Vec<Box<dyn AuthMethod>>,
    flows: Vec<Box<dyn Flow>>,
    session_store: Box<dyn SessionStore>,
    token_service: Box<dyn TokenService>,
}

impl Engine {
    pub fn builder() -> EngineBuilder {
        EngineBuilder::new()
    }
}
```

**Golden Path Example:**

```rust
let engine = Engine::builder()
    .with_provider(GoogleProvider::new(...))
    .with_method(Credentials::new())
    .with_session_store(MemoryStore::new())
    .with_token_service(JwtService::new(...))
    .build();
```

---

## 5. Step-by-Step Migration Plan

### Phase 1: Engine Consolidation (Immediate Priority)

**Goal:** Create the `authkestra-engine` and establish the core trait boundaries.

1. **Create `authkestra-engine`:** Initialize the new crate.
2. **Merge Crates:** Move code from `authkestra-core`, `authkestra-flow`, and `authkestra-token` into `authkestra-engine/src/{auth, flow, token, protocol}`. Do not alter business logic yet.
3. **Define Core Traits:** Implement the `AuthMethod`, `Flow`, `Provider`, `SessionStore`, and `TokenService` traits in `authkestra-engine`.
4. **Implement `Engine` Builder:** Create the `Engine` struct and its builder API.
5. **Refactor OAuth Flow:** Update the existing OAuth implementation to implement the `Flow` trait and use the `Provider` trait.
6. **Refactor Session Crate:** Split `authkestra-session` into an interface-only crate (`authkestra-session`) and implementation crates (`authkestra-session-memory`, etc.).
7. **Rename Guard:** Rename `authkestra-guard` to `authkestra-resource` and focus it strictly on validation and enforcement (middleware/extractors).
8. **Create Golden Example:** Update `authkestra-examples` to demonstrate the new `Engine::builder()` API using Axum/Actix.

### Phase 2: Authentication Expansion

**Goal:** Expand auth methods as plugins complying with `AuthMethod`.

1. Implement **WebAuthn / Passkeys** as a new plugin crate (`authkestra-webauthn`).
2. Implement **Magic Links** (`authkestra-magic-link`).
3. Implement **TOTP / MFA** (`authkestra-totp`).
4. Establish the unified model for linked identities (one user -> multiple credentials/providers).

### Phase 3: Authorization Foundation

**Goal:** Transition from authentication to robust authorization enforcement.

1. Implement **RBAC** (Roles, Permissions, Bindings) within the engine.
2. Develop **ABAC-lite** (Ownership checks, scopes, tenant constraints).
3. Integrate policy evaluation into `authkestra-resource` guards.

### Phase 4: Platform & Admin API

**Goal:** Enable external operability and SaaS integrations.

1. Define RESTful Admin APIs for Users, Identities, Sessions, Roles, and Tenants.
2. Create `authkestra-admin-api` crate exposing these routes.
3. Build the Next.js User Management Dashboard consuming the Admin API.

### Phase 5: Storage & Database Adapters

**Goal:** Production-grade data persistence.

1. Create `authkestra-store-postgres`, `authkestra-store-redis`, and `authkestra-store-sqlite`.
2. Ensure these crates strictly implement `SessionStore`, `UserStore`, etc., without leaking business logic.

### Phase 6: AI-Native DX & Code Generation

**Goal:** Make Authkestra the premier choice for AI-assisted development.

1. Define a declarative YAML/JSON auth config schema.
2. Build the `authkestra` CLI (`authkestra init`, `authkestra add google`).
3. Implement flow validation and security linting against the declarative config.

---

## 6. Migration Rules & Constraints

1. **No Breaking User-Space APIs in Phase 1 (Where Possible):** During the initial merge, preserve existing structs where feasible. The breaking changes occur when transitioning to the `Engine::builder()` pattern.
2. **Every Feature is a Plugin:** Do not hardcode WebAuthn, TOTP, or specific DB logic into the engine. They must implement the defined traits.
3. **One Identity Lifecycle:** All flows MUST resolve to the unified `Identity` struct.
4. **Dogfooding:** The Admin Dashboard MUST be authenticated using Authkestra itself.

## 7. Next Steps

- Review and approve this RFC.
- Create tracking issues for Phase 1 (Engine Consolidation).
- Update the community `docs/roadmap.md` and create `docs/architecture.md` reflecting these finalized decisions.
