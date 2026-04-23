# Architectural Review: Critical Analysis of Open Challenges

As the architectural blueprint for Authkestra shapes up in the Book, several critical design ambiguities have been highlighted. Below is an architect's critical review of these open questions, detailing how resolving them impacts project direction, scalability, and future expansion.

---

## Chapter 2: Core Engine and Identity

### Standard vs. Custom Claims

- **Challenge:** Should we enforce standard JWT fields strongly typed, or leave them inside the `extra` HashMap?
- **Architect's View:** We must enforce standard fields (e.g., `iss`, `aud`, `exp`, `iat`) as strongly typed fields on the `Claims` struct. Authentication heavily relies on standardization. Leaving these to a loose `HashMap` invites runtime bugs and makes OIDC interoperability brittle. Custom claims belong in an `extra` map, but standards must be enforced at compile time.

### Multiple Linked Identities

- **Challenge:** How do we represent a user who has logged in with both GitHub and Google?
- **Architect's View:** The `Identity` struct should be lightweight and represent the **current** authenticated context, not the entire database record. A bloated `Identity` struct degrades cache performance (e.g., in Redis). Linked accounts should be handled at the database level. The `Identity` might contain a `user_id` and the `current_provider`, and the application can fetch linked accounts separately if needed.

### Trait Objects vs Generics

- **Challenge:** Is `Box<dyn AuthMethod>` acceptable, or should we use generics?
- **Architect's View:** Authentication is inherently I/O bound (database lookups, network requests to OAuth providers). The microscopic performance penalty of dynamic dispatch (vtable lookups) via `Box<dyn Trait>` is entirely negligible here. Using trait objects massively simplifies the developer experience (DX) and builder pattern. We prioritize DX and compilation times over nanosecond optimizations in I/O bound paths.

---

## Chapter 3: Core Traits

### `async_trait` Dependency

- **Challenge:** Should we use `#[async_trait]` or native AFIT (Async Functions in Traits)?
- **Architect's View:** Native AFIT is stable, but enforcing `Send` bounds (which web frameworks like Axum strictly require) in public traits without `async_trait` can lead to complex and ugly bounds (`impl Future<Output = ...> + Send`). For now, `#[async_trait]` provides a cleaner DX for contributors. We should abstract this carefully so it can be migrated to native AFIT when the `Send` bound ergonomics improve in Rust.

### Context Object (`AuthContext`)

- **Challenge:** What belongs in `AuthContext`?
- **Architect's View:** `AuthContext` must be framework-agnostic. It should wrap the standard `http::Request<()>` parts (headers, URI, query params). Coupling the core engine to Axum or Actix types immediately kills the modularity of the framework.

---

## Chapter 4: Flows and Protocols

### State Storage

- **Challenge:** Where should OAuth `state` and `nonce` parameters be stored?
- **Architect's View:** For infinite horizontal scalability, intermediate flow state should be stored in **encrypted, short-lived cookies** (stateless), not in a database. Hitting a database twice just to validate an OAuth state token creates unnecessary bottlenecks under high load.

### OIDC Discovery

- **Challenge:** Should discovery parsing be dynamic or cached?
- **Architect's View:** Discovery documents must be fetched at startup and cached in memory. A background `tokio::spawn` task should refresh them periodically based on the `Cache-Control` headers. Fetching discovery documents per-request will destroy latency and rapidly hit rate limits at identity providers.

---

## Chapter 5: Authorization and Policies

### DSL vs. Code

- **Challenge:** Custom DSL (like Rego/Cedar) or Rust code for policies?
- **Architect's View:** Rust closures are fast but require a full server rebuild and redeploy to change a business rule. For an enterprise-grade auth system, a DSL (like AWS Cedar) is vastly superior. It allows policies to be updated in a database and evaluated dynamically at runtime, enabling SaaS multi-tenancy and zero-downtime policy updates.

### Data Hydration for ABAC

- **Challenge:** How does the policy engine fetch context (e.g., resource ownership)?
- **Architect's View:** The core engine should never touch the database directly for resource hydration. We must define a `ResourceLoader` trait. The application implements this trait to query its own database and feed the requested context into the `PolicyEngine`.

---

## Chapter 6: Adapters and Integrations

### Extractors vs Middleware

- **Challenge:** In Axum, custom extractors or middleware?
- **Architect's View:** Both serve different purposes. Custom extractors (`async fn handler(user: Identity)`) provide the best DX for route-specific logic. Middleware is better suited for global URL protection rules. We must provide both.

### Database Schema

- **Challenge:** Enforce table schemas or provide traits?
- **Architect's View:** Enforcing a specific database schema is a fatal mistake that alienates 90% of developers who have existing databases. We must provide traits (e.g., `UserStore`), allowing developers to map their existing tables to our interfaces.

---

## Chapter 7: Admin API and AI Layer

### API Serving

- **Challenge:** Embedded module or standalone binary?
- **Architect's View:** It must be deployable as both. We expose an Axum `Router` (or Actix equivalent) that developers can mount into their existing app (`app.nest("/admin", authkestra_admin::router())`). For the Keycloak-style deployment, we provide a pre-compiled binary that simply runs that router.

### Telemetry Data

- **Challenge:** Collecting AI telemetry without impacting latency?
- **Architect's View:** Telemetry must be collected asynchronously. The authentication flow should push lightweight events onto an in-memory channel (e.g., `tokio::sync::mpsc`). A separate background worker reads from this channel and processes the AI telemetry, ensuring the critical auth path remains strictly unblocked.
