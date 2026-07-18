# Chapter 6: Adapters and Integrations

To be truly framework-agnostic, the core engine must not know about HTTP requests or specific database connections. Adapters bridge this gap. Our architecture strictly separates interfaces from implementations—for example, treating `authkestra-session` purely as a contract by default, while implementations plug in dynamically via feature flags (e.g., `memory`, `redis`).

## Web Framework Adapters

We provide first-class integration layers for:

- **Axum** (`authkestra-axum`)
- **Actix Web** (`authkestra-actix`)

These are not just loose helpers, but robust, native-feeling extensions providing middleware, extractors, and routing guards. They map standard `AuthContext` requests into the framework's native HTTP response types.

### Supported Session Providers

- **Memory** (`memory` feature in `authkestra-session`) for local development.
- **Redis** (`redis` feature in `authkestra-session`) via `redis-rs`.
- **SQL** (`sql-postgres`, `sql-mysql` features in `authkestra-session`) for Postgres, MySQL.

## Database Adapters

For session storage and user data, adapters rely strictly on traits (`SessionStore`, etc), ensuring developers can plug their existing databases directly into Authkestra via feature-flagged implementations or custom code.

### Architectural Decisions & Future Direction

- **Extractors vs Middleware:** In Axum and Actix, both serve different purposes and we must provide both. Custom extractors (`async fn handler(user: Identity)`) provide the best developer experience (DX) for route-specific logic. Middleware is better suited for global URL protection rules.
- **Database Schema:** Enforcing a specific database schema is a fatal mistake that alienates 90% of developers who have existing databases. We must provide traits (e.g., `UserStore`), allowing developers to map their existing tables to our interfaces instead of forcing migrations.
