# Authkestra Agent Rules

- **Typestate Builder Pattern**: Use `Authkestra::builder()` which enforces compile-time availability of methods (e.g., `create_session` only exists if `session_store` is provided).
- **RFC-001 Migration**: The project is migrating to a unified `authkestra-engine`. Do not add logic to `authkestra-core` or `authkestra-flow`; target `AuthEngine` and plugin interfaces (`AuthMethod`, `Flow`).
- **Trait Objects vs Generics**: Prefer `Box<dyn Trait>` (e.g., `Box<dyn AuthMethod>`) over generics for I/O bound paths to optimize compilation time and DX.
- **Framework Agnostic**: The core must remain framework-independent. Axum/Actix integrations live in separate adapter crates (`authkestra-axum`, `authkestra-actix`) and use extractors (`AuthSession(session)`).
- **Stateless OAuth**: Store OAuth `state` and `nonce` in encrypted cookies, never in the database.
- **OIDC Discovery**: Cache discovery documents via background `tokio::spawn` tasks, avoid per-request fetching.
- **Database Agnosticism**: Never enforce schemas; always define data access via traits (e.g., `UserStore`, `SessionStore`).