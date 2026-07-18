# Authkestra Agent Rules

- **Typestate Builder Pattern**: Use `Authkestra::builder()` which enforces compile-time availability of methods (e.g., `create_session` only exists if `session_store` is provided).
- **RFC-001 Migration**: The project is migrating to a unified `authkestra-engine`. Do not add logic to `authkestra-core` or `authkestra-flow`; target `AuthEngine` and plugin interfaces (`AuthMethod`, `Flow`).
- **Trait Objects vs Generics**: Prefer `Box<dyn Trait>` (e.g., `Box<dyn AuthMethod>`) over generics for I/O bound paths to optimize compilation time and DX.
- **Framework Agnostic**: The core must remain framework-independent. Axum/Actix integrations live in separate adapter crates (`authkestra-axum`, `authkestra-actix`) and use extractors (`AuthSession(session)`).
- **Stateless OAuth**: Store OAuth `state` and `nonce` in encrypted cookies, never in the database.
- **OIDC Discovery**: Cache discovery documents via background `tokio::spawn` tasks, avoid per-request fetching.
- **Database Agnosticism**: Never enforce schemas; always define data access via traits (e.g., `UserStore`, `SessionStore`).
- **OP (RFC-003) — redirect_uri**: Always match `redirect_uri` by exact string equality against `ClientRegistration::redirect_uris`. Never add prefix, wildcard, or normalized matching, even if it seems convenient for local dev.
- **OP (RFC-003) — code replay**: `AuthorizationCodeStore::consume_code` must check-and-invalidate a code atomically (single storage operation/transaction). Never implement it as a separate lookup followed by a separate update.
- **OP (RFC-003) — token signing**: OP-issued tokens (ID tokens, and anything a third-party relying party must verify) must use asymmetric signing (RS256+) with a `kid`. Never use `TokenManager`'s existing HS256 path for tokens handed to an external client.
- **OP (RFC-003) — error responses**: Do not let OP error responses distinguish "client doesn't exist" from "client exists but redirect_uri is wrong" from "code doesn't exist" vs "code already used." Collapse these into the same generic error at the response layer to avoid enumeration.