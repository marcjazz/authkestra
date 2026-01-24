# Next Steps for authly-rs Development

This roadmap outlines the steps to reach a production-ready state.

## 1. Verify Implementation (Done)
- [x] Implement real OAuth logic in `authly-providers-github`.
- [x] Implement Redis persistence in `authly-session`.
- [x] Add unit tests for providers and session store.

## 2. Run and Verify Example (Done)
- [x] Configure environment variables in `.env`.
- [x] Run the example application: `cargo run --example axum_github`.
- [x] Verify GitHub login and session persistence.

## 3. Expand Provider Support
Add more OAuth providers to make the library more versatile.
- [x] **Google:** Implement `authly-providers-google`.
- [x] **Discord:** Implement `authly-providers-discord`.

## 4. Enhanced Security & Features
- [x] CSRF Protection: Ensure the `state` parameter in OAuth is cryptographically secure and validated.
- [x] Token Rotation: Implement refresh tokens if the provider supports it.
- [x] User Mapping: Allow mapping provider identities to a local user database (e.g., using an ORM like `sqlx` or `diesel`).

## 5. Documentation (Done)
- [x] Add `README.md` for each crate.
- [x] Add API documentation (Rustdoc) for public traits and structs.

## 6. Security Hardening
- [ ] **PKCE Support:** Implement Proof Key for Code Exchange for better security, especially for public clients.
- [ ] **Secure Session Defaults:** Audit cookie security settings and provide best-practice defaults.

## 7. Extended Storage & Integrations
- [ ] **Memory Session Store:** Make the `MemoryStore` public in `authly-session` for development use.
- [ ] **SQL Session Store:** Add support for PostgreSQL/MySQL/SQLite using `sqlx`.
- [ ] **Actix-web Support:** Implement a sister crate for `authly-axum` to support the Actix ecosystem.

## 8. Protocol Completeness
- [ ] **OIDC (OpenID Connect):** Implement ID Token validation and discovery document support.
- [ ] **Logout Flow:** Add standardized session invalidation and cookie clearing helpers.

## 9. Reliability & Distribution
- [ ] **CI/CD:** Set up GitHub Actions for automated testing across different Rust versions.
- [ ] **Integration Testing:** Add comprehensive integration tests with Mock servers for OAuth providers.
- [ ] **Crates.io Readiness:** Finalize metadata, licenses, and documentation for initial publishing.
