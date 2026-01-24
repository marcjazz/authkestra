# Next Steps for authly-rs Development

This roadmap outlines the steps to reach a production-ready state.

## 1. Verify Implementation (Done)
- [x] Implement real OAuth logic in `authly-providers-github`.
- [x] Implement Redis persistence in `authly-session`.
- [x] Add unit tests for providers and session store.

## 2. Run and Verify Example
The example application `examples/axum_github.rs` is ready to run.

*   **Action:** Configure environment variables in `.env` (use `.env.example` as a template).
*   **Run:** `cargo run --example axum_github`
*   **Verify:** Log in with GitHub and check if the session cookie is set and persisted in Redis (if enabled) or memory.

## 3. Expand Provider Support
Add more OAuth providers to make the library more versatile.
*   **Google:** Implement `authly-providers-google`.
*   **Discord:** Implement `authly-providers-discord`.

## 4. Enhanced Security & Features
*   **CSRF Protection:** Ensure the `state` parameter in OAuth is cryptographically secure and validated.
*   **Token Rotation:** Implement refresh tokens if the provider supports it.
*   **User Mapping:** Allow mapping provider identities to a local user database (e.g., using an ORM like `sqlx` or `diesel`).

## 5. Documentation
*   Add `README.md` for each crate.
*   Add API documentation (Rustdoc) for public traits and structs.
