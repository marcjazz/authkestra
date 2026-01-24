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

## 5. Documentation
- [x] Add `README.md` for each crate.
- [x] Add API documentation (Rustdoc) for public traits and structs.
