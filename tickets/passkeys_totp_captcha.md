# Ticket: WebAuthn, TOTP, and Bot Protection

## Goal Description
Enhance Authkestra's security primitives by implementing:
1. **Passkeys/WebAuthn & TOTP**: Built directly into the `authkestra-engine` crate behind optional features (`webauthn` and `totp`), avoiding new crate proliferation.
2. **Bot Protection (CAPTCHA)**: Framework-agnostic verifiers built directly into `authkestra-engine/src/captcha.rs` under a `captcha` feature flag (supporting Cloudflare Turnstile, hCaptcha, Google reCAPTCHA). Framework adapters (`authkestra-axum` and `authkestra-actix`) use it directly from the engine, avoiding redundant wrapper re-exports.
3. **Pluggable DB Storage (`SqlxCredentialStore`)**: Relational database persistence under `store/sql/` directory modules. Default table prefix is `ak_`.

---

## Design Refactoring

### 1. `authkestra-engine` (Optional Features & Core Traits)
*   **Cargo Features**: Added `webauthn` and `totp` feature gates to conditionally compile `webauthn-rs` and `totp-rs`. Added `captcha` feature to compile the generic HTTP client (`reqwest`) verifier.
*   **Core Trait (`CredentialStore`)**: Added the database-agnostic `store.rs` trait to persist user credentials (passkeys, TOTP keys).
*   **Refactored SQL Store**: Split the monolithic `sql.rs` into a clean folder module `store/sql/` consisting of:
    *   `mod.rs` (exporting the module)
    *   `session.rs` (isolated Session SQLx logic)
    *   `credential.rs` (implements SQLx `CredentialStore` with normalized columns for credentials)

### 2. Framework Adapters (`authkestra-axum` & `authkestra-actix`)
*   **Helpers Directory Module**: Refactored monolithic helper files into clean, directory-based structures:
    *   `helpers/mod.rs` (re-exports)
    *   `helpers/api.rs` (handlers & token managers)
    *   `helpers/cookie.rs` (cookie builder helpers)
*   **Framework Agnostic CAPTCHA**: Direct use of the core verifier from `authkestra_engine::captcha::*`, eliminating redundant wrapper modules.
