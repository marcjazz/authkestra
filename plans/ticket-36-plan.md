# Ticket #36: Merge Providers in a single crate with a feature-based strategy

## Goal

Consolidate individual provider crates (`authkestra-providers-github`, `authkestra-providers-google`, `authkestra-providers-discord`) into a single `authkestra-providers` crate using Cargo feature flags.

## Steps

### 1. Initialize `authkestra-providers`

- Create a new directory `authkestra-providers`.
- Initialize `Cargo.toml` with the following features:
  - `github`
  - `google`
  - `discord`
- Add shared dependencies (e.g., `authkestra-engine`, `serde`, `async-trait`).

### 2. Migrate Provider Logic

- **GitHub**: Move code from `authkestra-providers-github/src/lib.rs` to `authkestra-providers/src/github.rs`.
- **Google**: Move code from `authkestra-providers-google/src/lib.rs` to `authkestra-providers/src/google.rs`.
- **Discord**: Move code from `authkestra-providers-discord/src/lib.rs` to `authkestra-providers/src/discord.rs`.
- Update `authkestra-providers/src/lib.rs` to export these modules gated by features:

  ```rust
  #[cfg(feature = "github")]
  pub mod github;
  #[cfg(feature = "google")]
  pub mod google;
  #[cfg(feature = "discord")]
  pub mod discord;
  ```

### 3. Update Workspace Configuration

- Add `authkestra-providers` to `members` in the root `Cargo.toml`.
- Remove `authkestra-providers-github`, `authkestra-providers-google`, and `authkestra-providers-discord` from `members`.

### 4. Rewrite Imports and Dependencies

- Update `authkestra-examples/Cargo.toml` to use `authkestra-providers` with required features instead of individual crates.
- Update `authkestra-examples/examples/*.rs` to use new import paths (e.g., `authkestra_providers::github` instead of `authkestra_providers_github`).
- Update internal tests and other crates that depend on specific providers.

### 5. Cleanup

- Remove the old directories:
  - `authkestra-providers-github/`
  - `authkestra-providers-google/`
  - `authkestra-providers-discord/`
- Run `cargo check` and `cargo test --all-features` to ensure everything is working correctly.
