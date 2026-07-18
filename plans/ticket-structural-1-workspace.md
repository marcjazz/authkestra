# Structural Cleanup: Workspace Configuration & Feature Flags

## Goal
Centralize crate versions and metadata into `[workspace.package]` and `[workspace.dependencies]`, and ensure feature flags are consistently exposed across the facade.

## Steps
1. **Workspace Package Details**
   - Move `edition = "2021"`, `license`, `repository`, `keywords`, etc. to `[workspace.package]` in the root `Cargo.toml`.
   - Update all member crates to use `edition.workspace = true`, `license.workspace = true`, etc.

2. **Workspace Dependencies**
   - Consolidate all internal path-dependencies (`authkestra-engine`, etc.) into `[workspace.dependencies]` in the root `Cargo.toml`.
   - Update all member crates to use `authkestra-engine = { workspace = true }`.

3. **Facade Feature Surface**
   - Add a top-level `resource = ["dep:authkestra-resource"]` feature to the `authkestra` facade crate to match `session`, `token`, etc.
