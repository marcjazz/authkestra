# Structural Cleanup: Move crates under `crates/`

## Goal
Move all 14 crate directories into a centralized `crates/` folder to separate source code from workspace metadata/docs.

## Sequence Note
**DO NOT EXECUTE during the active OP (RFC-003) push.** Wait until `authkestra-token` and `authkestra-op` PRs are stabilized to avoid massive merge conflicts. This should be an isolated, feature-freeze PR.

## Steps
1. Create `crates/` directory.
2. Move `authkestra-engine`, `authkestra-op`, `authkestra-axum`, etc., into `crates/`.
3. Update `members` list in root `Cargo.toml`.
4. Update `.github/scripts/publish-crate.sh` and any CI paths.
5. Update markdown links in documentation that reference old root paths.
6. Verify with `cargo build --workspace` and `cargo test --workspace`.
