# Migration Plan: Ticket #10 (authkestra-engine)

## Goal
Create the `authkestra-engine` and establish the core trait boundaries without altering business logic.

## Steps
1. **Branch Creation**
   - Create and checkout branch `issue-10`.

2. **Crate Initialization**
   - Run `cargo new --lib authkestra-engine`.
   - Update workspace `Cargo.toml` to include the new crate.
   - Configure `authkestra-engine/Cargo.toml` with dependencies from the crates being merged.

3. **Code Migration**
   - **`authkestra-core`**: Move to `authkestra-engine/src/auth` (or direct integration depending on the module).
   - **`authkestra-flow`**: Move to `authkestra-engine/src/flow`.
   - **`authkestra-token`**: Move to `authkestra-engine/src/token`.
   - Setup `authkestra-engine/src/protocol` if any files fit there.
   - Re-export modules in `authkestra-engine/src/lib.rs`.

4. **Integration & Compilation**
   - Update references in other crates (like `authkestra-axum`, `authkestra-actix`, etc.) that depended on the old crates, changing them to depend on `authkestra-engine`.
   - Note: The ticket specifically says "Move code from `authkestra-core`, `authkestra-flow`, and `authkestra-token` into `authkestra-engine/src/{auth, flow, token, protocol}`". We will simply copy/move the files and set up module declarations.
   - Remove `authkestra-core`, `authkestra-flow`, and `authkestra-token` from workspace `Cargo.toml` (or leave them empty depending on if they are completely removed, but ticket implies moving code).

5. **Validation**
   - Run `cargo fmt` to format code.
   - Run `cargo clippy` to check for lints.
   - Run `cargo test --workspace` to ensure everything works without logic changes.
