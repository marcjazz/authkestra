## Goal Description
This plan addresses multiple maintenance and documentation tasks requested:
1. Update `jsonwebtoken` dependency to version `11.x`.
2. Fulfill promises of improvement found in the codebase and documentation (WebAuthn helper methods and OAuth2 nonce validation).
3. Update version references in `devsig` and `op-server` documentation.
4. Introduce a tab system (`<Tabs>`) in the docs for Axum vs Actix code snippets (`devsig` and `resource-server`).
5. Answer architectural and Markdown-related questions (endpoints in `OpConfig`, `[!CAUTION]` tags, and Stateless OAuth).
6. Update the comparison matrix to reflect recently added features.
7. **(New)** Link directly to GitHub source files when examples are cited in the docs.
8. **(New)** Add tests for new code to help push the codebase coverage toward the >70% goal.

## Answers to Your Questions

**Are the endpoints locations optional in the `opconfig`? Does it support relative path also?**
Looking at `crates/authkestra-op/src/config.rs`, the `OpConfig` struct does **not** have fields for `authorization_endpoint`, `token_endpoint`, etc. The documentation in `op-server.md` is outdated and incorrectly shows these as struct fields. In reality, `OpConfig` computes these dynamically as absolute URLs based on the `issuer` (e.g., `format!("{}/authorize", self.issuer)`). Therefore, they are not optional fields you can provide, nor do they support custom relative paths; they are strictly derived from the issuer base URL to comply with standard OIDC discovery expectations. We will fix the documentation to reflect the true struct shape.

**I see thing like `[!CAUTION]`, I'm not sure if it's a markdown interpretation issue or it's meant to be like that**
Ah, you are absolutely right! Because the `website` uses Astro Starlight, it does not use GitHub Flavored Markdown alerts (`> [!CAUTION]`). Instead, Starlight uses Markdown directives (e.g., `:::caution`). When Starlight encounters the GFM syntax, it just renders it as a literal blockquote text, which is incorrect. We will plan to replace all instances of GFM alerts (`> [!TIP]`, `> [!CAUTION]`, etc.) with Starlight's directive syntax (`:::tip`, `:::caution`, etc.) across the docs.

**Is it impossible to provider wired endpoint for stateless Oauth?**
In the framework-agnostic core (`authkestra-engine`), yes, it is impossible to provide a fully wired endpoint for Stateless OAuth because stateless OAuth requires writing and reading `state` and `nonce` from encrypted HTTP cookies. The core does not know about HTTP requests or cookies. However, it is fully possible to provide wired endpoints in the adapter crates (`authkestra-axum` and `authkestra-actix`), as they have access to the framework's HTTP context and can manage the encrypted cookies automatically before passing the verified state down to the core engine.

## Proposed Changes

### `Cargo.toml` updates
Update `jsonwebtoken` to version `11` in all crates.

### Code Improvements & Tests (Targeting >70% Coverage)
#### [MODIFY] `crates/authkestra-engine/src/engine.rs`
Add a simplified WebAuthn authentication start method to `Engine` to fulfill the promise in `passkeys.md` (`// This specific extraction will be simplified in a future release!`).
```rust
impl Engine {
    pub fn start_webauthn(&self, passkeys: &[Passkey]) -> Result<(ChallengeResponse, AuthState), Error> {
        let method = self.auth_methods.get("webauthn").ok_or(Error::MethodNotFound)?;
        // Downcast and call...
    }
}
```
*We will add corresponding unit tests in `src/tests.rs` to cover this new helper.*

#### [MODIFY] `crates/authkestra-engine/src/flow/oauth2.rs`
Implement the TODO: `// TODO: Validate nonce if present in identity/ID token`.
We will add logic to verify that the `nonce` claim in the decoded ID Token matches the expected nonce stored in the user's session state.
*We will add a new unit test for `oauth2.rs` testing successful and failed nonce validation.*

### Documentation Updates
#### [MODIFY] `website/src/content/docs/**/*.md`
Find and replace all GFM alerts (e.g. `> [!TIP]`) with Astro Starlight directives:
```markdown
:::tip
This is a tip.
:::
```

#### [MODIFY] `website/src/content/docs/providers/passkeys.md`
Remove the comment about the future release and update the snippet to use the new simplified `engine.start_webauthn(&passkeys)` method.

#### [MODIFY] `website/src/content/docs/advanced/op-server.md`
- Update the crate version from `0.2.3` to `0.3.0`.
- Fix the `OpConfig` instantiation code snippet, removing the endpoint fields that don't actually exist on the struct.
- **Add hrefs to GitHub examples**: When `op_server.rs`, `axum_op_server_attestation.rs`, and `actix_op_server_attestation.rs` are cited, wrap them in links pointing to `https://github.com/marcjazz/authkestra/tree/main/crates/authkestra/examples/...`.

#### [MODIFY] `website/src/content/docs/providers/device-signatures.md`
- Update `authkestra-devsig` version from `0.1.0` to `0.3.0`.
- Combine Axum and Actix wiring sections into a single section using Astro `<Tabs>` and `<TabItem>`.

#### [MODIFY] `website/src/content/docs/advanced/resource-server.md`
- Update `authkestra-resource` version to `0.3.0`.
- Refactor the code snippets to use Astro `<Tabs>` and `<TabItem>` for Axum vs Actix framework examples.

#### [MODIFY] `website/src/content/docs/concepts/comparison.mdx`
Update the matrix to show `✅ Native Support` / `✅ Built-in` for:
- WebAuthn/Passkeys
- Bot Protection
- Device Signatures (DevSig)
- Multi-factor Authentication (MFA)
Remove all `⏳ Coming Soon` markers for these features.

## Verification Plan

### Automated Tests
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

### Coverage Tracking
To ensure we maintain or exceed the 70% coverage goal, we can run a coverage tool (e.g., `cargo llvm-cov` or `cargo tarpaulin`) after making the code changes to verify that the newly added logic (WebAuthn helper, Nonce validation) is fully covered.

### Manual Verification
- Review the generated documentation changes locally by checking the raw Markdown to ensure Astro `<Tabs>` and `:::` directives are formatted correctly.
- Ensure the Rust compiler passes all strict lint checks after the `jsonwebtoken` v11 upgrade.
