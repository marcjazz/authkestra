You are a senior Rust library architect.

Design a production-quality Rust workspace for an authentication framework called "authly".

GOAL:
Create a modular, framework-agnostic authentication orchestration system inspired by Auth.js and Passport.js, but idiomatic to Rust. The system must emphasize explicit control flow, strong typing, and composability over runtime plugins or magic middleware.

REQUIREMENTS:
- Use a Cargo workspace with multiple crates
- Separate concerns clearly between core logic, OAuth flow orchestration, session handling, token handling, providers, and web framework adapters
- Avoid JavaScript-style dynamic strategies or runtime registries
- Prefer traits, enums, and explicit types
- No macros unless absolutely necessary
- Assume Axum as the first supported framework

CORE CRATES TO DESIGN:
1. authly-core
   - Defines error types, Identity struct, Provider traits
2. authly-flow
   - Handles OAuth2/OIDC authorization code flows
3. authly-session
   - Cookie-based session storage abstraction
4. authly-token
   - JWT and PASETO token issuance and validation
5. authly-providers-github
   - GitHub OAuth provider implementation
6. authly-axum
   - Axum integration helpers (routes, extractors)

OUTPUT EXPECTATIONS:
- Propose the directory structure
- Provide example public APIs (traits, structs, functions)
- Include minimal Rust code stubs for each crate
- Show how an Axum app would use authly to implement "Login with GitHub"
- Favor clarity, correctness, and extensibility over completeness

CONSTRAINTS:
- No unsafe Rust
- No global mutable state
- No hidden request mutation
- OAuth logic must be reusable outside Axum

TONE:
Professional, precise, and idiomatic Rust. Avoid JavaScript patterns.

DELIVERABLE:
A well-structured Rust workspace design with code skeletons and a simple end-to-end example.
