# Authkestra Roadmap

This roadmap is designed for contributors and maintainers to guide Authkestra from its current state to a next-generation, community-driven authentication platform.

---

## 0. North Star

> **Authkestra = composable, verifiable auth primitives for humans and AI systems.**

- Embedded like better-auth
- Deployable like Keycloak
- Safer for AI-generated systems

---

## 1. Foundational Concepts

Before contributing, review these:

- [OAuth 2.0](https://oauth.net/2/)
- [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [JWT](https://jwt.io/introduction)
- [PASETO](https://paseto.io/)
- [RBAC](https://auth0.com/docs/manage-users/access-control/rbac)
- [ABAC](https://en.wikipedia.org/wiki/Attribute-based_access_control)
- [WebAuthn Guide](https://webauthn.guide/)

---

## 2. Architecture & Crate Structure

**Target Zones:**

1. Engine (core logic, no frameworks)
2. Extensions (providers, flows, storage)
3. Adapters (axum, actix, etc.)

**Proposed Crates:**

- `authkestra-engine` (core, flow, token merged)
- `authkestra-token` (token creation)
- `authkestra-resource` (validation, enforcement)
- `authkestra-session` (traits only)
- `authkestra-session-memory`, `-redis`, `-sql` (implementations)
- `authkestra-oidc`, `authkestra-providers-*` (providers)
- `authkestra-axum`, `authkestra-actix` (adapters)
- `authkestra-macros` (optional)
- `authkestra-examples` (integration tests, docs)

---

## 3. Phased Roadmap

### Phase 0 — Stabilize Core

- Normalize APIs
- Define internal interfaces: `AuthMethod`, `Provider`, `PolicyEngine`

### Phase 1 — Modern Auth Baseline

- Add WebAuthn, Magic Links, TOTP as plugins
- Ensure plugin architecture for extensibility

### Phase 2 — Advanced Authorization

- Implement RBAC, then ABAC-lite
- Plan for a policy DSL

### Phase 3 — Developer Experience

- Build CLI
- TypeScript SDK
- Local dev mode

### Phase 4 — Deployment Duality

- Embedded SDK (npm, minimal config)
- Server mode (Docker, REST + Admin API, multi-tenant)

### Phase 5 — AI-Native Workflows

- Config → system generator
- Validation engine (security checks)
- AI hooks (audit, explain, generate)

---

## 4. Admin & User Management

- Admin APIs for user management
- RBAC/ABAC policy management
- User management dashboard (web UI)
- Database adapters (Postgres, MySQL, SQLite, etc.)

---

## 5. Community & Contribution

- Pin the North Star in README, CONTRIBUTING, docs
- Use GitHub Discussions for design debates
- Label issues for onboarding (`good first issue`, `help wanted`)
- Encourage RFCs for major changes

---

## 6. Resources

- [Keycloak Docs](https://www.keycloak.org/documentation)
- [better-auth](https://github.com/epic-web-dev/better-auth)
- [Rust async book](https://rust-lang.github.io/async-book/)
- [Rust trait objects](https://doc.rust-lang.org/book/ch17-02-trait-objects.html)

---

For the full vision and architectural review, see [conversion.md](../conversion.md).
