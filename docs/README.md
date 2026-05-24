# Authkestra Documentation

Welcome to the Authkestra documentation! This guide will help contributors and users understand the vision, architecture, and roadmap for Authkestra, and provide foundational resources for building the next generation of authentication systems.

---

## 🧭 North Star

**Authkestra = composable, verifiable auth primitives for humans and AI systems.**

- Embedded like better-auth
- Deployable like Keycloak
- Safer for AI-generated systems

> Pin this in README, CONTRIBUTING, and docs homepage.

---

## 🏗️ Foundational Concepts

Before contributing, review these core concepts and resources:

### 🔐 Identity & Auth basics

- [OAuth 2.0](https://oauth.net/2/)
- [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE](https://datatracker.ietf.org/doc/html/rfc7636)

### 🔑 Token systems

- [JWT](https://jwt.io/introduction)
- [PASETO (optional future)](https://paseto.io/)

### 🧠 Authorization models

- [RBAC](https://auth0.com/docs/manage-users/access-control/rbac)
- [ABAC](https://en.wikipedia.org/wiki/Attribute-based_access_control)

### 🔐 WebAuthn (future-critical)

- [WebAuthn Guide](https://webauthn.guide/)

---

## 🏛️ Architecture Overview

Authkestra is a modular auth platform, not a monolith or a simple library. It is structured as:

- **Engine**: Core logic, no frameworks
- **Extensions**: Providers, flows, storage
- **Adapters**: Framework integrations (axum, actix, etc.)

### Layered Structure

```
┌──────────────────────────────┐
│        SDK / CLI / AI        │
├──────────────────────────────┤
│   actix / axum adapters      │
├──────────────────────────────┤
│        Auth Engine           │
├──────────────────────────────┤
│ flows | providers | guards   │
├──────────────────────────────┤
│ token | session | identity   │
├──────────────────────────────┤
│          core                │
└──────────────────────────────┘
```

---

## 🛣️ Roadmap

### Phase 0 — Stabilize Core

- Normalize APIs
- Define internal interfaces (e.g., `AuthMethod`, `Provider`, `PolicyEngine`)

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

## 🧩 Crate/Module Structure (Target)

- `authkestra/` (DX façade)
- `authkestra-engine/` (merged core, flow, token)
- `authkestra-token/` (token creation)
- `authkestra-resource/` (validation, enforcement)
- `authkestra-session/` (traits only)
- `authkestra-session-memory/`, `-redis/`, `-sql/` (implementations)
- `authkestra-oidc/`, `authkestra-providers-*` (providers)
- `authkestra-axum/`, `authkestra-actix/` (adapters)
- `authkestra-macros/` (optional)
- `authkestra-examples/` (integration tests, docs source)

---

## 🛠️ Contributor Onboarding

1. Read the North Star and foundational concepts
2. Review the architecture and roadmap
3. Pick an area (engine, provider, adapter, etc.)
4. Join discussions, propose RFCs, or start with issues labeled `good first issue`

---

## 📚 Additional Resources

- [Keycloak Docs](https://www.keycloak.org/documentation)
- [better-auth](https://github.com/epic-web-dev/better-auth)
- [Rust async book](https://rust-lang.github.io/async-book/)
- [Rust trait objects](https://doc.rust-lang.org/book/ch17-02-trait-objects.html)

---

## 🤝 Community

- [GitHub Discussions](https://github.com/marcjazz/authkestra/discussions)
- [CONTRIBUTING.md](../CONTRIBUTING.md)
- [Roadmap](./roadmap.md)

---

For more, see the [conversion.md](../conversion.md) for the full vision and architectural review.
