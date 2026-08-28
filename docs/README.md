# Authkestra Documentation

Welcome to the Authkestra documentation! This guide will help contributors and users understand the vision, architecture, and roadmap for Authkestra, and provide foundational resources for building the next generation of authentication systems.

## 📚 Documentation Hierarchy & Source of Truth

To help navigate the various documentation surfaces, please adhere to the following hierarchy of truth:

1. **RFCs (`docs/rfc-*.md`)**: These are the definitive design records. They represent the finalized, agreed-upon architecture and protocol specifications that the codebase must conform to.
2. **`roadmap.md`**: This file tracks what is *actually* being built next. It reflects the immediate implementation priorities and active development phases.
3. **`book/` (mdBook)**: This contains the user-facing tutorials and guides. Because the project is evolving rapidly, **the book may lag behind the RFCs and current codebase**. It is best effort documentation for end-users, not the architectural source of truth.
4. **`research/`**: Contains raw research dumps and reference materials used during the design phases (e.g., `deep-search.md`). These are not authored documentation.

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

The phased roadmap lives in a single place — [roadmap.md](./roadmap.md) — so it cannot drift
against a second copy. Per the hierarchy above, that file is what tracks what is actually being
built next.

---

## 🧩 Workspace Crates (Current)

The RFC-001 consolidation is done; these are the crates that actually exist today:

- `authkestra/` — DX façade, re-exports the rest behind features, and hosts every runnable example
- `authkestra-engine/` — the merged core: identity, flows, sessions, tokens, and the stores
  (`memory`, `redis`, `sql-postgres`/`sql-mysql`/`sql-sqlite` features)
- `authkestra-resource/` — validation and enforcement (`Guard`, JWT strategies)
- `authkestra-providers/` — GitHub, Google, Discord
- `authkestra-oidc/` — generic OIDC relying-party client
- `authkestra-op/` — OpenID Provider (authorization server)
- `authkestra-devsig/` — device-bound signature authentication
- `authkestra-crypto-util/` — shared strict signature/key verification helpers
- `authkestra-axum/`, `authkestra-actix/` — framework adapters
- `authkestra-macros/` — `AxumState` / `ActixState` / `KvStore` derives

There is no separate `authkestra-core`, `authkestra-flow`, `authkestra-token`, or
`authkestra-session` crate — all four were folded into `authkestra-engine` by RFC-001. Older docs
that mention them are describing the pre-migration layout.

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

For more, see [rfc-002-next-gen-identity.md](./rfc-002-next-gen-identity.md) for the full vision
and architectural review.
