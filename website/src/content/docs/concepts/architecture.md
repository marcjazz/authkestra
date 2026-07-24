---
title: Architecture
description: Learn about Authkestra's unified engine, adapters, and framework-agnostic design.
---

Authkestra is designed around a strictly layered architecture. Our goal is to provide a unified, highly composable authentication engine (`authkestra-engine`) that seamlessly integrates into various web frameworks via lightweight adapters, while remaining strictly database-agnostic.

## The Three Layers

Our system is split into three distinct zones, ensuring clear boundaries and preventing leaky abstractions.

### 1. Engine (The Core)
The **`authkestra-engine`** crate is the brain of the system. It is entirely framework-agnostic and contains pure Rust logic.
- **Responsibilities**: Defines identity modeling, standard traits (`Provider`, `SessionStore`), protocol helpers (like PKCE and OIDC discovery), and the central `Engine` orchestrator.
- **Why?**: By decoupling the engine from any specific web server (like Axum or Actix), we ensure your authentication logic is portable, highly testable, and isolated from HTTP request intricacies.

### 2. Extensions (Plugins)
Pluggable components that implement the strict traits defined by the core engine.
- **Examples**: `authkestra-providers` (GitHub, Google, etc.), `authkestra-oidc`.
- **Responsibilities**: These crates provide concrete implementations for OAuth/OIDC providers or external mechanisms without injecting their own business logic into the engine.

### 3. Adapters (Integrations)
Framework-specific wrappers that embed the engine into your web application.
- **Examples**: `authkestra-axum`, `authkestra-actix`.
- **Responsibilities**: They provide native middleware, explicit extractors (e.g., `AuthSession`), route guards, and handle raw HTTP request/response translations.

## Core Design Principles

1. **Typestate Builder Pattern**: The `Engine::builder()` utilizes Rust's typestate pattern to enforce configuration validity at compile-time. Misconfigurations are compile errors, not runtime panics.
2. **Stateless OAuth by Default**: OAuth `state` and `nonce` parameters are stored in securely encrypted cookies rather than a database. This guarantees horizontal scalability.
3. **Database Agnostic**: Authkestra never enforces schemas. All data access occurs through traits like `SessionStore` and `UserStore`, allowing you to use SQLx, Diesel, Redis, or purely in-memory solutions.
4. **Trait Objects over Generics**: For I/O-bound paths, we prefer dynamic dispatch (`Box<dyn Trait>`) to optimize compilation times and improve Developer Experience without sacrificing noticeable runtime performance.
5. **Observability**: Every handler and endpoint is deeply instrumented via the `tracing` crate, providing granular visibility into authentication flows in production.
