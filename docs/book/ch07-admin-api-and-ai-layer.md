# Chapter 7: Admin API and AI Layer

A modern identity solution often requires administrative oversight and intelligent monitoring. Authkestra's vision extends into AI-driven generation and declarative configuration, distinguishing it from legacy monolithic systems.

## The Admin API

We expose a standardized REST/GraphQL API for managing:

- Users and Identities
- Sessions (revocation)
- Policies and Roles
- Provider configurations (adding OAuth clients dynamically)

## The AI / Analytics Layer

Authkestra's killer feature is its AI-first layer, where developers can define declarative setups (YAML/JSON) and leverage tooling to safely generate complete auth architectures.

As part of the roadmap, we also integrate AI-driven threat detection:

- Anomaly detection (login from unusual locations).
- Credential stuffing prevention.
- Risk-based authentication (prompting for MFA only when risk is high).

### Architectural Decisions & Future Direction

- **API Serving:** Should the Admin API be embedded or standalone? It must be deployable as both. We expose an Axum `Router` (or Actix equivalent) that developers can mount into their existing app (`app.nest("/admin", authkestra_admin::router())`). For Keycloak-style deployments, we provide a pre-compiled binary that simply runs that router.
- **Telemetry Data:** Telemetry must be collected asynchronously to avoid impacting authentication latency. The authentication flow pushes lightweight events onto an in-memory channel (e.g., `tokio::sync::mpsc`). A separate background worker reads from this channel and processes the AI telemetry, ensuring the critical auth path remains strictly unblocked.
