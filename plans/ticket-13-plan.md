## Goal

Make the existing OAuth implementation compliant with the new architecture.

## Tasks

- Update the existing OAuth implementation to implement the `Flow` trait.
- Update providers to use the `Provider` trait.
- Ensure OAuth `state` and `nonce` are stored in encrypted cookies, never in the database.

## Acceptance Criteria

- [x] OAuth flow is refactored to implement the generic `Flow` trait.
- [x] Existing providers (GitHub, Google, etc.) implement the `Provider` trait.
- [x] OAuth sequence diagrams in docs are still valid for the new implementation.

## Definition of Done (DoD)

- [x] OAuth integration tests pass.
- [x] Verified that no state is stored in the DB during the flow.
- [x] Documentation on how to add a new provider is updated.

### Proposed Protocol Flow (GNAP/OAuth 2.1 Hybrid)

```mermaid
sequenceDiagram
    participant U as User / AI Agent
    participant C as Client (e.g., Axum App)
    participant AS as Authkestra AS (GNAP/OAuth 2.1)
    participant RS as Resource Server

    Note over U, AS: Phase 1: Negotiation (GNAP)
    U->>C: Request Action
    C->>AS: POST /gnap/request (Intent + Key)
    AS-->>C: 200 OK (Interact URL + Instance ID)
    C-->>U: Redirect to AS
    U->>AS: Authenticate & Authorize
    AS-->>U: Success
    U->>C: Return to App

    Note over C, RS: Phase 2: Access
    C->>AS: POST /gnap/continue
    AS-->>C: Access Token (DPoP Bound)
    C->>RS: Request with DPoP Token
    RS->>RS: Verify DPoP + Token
    RS-->>C: Resource Data
```
