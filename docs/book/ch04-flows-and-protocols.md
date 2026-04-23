# Chapter 4: Flows and Protocols

Authentication is rarely a simple "check password" operation. It often involves multi-step flows, redirects, and state management. Our strategy defines flows not just as hardcoded functions, but as highly composable, declarative units within the `authkestra-engine`.

## Supported Protocols

Authkestra aims to support out-of-the-box:

- **OAuth2 / OIDC:** The standard for delegated authorization and identity.
- **SAML 2.0:** Crucial for enterprise SSO integrations.
- **Passkeys / WebAuthn:** Passwordless, biometric-based authentication.
- **Magic Links / OTP:** Email or SMS based one-time passwords.

## Managing Flow State

Many protocols (like OAuth2's Authorization Code Flow) require maintaining state across multiple HTTP requests. Through the engine's `Flow` trait, we enforce consistent, secure lifecycle management for these intermediate phases.

### Architectural Decisions & Future Direction

- **State Storage:** For infinite horizontal scalability, intermediate flow state (like `state` and `nonce` parameters in OAuth) should be stored in **encrypted, short-lived cookies** (stateless), not in a database. Hitting a database twice just to validate an OAuth state token creates unnecessary bottlenecks under high load.
- **OIDC Discovery:** Discovery documents must be fetched at startup and cached in memory. A background `tokio::spawn` task should refresh them periodically based on the `Cache-Control` headers. Fetching discovery documents per-request will destroy latency and rapidly hit rate limits at identity providers.
