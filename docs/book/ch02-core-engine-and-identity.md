# Chapter 2: Core Engine and Identity

The `AkBase` is the heart of Authkestra. It orchestrates the various components (session stores, auth methods) and produces a unified, verifiable `Identity`.

## Identity and Verifiable Claims

In the next-gen architecture, an `Identity` is more than a database ID. It represents a cryptographically verifiable subject, potentially backed by a Decentralized Identifier (DID).

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// The canonical subject identifier (could be a DID, email, or UUID)
    pub sub: String,
    /// Optional DID if the identity is decentralized
    pub did: Option<String>,
    /// The provider that established this identity context
    pub provider: String,
    /// Verifiable claims associated with this session
    pub claims: Claims,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    // Standard JWT/OIDC Claims
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    
    // Support for Selective Disclosure (SD-JWT)
    pub _sd: Option<Vec<String>>,
    
    // Generic storage for non-standard or custom attributes
    pub extra: HashMap<String, serde_json::Value>,
}
```

## The AkBase (Orchestrator)

The `AkBase` uses the **Typestate Builder Pattern** to ensure that critical components (like a `SessionStore` or `TokenService`) are configured at compile-time before the engine can be used.

### Quantum Readiness

The `AkBase` is designed to be **PQC-ready**. This means the `TokenService` and `Authenticator` traits are defined to handle larger signature and key sizes associated with Module-Lattice-Based algorithms like **ML-DSA** (FIPS 204).

## Architectural Decisions

- **DID Integration**: We treat DIDs as first-class citizens, allowing Authkestra to act as a bridge between traditional OAuth2/OIDC systems and the decentralized web.
- **Selective Disclosure**: We prioritize privacy by supporting SD-JWTs, enabling users to prove specific attributes (e.g., "Over 18") without revealing their entire profile.
- **Dynamic Key Binding**: Following the **GNAP** model, we support binding tokens to specific client instances using cryptographic proof-of-possession, mitigating token theft.

## Protocol-Bound vs Schema-Bound Identity (Why no Repository?)

Authkestra is explicitly a **Protocol-bound Auth Engine** (like Ory Hydra), rather than a **Schema-bound Auth Library** (like NextAuth or better-auth). 

This architectural separation is deliberate:

1. **Schema-Bound Libraries**: Provide a rigid database schema out of the box (`users`, `accounts`, `sessions`). While fast to start, they hijack your domain model. Adding custom columns, complex relations, or switching to an unsupported database requires fighting the library's adapter layer.
2. **Protocol-Bound Engines (Authkestra)**: Focus entirely on the complex cryptography, RFC compliance, PKCE, JWT minting, and OAuth2/OIDC state machines. 

### The Separation of Persistence

**What Authkestra Owns (`KvStore`)**:
Authkestra only persists ephemeral, protocol-specific state:
- `authorization_code`s (10-minute expiry)
- `refresh_token`s
- `device_code`s
- `OP_Session`s (the cryptographic cookies proving authentication to the OpenID Provider)

**What Your Application Owns**:
Your application completely owns the `users` and `accounts` tables. Authkestra has no `UserRepository` or `AccountRepository` trait. 

### The Identity Handoff

When a user logs in (e.g., via Google), the flow is:
1. Authkestra perfectly executes the complex OAuth2/OIDC protocol with Google.
2. Authkestra receives the `Identity` from Google (email, name, Google ID).
3. **The Handoff**: Authkestra delegates to the host application via a trait hook.
4. **Your Application's Job**: Your Rust code looks up the email in *your* database using *your* preferred tools (Diesel, SQLx, SeaORM). If the user doesn't exist, you create them. If they do, you link the social account (see "Linked Social Identities").
5. You return your internal `user_id` (the `subject`) to Authkestra.
6. Authkestra mints the `id_token` and `access_token` asserting that subject, and completes the flow.

This is the holy grail of flexibility: you get an enterprise-grade OAuth2/OIDC server without surrendering control of your most critical data structure (the User).
