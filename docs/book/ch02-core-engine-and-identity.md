# Chapter 2: Core Engine and Identity

The `AuthEngine` is the heart of Authkestra. It orchestrates the various components (session stores, auth methods) and produces a unified, verifiable `Identity`.

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

## The AuthEngine (Orchestrator)

The `AuthEngine` uses the **Typestate Builder Pattern** to ensure that critical components (like a `SessionStore` or `TokenService`) are configured at compile-time before the engine can be used.

### Quantum Readiness

The `AuthEngine` is designed to be **PQC-ready**. This means the `TokenService` and `Authenticator` traits are defined to handle larger signature and key sizes associated with Module-Lattice-Based algorithms like **ML-DSA** (FIPS 204).

## Architectural Decisions

- **DID Integration**: We treat DIDs as first-class citizens, allowing Authkestra to act as a bridge between traditional OAuth2/OIDC systems and the decentralized web.
- **Selective Disclosure**: We prioritize privacy by supporting SD-JWTs, enabling users to prove specific attributes (e.g., "Over 18") without revealing their entire profile.
- **Dynamic Key Binding**: Following the **GNAP** model, we support binding tokens to specific client instances using cryptographic proof-of-possession, mitigating token theft.
