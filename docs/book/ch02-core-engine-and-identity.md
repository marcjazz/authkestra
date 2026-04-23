# Chapter 2: Core Engine and Identity

The `AuthEngine` is the heart of Authkestra. It orchestrates the various components (session stores, auth methods) and produces a unified `Identity` object. As part of the new architectural direction, we are consolidating `authkestra-core`, `authkestra-flow`, and `authkestra-token` into a single, unified `authkestra-engine` crate. This provides a clear, central "brain" for the auth runtime, allowing it to easily bridge the gap between an embedded library and a standalone service.

## Draft Implementations

### Identity and Claims

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub provider: String,
    pub claims: Claims,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub sub: String,
    pub email: Option<String>,
    // Generic storage for non-standard claims
    pub extra: HashMap<String, serde_json::Value>,
}
```

### The AuthEngine and Builder

```rust
pub struct AuthEngine<S> {
    session_store: S,
    methods: HashMap<String, Box<dyn AuthMethod>>,
}

pub struct AuthEngineBuilder<S> {
    session_store: Option<S>,
    methods: HashMap<String, Box<dyn AuthMethod>>,
}

impl<S> AuthEngineBuilder<S> {
    pub fn new() -> Self {
        Self {
            session_store: None,
            methods: HashMap::new(),
        }
    }

    pub fn session_store(mut self, store: S) -> Self {
        self.session_store = Some(store);
        self
    }

    pub fn add_method(mut self, name: &str, method: Box<dyn AuthMethod>) -> Self {
        self.methods.insert(name.to_string(), method);
        self
    }

    pub fn build(self) -> Result<AuthEngine<S>, String> {
        Ok(AuthEngine {
            session_store: self.session_store.ok_or("Session store missing")?,
            methods: self.methods,
        })
    }
}
```

### Architectural Decisions & Future Direction

- **Standard vs. Custom Claims:** We enforce standard JWT fields (e.g., `iss`, `aud`, `exp`, `iat`) as strongly typed fields on the `Claims` struct. Authentication heavily relies on standardization. Leaving these to a loose `HashMap` invites runtime bugs and makes OIDC interoperability brittle. Custom claims belong in an `extra` map, but standards must be enforced at compile time.
- **Multiple Linked Identities:** The `Identity` struct should be lightweight and represent the **current** authenticated context, not the entire database record. A bloated `Identity` struct degrades cache performance (e.g., in Redis). Linked accounts should be handled at the database level. The `Identity` contains the `user_id` and the `current_provider`, and the application can fetch linked accounts separately if needed.
- **Trait Objects vs Generics:** We accept the use of `Box<dyn AuthMethod>`. Authentication is inherently I/O bound (database lookups, network requests to OAuth providers). The microscopic performance penalty of dynamic dispatch (vtable lookups) via `Box<dyn Trait>` is entirely negligible here. Using trait objects massively simplifies the developer experience (DX) and builder pattern. We prioritize DX and compilation times over nanosecond optimizations in I/O bound paths.
