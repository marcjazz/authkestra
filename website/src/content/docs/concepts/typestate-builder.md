---
title: Typestate Builder Pattern
description: Learn how Authkestra leverages the typestate pattern for compile-time safety.
---

Authkestra relies heavily on Rust's **Typestate Pattern** through the `Engine::builder()` API. This design pattern ensures that your authentication stack is configured correctly *at compile-time*, completely eliminating an entire class of runtime panics and misconfigurations.

## What is the Typestate Pattern?

In Rust, the typestate pattern is used to encode a state machine into the type system. Methods return new types representing the transitioned state, meaning certain methods simply do not exist unless the builder is in the correct state.

For Authkestra, this means that the builder structurally guarantees you cannot use a feature if you haven't provided its prerequisite configuration.

## How Authkestra Uses It

When you call `Engine::builder()`, it starts in an empty state. As you append configuration options (like providing an OAuth flow or a session store), the builder transitions through defined types.

### Example: Enforcing Session Configuration

Consider building an engine that issues sessions. If you attempt to invoke session-related handler generation without first providing a `SessionStore`, the compiler will reject it.

```rust
use authkestra::flow::{Engine, OAuth2Flow};
use authkestra_providers::github::GithubProvider;
use authkestra_engine::store::memory::MemoryStore;
use std::sync::Arc;

// 1. Initialize a Provider
let github_provider = GithubProvider::new(
    "CLIENT_ID".to_string(), 
    "SECRET".to_string(), 
    "URI".to_string()
);

// 2. Build the Engine
let auth_engine = Engine::builder()
    .provider(OAuth2Flow::new(github_provider))
    // If you omit this line, methods reliant on a session store won't exist!
    .session_store(Arc::new(MemoryStore::default())) 
    .build();
```

By leveraging this pattern, Authkestra provides an incredibly robust Developer Experience (DX). You can confidently rely on cargo and rust-analyzer to guide you through a correct, secure authentication setup.
