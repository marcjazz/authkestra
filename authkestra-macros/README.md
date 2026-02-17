# authkestra-macros

Procedural macros for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides procedural macros to eliminate boilerplate code when integrating the `authkestra` authentication framework into web applications, specifically targeting Axum application state.

## Features

- **AuthkestraFromRef**: A derive macro that automatically generates the 4 required `FromRef` trait implementations for Axum.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-macros = "0.1.0"
```

### AuthkestraFromRef

The `AuthkestraFromRef` macro is designed to work with the `Authkestra<S, T>` type from `authkestra-flow`. It automatically implements `FromRef` for the state, the session store, the session config, and the token manager.

```rust
use authkestra_axum::AuthkestraFromRef;
use authkestra::flow::Authkestra;
use authkestra_flow::{Configured, Missing};
use authkestra_session::SessionStore;
use std::sync::Arc;

#[derive(Clone, AuthkestraFromRef)]
struct AppState {
    #[authkestra]
    auth: Authkestra<Configured<Arc<dyn SessionStore>>, Missing>,
    // Other application state...
}
```

This macro eliminates the need to manually implement `FromRef` for:
- `Authkestra<S, T>`
- `Result<Arc<dyn SessionStore>, AuthkestraAxumError>` (if sessions are configured)
- `SessionConfig`
- `Result<Arc<TokenManager>, AuthkestraAxumError>` (if tokens are configured)

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
