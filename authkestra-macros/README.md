# authkestra-macros

Procedural macros for authkestra framework integrations to simplify integration with custom application state.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-axum = { version = "0.1.1", features = ["macros"] }
```

Annotate your state struct with `#[derive(AuthkestraFromRef)]`:

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
    db_pool: Arc<PgPool>,
}
```

The macro automatically generates all required `FromRef` trait implementations.

## What It Generates

The macro generates 4 `FromRef` implementations:

1. `FromRef<AppState> for Authkestra<S, T>`
2. `FromRef<AppState> for Result<Arc<dyn SessionStore>, AuthkestraAxumError>` (when S: SessionStoreState)
3. `FromRef<AppState> for SessionConfig`
4. `FromRef<AppState> for Result<Arc<TokenManager>, AuthkestraAxumError>` (when T: TokenManagerState)

## Requirements

- The struct must have exactly one field marked with `#[authkestra]`
- That field must be of type `Authkestra<S, T>`
- The struct must derive `Clone`

## Migration from Manual Implementation

Before (manual - 30+ lines):

```rust
#[derive(Clone)]
struct AppState<S, T> {
    auth: Authkestra<S, T>,
    db_pool: Arc<PgPool>,
}

impl<S: Clone, T: Clone> FromRef<AppState<S, T>> for Authkestra<S, T> {
    fn from_ref(state: &AppState<S, T>) -> Self {
        state.auth.clone()
    }
}

impl<S, T> FromRef<AppState<S, T>> for Result<Arc<dyn SessionStore>, AuthkestraAxumError>
where
    S: authkestra_flow::SessionStoreState,
{
    fn from_ref(state: &AppState<S, T>) -> Self {
        Ok(state.auth.session_store.get_store())
    }
}

// ... 2 more implementations
```

After (with macro - 3 lines):

```rust
use authkestra_axum::AuthkestraFromRef;

#[derive(Clone, AuthkestraFromRef)]
struct AppState<S, T> {
    #[authkestra]
    auth: Authkestra<S, T>,
    db_pool: Arc<PgPool>,
}
```

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
