# authkestra-macros

Procedural macros for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides procedural macros to eliminate boilerplate code when integrating the `authkestra` authentication framework into web applications.

## Features

- **`AxumState`**: derive macro that generates the `axum::extract::FromRef` implementations Axum's extractors need.
- **`ActixState`**: the Actix counterpart, generating a `configure_authkestra` method that registers the engine's pieces as `app_data`.
- **`KvStore`**: derive macro that forwards the `authkestra_engine::store::KvStore` trait through a newtype wrapper.

You normally do not depend on this crate directly — `authkestra-axum` and `authkestra-actix`
re-export the relevant derive behind their own `macros` feature.

## Usage

```toml
[dependencies]
authkestra-axum = { version = "0.6", features = ["macros"] }
# or, to depend on the macros directly:
authkestra-macros = "0.6"
```

### AxumState / ActixState

Both derives work on a struct holding an `Engine<S, T>` (or one of its aliases:
`AkWebAppEngine`, `AkApiEngine`, `AkEngine`). Mark that field with `#[authkestra(engine)]`.
Additional store fields can be marked with `#[authkestra(store)]` to get a `FromRef` impl for
them too.

```rust,ignore
use authkestra_axum::AxumState;
use authkestra_engine::AkWebAppEngine;

#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkWebAppEngine,
    // Other application state...
}
```

For Axum, this eliminates the need to manually implement `FromRef` for:
- `Engine<S, T>`
- `Result<Arc<dyn SessionStore>, AxumError>` (if sessions are configured)
- `SessionConfig`
- `Result<Arc<TokenManager>, AxumError>` (if tokens are configured)

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
