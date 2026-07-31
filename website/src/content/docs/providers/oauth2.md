---
title: Stateless OAuth2
description: Configuring Stateless OAuth with Authkestra.
---

By default, OAuth2 logins often result in a server-side session being created. However, Authkestra allows you to build a strictly **stateless** flow where the authentication results in a JWT (JSON Web Token).

"Stateless" means that the entire flow can be completed *without* using a session store. 

## The OAuth2 Standard

Authkestra strictly implements the [OAuth 2.0 Authorization Framework (RFC 6749)](https://datatracker.ietf.org/doc/html/rfc6749) and [PKCE (RFC 7636)](https://datatracker.ietf.org/doc/html/rfc7636). We didn't invent these protocols; we just provide a memory-safe, idiomatic Rust engine to execute them.

## Prerequisites

If you are using multiple OAuth providers (e.g., GitHub and Google), you must enable their respective feature flags:

```toml
[dependencies]
authkestra = { version = "0.2.4", features = ["github", "google"] }
```

## Stateless Engine Configuration

Notice how we completely omit `.session_store()` and use `.jwt_secret()` instead. You can also chain multiple providers back-to-back:

```rust
use authkestra::flow::{Engine, OAuth2Flow};
use authkestra_providers::github::GithubProvider;
use authkestra_providers::google::GoogleProvider;

// Initialize Authkestra in stateless mode supporting multiple providers
let auth_engine = Authkestra::builder()
    .provider(OAuth2Flow::new(GithubProvider::new(...)))
    .provider(OAuth2Flow::new(GoogleProvider::new(...)))
    .jwt_secret(b"your-256-bit-secret-key-at-least-32-bytes-long")
    .build();
```

## Wiring the Routes Manually

Because we are not using sessions, we **cannot** use the automatic `auth_engine.axum_router()`. Instead, you must manually define your `/auth/:provider` and `/auth/callback/:provider` routes.

Here is a step-by-step breakdown of how the manual handlers work:

### 1. The Login Handler

The login handler intercepts the user's request and delegates to Authkestra's `axum_login_handler` helper. This helper securely generates the PKCE challenges and cookies before redirecting to the provider.

```rust
use axum::{extract::{Path, State, Query}, response::IntoResponse};
use authkestra_axum::helpers;

async fn login_handler(
    Path(provider): Path<String>,
    State(state): State<AppState>,
    Query(params): Query<helpers::OAuthLoginParams>,
    cookies: tower_cookies::Cookies,
) -> impl IntoResponse {
    // We pass the framework extractors directly into the helper.
    // The helper handles generating the state, nonce, and the 302 Redirect.
    helpers::axum_login_handler::<AppState, _, _>(Path(provider), State(state), Query(params), cookies).await
}
```

### 2. The Callback Handler

The callback handler is where the stateless magic happens. Instead of relying on a session store, we use `handle_oauth_callback_jwt_erased`.

```rust
async fn callback_handler(
    Path(provider): Path<String>,
    State(state): State<AppState>,
    Query(params): Query<helpers::OAuthCallbackParams>,
    cookies: tower_cookies::Cookies,
) -> Result<impl IntoResponse, AxumError> {
    
    // Extract the token manager (injected via .jwt_secret() earlier)
    let token_manager = <Result<Arc<TokenManager>, AxumError>>::from_ref(&state)?;
    
    // Resolve which provider (e.g. github vs google) was requested
    let flow = state.auth.providers.get(&provider).unwrap();

    // The helper exchanges the code for tokens and issues a custom JWT
    helpers::handle_oauth_callback_jwt_erased(
        flow.as_ref(), 
        cookies, 
        params, 
        token_manager, 
        3600, // Token TTL in seconds
        state.auth.session_config
    ).await
}
```

By manually exposing these handlers, you gain absolute control over the HTTP response. You can append headers, write to custom databases, or return the JWT inside a JSON body.
