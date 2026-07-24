---
title: Wired Endpoints
description: Learn how Authkestra automatically maps authentication endpoints, and when to wire them manually.
---

When building an authentication flow, you need HTTP endpoints that initiate the login and endpoints that handle the callback from the identity provider.

## Automatic Route Wiring (Session Mode)

If you are using a stateful session store, the easiest way to get started is by letting Authkestra automatically wire the endpoints for you using `auth_engine.axum_router()` or `auth_engine.actix_router(cfg)`.

### Client Login Endpoints

The auto-wired router generates two standard endpoints per provider registered in the engine:

#### 1. `GET /auth/{provider_id}`
This endpoint **initiates the OAuth2/OIDC flow**. 
- It constructs the authorization URL using the provider's configuration.
- It generates a cryptographically secure `state` and `nonce`, storing them in an encrypted, HTTP-only cookie.
- Finally, it returns an HTTP 302 Redirect to send the user to the provider (e.g., Google or GitHub).

#### 2. `GET /auth/callback/{provider_id}`
This endpoint **handles the provider's redirect callback**.
- It verifies that the `state` parameter matches the one in the secure cookie (preventing CSRF attacks).
- It exchanges the authorization code for an Access Token (and optionally an ID Token).
- It establishes a server-side session and issues a session cookie to the client.

## Manual Route Wiring (Stateless Mode & Custom Flows)

What if you don't want to use sessions at all? For example, in a purely **Stateless OAuth2** flow, you want the callback to return a JSON Web Token (JWT) in the response body instead of setting a session cookie.

In this scenario, the automatic `axum_router()` will not work because it assumes a session-based flow. Instead, you manually define your routes and call Authkestra's `helpers`. (See the **Stateless OAuth2** page for a detailed breakdown of how these manual handlers work).

## Multiple Providers

Authkestra's routing is deeply dynamic. The `{provider_id}` path parameter is resolved at runtime against the providers registered in the engine. 

If you register multiple providers (e.g., `.provider(github).provider(google)`), the same two routes handle *both* providers dynamically based on whether you call `/auth/github` or `/auth/google`!
