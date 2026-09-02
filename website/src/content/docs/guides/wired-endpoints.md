---
title: Wired Endpoints
description: Learn how Authkestra automatically maps authentication endpoints, and when to wire them manually.
---

When building an authentication flow, you need HTTP endpoints that initiate the login and endpoints that handle the callback from the identity provider.

## Automatic Route Wiring (Session Mode)

If you are using a stateful session store, the easiest way to get started is by letting Authkestra automatically wire the endpoints for you using `auth_engine.axum_router()` (returns an `axum::Router`) or `auth_engine.actix_scope()` (returns an `actix_web::Scope` you mount with `.service(...)`).

### Client Login Endpoints

The auto-wired router generates three standard endpoints, all resolving the provider at runtime:

#### 1. `GET /auth/login/{provider_id}`
This endpoint **initiates the OAuth2/OIDC flow**. 
- It constructs the authorization URL using the provider's configuration.
- It generates a cryptographically secure `state` and `nonce`, storing them in an encrypted, HTTP-only cookie.
- Finally, it returns an HTTP 302 Redirect to send the user to the provider (e.g., Google or GitHub).

#### 2. `GET /auth/callback/{provider_id}`
This endpoint **handles the provider's redirect callback**.
- It verifies that the `state` parameter matches the one in the secure cookie (preventing CSRF attacks).
- It exchanges the authorization code for an Access Token (and optionally an ID Token).
- It establishes a server-side session and issues a session cookie to the client.

#### 3. `GET /auth/logout`
This endpoint **ends the session**: it deletes the session from the store and clears the session cookie.

## Automatic Route Wiring (Stateless Mode)

What if you don't want to use sessions at all? For example, in a purely **Stateless OAuth2** flow, you want the callback to return a JSON Web Token (JWT) in the response body instead of setting a session cookie.

For stateless environments, Authkestra provides the `auth_engine.axum_router_stateless()` and `auth_engine.actix_scope_stateless()` counterparts. They wire the login and callback endpoints only (there is no server-side session to log out of), and the callback handler returns a JWT instead of initializing a session.

These two methods live on **`AxumStatelessExt`** and **`ActixStatelessExt`**, separate traits from
the `AxumExt` / `ActixExt` that carry the session-mode routers. Import the stateless trait or the
method will not resolve. They also require an engine with a token manager (`AkApiEngine` or
`AkEngine`), because the callback has to mint the JWT it returns.

## Manual Route Wiring & Custom Flows

If you need absolute control over the HTTP response (e.g. to append headers, write to custom databases, or augment the JWT response), you can bypass the automatic routers entirely. Instead, you manually define your routes and call Authkestra's `helpers`. (See the **Stateless OAuth2** page for a detailed breakdown of how these manual handlers work).

## Multiple Providers

Authkestra's routing is deeply dynamic. The `{provider_id}` path parameter is resolved at runtime against the providers registered in the engine. 

If you register multiple providers (e.g., `.provider(OAuth2Flow::new(github)).provider(OAuth2Flow::new(google))`), the same routes handle *both* providers dynamically based on whether you call `/auth/login/github` or `/auth/login/google`. Each provider's `provider_id()` is what the path segment is matched against.
