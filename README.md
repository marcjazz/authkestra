# Authkestra

`authkestra` is a modular, framework-agnostic authentication orchestration system designed to be idiomatic to Rust, emphasizing **explicit control flow, strong typing, and composability** over dynamic middleware strategies common in other ecosystems.

## 📦 Getting Started

The easiest way to use Authkestra is via the `authkestra` facade crate. It re-exports all sub-crates behind feature flags, allowing you to manage your authentication stack from a single dependency.

Add this to your `Cargo.toml`:

```toml
[dependencies]
# Use the facade with the features you need
authkestra = { version = "0.1.0", features = ["axum", "github"] }
```

For advanced users, individual crates are still available and can be used independently if preferred.

## 🚀 Features

- **Modular Design**: Concerns are strictly separated into crates: `authkestra-core`, `authkestra-flow`, `authkestra-session`, `authkestra-token`, and framework adapters like `authkestra-axum` and `authkestra-actix`.
- **Explicit Flow Control**: Dependencies and authentication context are injected explicitly via **Extractors** (Axum/Actix) or constructor arguments, eliminating "magic" middleware.
- **Provider Agnostic**: Easily integrate new OAuth providers by implementing the `OAuthProvider` trait.
- **Session Management**: Flexible session storage via the `SessionStore` trait, with built-in support for in-memory, Redis, and SQL via `sqlx`.
- **Stateless Tokens**: Comprehensive JWT support via `authkestra-token`.

## 📦 Workspace Crates

| Crate                                                                    | Responsibility                                                            |
| :----------------------------------------------------------------------- | :------------------------------------------------------------------------ |
| [`authkestra`](authkestra/README.md)                                     | **Primary Facade**: Re-exports all other crates behind features.          |
| [`authkestra-core`](authkestra-core/README.md)                           | Foundational types, traits (`Identity`, `OAuthProvider`, `SessionStore`). |
| [`authkestra-flow`](authkestra-flow/README.md)                           | Orchestrates OAuth2/OIDC flows (Authorization Code, PKCE).                |
| [`authkestra-session`](authkestra-session/README.md)                     | Session persistence layer abstraction.                                    |
| [`authkestra-token`](authkestra-token/README.md)                         | JWT signing, verification, and token abstraction.                         |
| [`authkestra-providers-github`](authkestra-providers-github/README.md)   | Concrete implementation for GitHub OAuth.                                 |
| [`authkestra-providers-google`](authkestra-providers-google/README.md)   | Concrete implementation for Google OAuth.                                 |
| [`authkestra-providers-discord`](authkestra-providers-discord/README.md) | Concrete implementation for Discord OAuth.                                |
| [`authkestra-axum`](authkestra-axum/README.md)                           | Axum-specific integration, including `AuthSession` extractors.            |
| [`authkestra-actix`](authkestra-actix/README.md)                         | Actix-specific integration.                                               |
| [`authkestra-oidc`](authkestra-oidc/README.md)                           | OpenID Connect discovery and provider support.                            |

## 🛠️ Usage

To see Authkestra in action, check out the [examples](examples/) directory:

- [Get Started](examples/get_started.rs)
- [Axum with GitHub OAuth](examples/axum_oauth.rs)
- [Actix with GitHub OAuth](examples/actix_github.rs)
- [OIDC Generic Provider](examples/oidc_generic.rs)
- [Device Flow](examples/device_flow.rs)

## 💡 Testing & Troubleshooting

### 🔑 Environment Variable Configuration

When implementing a resource server or using OAuth2 flows, ensure your `.env` file (or system environment) is correctly configured. Authkestra examples typically look for:

- `OIDC_ISSUER`: The base URL of your OAuth2/OIDC provider (e.g., `https://accounts.google.com`).
- `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET`: Credentials obtained from your provider's developer console.
- `OIDC_REDIRECT_URI`: The callback URL registered with your provider (e.g., `http://localhost:3000/auth/oidc/callback`).
- `OIDC_JWKS_URI`: The URI for the provider's Public Key Set (optional if discovery is used, but often explicitly set in resource server examples).

> **Hint:** You can usually find these values in your provider's "Well-Known Configuration" endpoint (e.g., `https://<issuer>/.well-known/openid-configuration`).

### 🏃 Running Resource Server Examples

Authkestra provides ready-to-use resource server examples for both Axum and Actix. You can run them using:

```bash
# Run the Axum resource server
cargo run --bin axum_resource_server

# Run the Actix resource server
cargo run --bin actix_resource_server
```

These servers listen on `http://localhost:3000` by default.

### 🧪 Generating and Using Tokens for Testing

To test protected endpoints like `/api/protected`, you need a valid OAuth2 access token.

1.  **Obtain a Token**: Use an OAuth2 flow (like the Authorization Code flow in `axum_oauth.rs`) or a tool like `Postman` or `curl` against your provider's token endpoint to get an `access_token`.
2.  **Authorize Your Request**: Include the token in the `Authorization` header when making requests:

    ```bash
    curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" http://localhost:3000/api/protected
    ```

### 🚦 Interpreting HTTP Status Codes

When testing your resource server, you might encounter these common status codes:

-   `200 OK`: Successful authorization. The token is valid, and you have access to the resource.
-   `401 Unauthorized`: The token is missing, expired, or invalid. Check your `Authorization` header and token validity.
-   `403 Forbidden`: The token is valid, but it lacks the required scopes or permissions for this specific resource.

### 🔍 Troubleshooting Common Issues

If the resource server is not behaving as expected:

1.  **Check Server Logs**: Look at the terminal output for discovery failures, JWKS fetch errors, or JWT validation reasons (e.g., "ExpiredSignature").
2.  **Verify Token Validity**: Use a tool like [jwt.io](https://jwt.io) to inspect your token's `iss` (issuer), `aud` (audience), and `exp` (expiry) claims. They must match your server's configuration.
3.  **Ensure Correct Paths**: Double-check that you are hitting the correct endpoint path (e.g., `/api/protected` vs `/protected`).
4.  **Network Access**: Ensure your server can reach the provider's JWKS URI for offline validation.

## �️ Technical Design Principles

The architecture favors compile-time guarantees over runtime flexibility:

- **Trait-Based Extension**: Customization is achieved by implementing traits, not by configuring dynamic strategies.
- **Explicit Injection**: Authentication context is never implicitly available; users must explicitly request it via extractors (e.g., `AuthSession(session): AuthSession`).
- **Framework Agnostic Core**: `authkestra-flow` is pure Rust logic, completely independent of any web framework.

## 📜 License

This project is dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
