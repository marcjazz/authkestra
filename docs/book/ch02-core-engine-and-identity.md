# Chapter 2: Core Engine and Identity

The `Engine` is the heart of Authkestra. It orchestrates the various components (session stores, auth methods) and produces a unified, verifiable `Identity`.

## Identity (as shipped)

`authkestra_engine::Identity` is what a `Flow` or an `AuthMethod` hands back on success, and what
gets stored inside a `Session`. It is deliberately small — everything provider-specific lands in
`attributes`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// The provider identifier (e.g., "github", "google")
    pub provider_id: String,
    /// The unique ID of the user within the provider's system
    pub external_id: String,
    /// The user's email address, if available and authorized
    pub email: Option<String>,
    /// The user's username or display name, if available
    pub username: Option<String>,
    /// Additional provider-specific attributes
    pub attributes: HashMap<String, String>,
}
```

Token claims are a separate type, `authkestra_engine::Claims`, minted by `TokenManager` — an
`Identity` does not embed them.

> **Planned, not implemented.** Earlier drafts of this chapter showed an `Identity` with `sub`,
> `did` and an embedded `claims` field, describing a decentralized-identifier-backed subject. No
> such shape exists: there is no DID support, no `did` field, and no verifiable-credential type in
> the workspace. Selective disclosure *is* shipped, but as `TokenManager::issue_sd_jwt` /
> `validate_sd_jwt` operating on `Claims` — see Chapter 4 §5 for what it does and does not cover.

## The Engine (Orchestrator)

The `Engine` uses the **Typestate Builder Pattern** so that its two optional halves — a session
store and a token manager — are resolved at compile time. `Engine<S, T>`'s two generic parameters
are each either `Missing` or `Configured<_>`, and the aliases `AkWebAppEngine` (sessions only),
`AkApiEngine` (tokens only) and `AkEngine` (both) name the combinations you store in application
state. Calling a session API on an engine built without `.session_store()` is a compile error, not
a runtime panic.

### Quantum readiness — planned

> **Not implemented.** RFC-002 calls for PQC-ready token issuance (ML-DSA / FIPS 204), which would
> arrive as a `TokenService` abstraction generic over signature size. Today `TokenManager` is a
> concrete type over `jsonwebtoken`'s classical algorithm set (RSA, ECDSA, EdDSA). There is no
> `TokenService` trait and no ML-DSA support in the workspace. See Chapter 3, "Planned traits".

## Architectural Decisions

- **DID Integration**: We treat DIDs as first-class citizens, allowing Authkestra to act as a bridge between traditional OAuth2/OIDC systems and the decentralized web.
- **Selective Disclosure**: We prioritize privacy by supporting SD-JWTs, enabling users to prove specific attributes (e.g., "Over 18") without revealing their entire profile.
- **Dynamic Key Binding**: Following the **GNAP** model, we support binding tokens to specific client instances using cryptographic proof-of-possession, mitigating token theft.

## Protocol-Bound vs Schema-Bound Identity (Why no Repository?)

Authkestra is explicitly a **Protocol-bound Auth Engine** (like Ory Hydra), rather than a **Schema-bound Auth Library** (like NextAuth or better-auth). 

This architectural separation is deliberate:

1. **Schema-Bound Libraries**: Provide a rigid database schema out of the box (`users`, `accounts`, `sessions`). While fast to start, they hijack your domain model. Adding custom columns, complex relations, or switching to an unsupported database requires fighting the library's adapter layer.
2. **Protocol-Bound Engines (Authkestra)**: Focus entirely on the complex cryptography, RFC compliance, PKCE, JWT minting, and OAuth2/OIDC state machines. 

### The Separation of Persistence

**What Authkestra Owns (`KvStore`)**:
Authkestra only persists ephemeral, protocol-specific state — plus, if you enable them,
TOTP/WebAuthn credentials via `CredentialStore`:
- `authorization_code`s (10-minute expiry)
- `refresh_token`s
- `device_code`s
- `OP_Session`s (the cryptographic cookies proving authentication to the OpenID Provider)

**What Your Application Owns**:
Your application completely owns the `users` and `accounts` tables. Authkestra has no `UserRepository`, `AccountRepository`, or `UserStore` trait — if you find one named in older documentation, it does not exist. 

### The Identity Handoff

When a user logs in (e.g., via Google), the flow is:
1. Authkestra perfectly executes the complex OAuth2/OIDC protocol with Google.
2. Authkestra receives the `Identity` from Google (email, name, Google ID).
3. **The Handoff**: Authkestra delegates to the host application via a trait hook.
4. **Your Application's Job**: Your Rust code looks up the email in *your* database using *your* preferred tools (Diesel, SQLx, SeaORM). If the user doesn't exist, you create them. If they do, you link the social account (see "Linked Social Identities").
5. You return your internal `user_id` (the `subject`) to Authkestra.
6. Authkestra mints the `id_token` and `access_token` asserting that subject, and completes the flow.

This is the holy grail of flexibility: you get an enterprise-grade OAuth2/OIDC server without surrendering control of your most critical data structure (the User).
