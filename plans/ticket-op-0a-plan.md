# Ticket #OP.0a: Asymmetric (RS256) signing in TokenService

## Goal

Add an asymmetric signing path to `TokenService`/`TokenManager` so tokens
issued by an OpenID Provider (`authkestra-op`, RFC-003) can be verified by
external relying parties via a published JWKS, without requiring them to
know a shared secret. This is a prerequisite for `OP.2` (JWKS endpoint) and
`OP.4` (`/token` endpoint) — do not begin those tickets until this merges.

Do NOT touch `authkestra-op` in this ticket. This ticket is scoped to
`authkestra-engine` (and `authkestra-resource` if the `Jwk` type needs a
`Serialize` impl to represent the new public key). Keep it that way.

## Non-goals

- Key rotation / multiple simultaneous signing keys (single key + `kid` is
  enough for this ticket; rotation is a follow-up).
- Any change to the existing HS256 path — it must keep working unchanged
  for existing resource-server use cases. This is additive, not a
  replacement.

## Steps

### 1. Extend `TokenManager` construction

- Add a variant of `TokenManager::new` (or a new constructor,
  `TokenManager::new_asymmetric` / builder method) that accepts an RSA
  keypair (`EncodingKey::from_rsa_pem`, `DecodingKey::from_rsa_pem`) instead
  of a raw secret.
- Store a `kid: String` alongside the keys (generate one, e.g. a UUID or a
  hash of the public key, if the caller doesn't supply one).
- Keep the existing HMAC fields/constructor untouched; the struct should
  support either mode, not force a choice at the type level unless that's
  clearly simpler — use your judgment, but don't break existing callers.

### 2. Set the `alg` and `kid` in the JWT header on issuance

- When issuing via the asymmetric path, use `Header::new(Algorithm::RS256)`
  and set `header.kid = Some(self.kid.clone())` before calling `encode`.
- Verify the existing HMAC path is unaffected (still `HS256`, no `kid`
  unless you decide to add one there too for consistency — optional, note
  your choice in the PR description either way).

### 3. Expose the public key in a JWKS-ready shape

- Add a method (e.g. `TokenManager::public_jwk(&self) -> Jwk`) that returns
  the RSA public key as a `Jwk` (n, e, kid, kty="RSA", alg="RS256").
- Check whether `authkestra_resource::jwt::Jwk` (currently
  `Deserialize`-only) can be reused by adding `Serialize` to it, rather than
  defining a second JWK type. Prefer reuse — a duplicate `Jwk` type in two
  crates is exactly the kind of drift RFC-001 was written to avoid.

### 4. Tests

- Round-trip test: issue a token via the asymmetric path, verify it with
  `jsonwebtoken::decode` using the public key directly (not via
  `TokenManager`, to prove the token is independently verifiable — this is
  the whole point of the change).
- Confirm the existing HMAC round-trip test still passes unmodified.
- Confirm `header.kid` is present and matches `TokenManager`'s stored `kid`
  on asymmetric-path tokens.

### 5. Docs

- Doc-comment the new constructor/method explaining when to use asymmetric
  vs HMAC (OP/external verification vs internal resource server).
- No RFC changes needed — RFC-003 §4 already describes this; just link back
  to it from the doc comment if convenient.

## Definition of done

- `cargo test --workspace` green.
- `cargo clippy --workspace -- -D warnings` clean.
- Existing HS256 behavior unchanged (no breaking change to current callers).
- A round-trip test proves a token issued via the new path can be verified
  using only the public key, without `TokenManager`.
