# Chapter 9: Security & Threat Model

Authkestra is designed with security as a primary concern. This chapter outlines our security posture, cryptographic choices, secrets management, and our comprehensive threat model.

## Core Cryptographic Choices

We select modern, battle-tested cryptographic primitives and avoid legacy algorithms.

### Password Hashing: Argon2id

All user passwords stored via local providers are hashed using **Argon2id**. This algorithm provides resistance against both GPU-cracking attacks and side-channel timing attacks.

- **Default Parameters**: Tuned for modern server hardware to take ~0.5 seconds per hash, balancing security and user experience.
- **Upgrades**: Hashing parameters are versioned, allowing for seamless upgrades when hardware capabilities advance.

### Token Signatures: EdDSA (Ed25519)

For signing JSON Web Tokens (JWTs) and internal verifiable credentials, we default to **EdDSA (Ed25519)**.

- **Why?**: It offers superior performance and security margins compared to RSA, and is less prone to implementation vulnerabilities than ECDSA.
- **Fallback**: RS256 is supported strictly for compatibility with legacy third-party systems that do not yet support EdDSA.

## Secrets Management & Key Rotation

### Key Material

Authkestra requires specific cryptographic keys for operation:

- **Cookie Encryption Key**: Used for encrypting session state (AES-GCM).
- **Token Signing Keys**: The private keys used to sign JWTs.

### Key Rotation Strategy

We implement automated, zero-downtime key rotation:

1. **Multiple Keys**: The engine maintains a JWKS (JSON Web Key Set) containing multiple active keys.
2. **Current Key**: One key is designated as the "current" signing key.
3. **Grace Period**: Older keys are retained in the JWKS for a configurable grace period (e.g., 24 hours) to validate tokens issued before the rotation.
4. **Invalidation**: Once the grace period expires, the old key is purged.

## Threat Model

Our threat model assumes a hostile environment and categorizes potential attacks and our mitigations:

### 1. Identity Spoofing & Credential Stuffing

- **Threat**: Attackers use leaked credentials from other breaches or brute-force passwords.
- **Mitigation**: Rate limiting by IP and account, support for mandatory Multi-Factor Authentication (MFA), and secure password hashing (Argon2id).

### 2. Session Hijacking (XSS/CSRF)

- **Threat**: Attackers steal session tokens or forge requests.
- **Mitigation**:
  - Cookies are always `HttpOnly`, `Secure`, and use `SameSite=Lax` or `Strict`.
  - Token payloads do not contain sensitive PII.
  - State and Nonce validation in OAuth flows mitigates CSRF.

### 3. Replay Attacks

- **Threat**: Intercepting and reusing a valid request or token.
- **Mitigation**: Short-lived access tokens, use of PKCE (Proof Key for Code Exchange) by default for all OAuth flows, and strict validation of the `jti` (JWT ID) claim for single-use tokens.

### 4. Privilege Escalation

- **Threat**: A user accessing resources they are not authorized for.
- **Mitigation**: Strict typing in Rust prevents many logical bypasses. Policies are evaluated securely in the core engine before any action is authorized, and the `RequireAuth` extractors enforce valid session state.

## Reporting Vulnerabilities

If you discover a security vulnerability in Authkestra, please do **NOT** open a public issue. Instead, email security@authkestra.example.com or use the GitHub Security Advisory feature. We aim to acknowledge reports within 48 hours and coordinate a fix and release.
