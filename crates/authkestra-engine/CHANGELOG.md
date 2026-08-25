# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.5](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.5.4...authkestra-engine-v0.5.5) - 2026-08-24

### Added

- *(engine)* SD-JWT (selective disclosure) issuance and verification ([#238](https://github.com/marcjazz/authkestra/pull/238))

### Fixed

- *(engine)* gate webauthn-only test and totp_webauthn example on their features ([#240](https://github.com/marcjazz/authkestra/pull/240))

### Other

- *(engine)* add SD-JWT runnable example, doctests, and book/README docs ([#241](https://github.com/marcjazz/authkestra/pull/241))

## [0.5.4](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.5.3...authkestra-engine-v0.5.4) - 2026-08-24

### Added

- *(op)* RFC 8705 certificate-bound access tokens for client_credentials ([#231](https://github.com/marcjazz/authkestra/pull/231))

## [0.5.3](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.5.2...authkestra-engine-v0.5.3) - 2026-08-24

### Added

- *(engine)* add private_key_jwt client authentication to ClientCredentialsFlow ([#229](https://github.com/marcjazz/authkestra/pull/229))

### Other

- *(axum,actix)* add E2E integration tests for engine adapters ([#232](https://github.com/marcjazz/authkestra/pull/232))

## [0.5.0](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.4.0...authkestra-engine-v0.5.0) - 2026-08-15

### Fixed

- *(engine)* honor extra["jti"] as a jti override, stop emitting duplicate-key JWTs ([#215](https://github.com/marcjazz/authkestra/pull/215))
- *(engine,op)* accept array-shaped aud claims in token exchange ([#207](https://github.com/marcjazz/authkestra/pull/207))

## [0.4.0](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.3.4...authkestra-engine-v0.4.0) - 2026-08-13

### Added

- *(engine)* add Ed25519/EdDSA signing and OKP JWKS support ([#190](https://github.com/marcjazz/authkestra/pull/190))

## [0.3.4](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.3.3...authkestra-engine-v0.3.4) - 2026-08-05

### Fixed

- *(engine)* derive the asymmetric decoding key from the public half ([#182](https://github.com/marcjazz/authkestra/pull/182))

## [0.3.3](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.3.2...authkestra-engine-v0.3.3) - 2026-08-02

### Fixed

- *(deps)* let consumers choose the TLS backend instead of forcing aws-lc-rs ([#179](https://github.com/marcjazz/authkestra/pull/179))

## [0.3.2](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.3.1...authkestra-engine-v0.3.2) - 2026-08-01

### Added

- upgrade jsonwebtoken to v11.x and resolve docs/promises ([#175](https://github.com/marcjazz/authkestra/pull/175)) ([#176](https://github.com/marcjazz/authkestra/pull/176))

### Other

- clean up scratch dir and bump documentation versions to 0.3.1 ([#173](https://github.com/marcjazz/authkestra/pull/173))

## [0.3.0](https://github.com/marcjazz/authkestra/compare/v0.2.5...v0.3.0) - 2026-07-31

### Other

- release v0.3.0 ([#166](https://github.com/marcjazz/authkestra/pull/166))
