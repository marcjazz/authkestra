# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.6.3...authkestra-op-v0.7.0) - 2026-08-31

### Other

- add coverage for auth strategies and flow orchestration ([#297](https://github.com/marcjazz/authkestra/pull/297)) ([#298](https://github.com/marcjazz/authkestra/pull/298))
- Merge next into main (DPoP, migrations, and fixes) ([#292](https://github.com/marcjazz/authkestra/pull/292))

## [0.6.3](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.6.2...authkestra-op-v0.6.3) - 2026-08-28

### Fixed

- *(op)* add public constructors for non_exhaustive store types ([#271](https://github.com/marcjazz/authkestra/pull/271))

## [0.6.2](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.6.1...authkestra-op-v0.6.2) - 2026-08-28

### Other

- correct API drift across README, crate docs, website and book ([#269](https://github.com/marcjazz/authkestra/pull/269))

## [0.6.1](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.6.0...authkestra-op-v0.6.1) - 2026-08-28

### Fixed

- *(op)* verify EdDSA strictly and refuse low-order enrolment keys ([#256](https://github.com/marcjazz/authkestra/pull/256)) ([#265](https://github.com/marcjazz/authkestra/pull/265))

## [0.6.0](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.5.5...authkestra-op-v0.6.0) - 2026-08-27

### Added

- *(op)* route authorization_code grant through the OpStore seam ([#249](https://github.com/marcjazz/authkestra/pull/249))

### Fixed

- *(crypto)* [**breaking**] harden authkestra-resource and authkestra-op against low-order Ed25519 keys ([#261](https://github.com/marcjazz/authkestra/pull/261))

### Other

- massive sweep to add non_exhaustive to all public structs ([#259](https://github.com/marcjazz/authkestra/pull/259))

## [0.5.5](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.5.4...authkestra-op-v0.5.5) - 2026-08-24

### Other

- *(engine)* add SD-JWT runnable example, doctests, and book/README docs ([#241](https://github.com/marcjazz/authkestra/pull/241))

## [0.5.4](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.5.3...authkestra-op-v0.5.4) - 2026-08-24

### Added

- *(op)* RFC 8705 certificate-bound access tokens for client_credentials ([#231](https://github.com/marcjazz/authkestra/pull/231))

## [0.5.3](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.5.2...authkestra-op-v0.5.3) - 2026-08-24

### Added

- *(engine)* add private_key_jwt client authentication to ClientCredentialsFlow ([#229](https://github.com/marcjazz/authkestra/pull/229))
- *(op)* add revocation_endpoint field to OidcDiscovery (RFC 8414 §2) ([#226](https://github.com/marcjazz/authkestra/pull/226))

### Fixed

- *(op)* validate requested audience against allowed_audiences in client_credentials ([#230](https://github.com/marcjazz/authkestra/pull/230))

## [0.5.1](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.5.0...authkestra-op-v0.5.1) - 2026-08-15

### Added

- *(op)* add RedisClientAssertionStore backed by redis ([#211](https://github.com/marcjazz/authkestra/pull/211))

## [0.5.0](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.4.0...authkestra-op-v0.5.0) - 2026-08-15

### Fixed

- *(op)* add issued_token_type to token-exchange response, expose default_handle_token_exchange ([#217](https://github.com/marcjazz/authkestra/pull/217))
- *(op)* omit authorization_endpoint when unsupported, gate authorization_code on client grant ([#214](https://github.com/marcjazz/authkestra/pull/214))
- *(engine,op)* accept array-shaped aud claims in token exchange ([#207](https://github.com/marcjazz/authkestra/pull/207))

### Other

- make token-exchange grant overridable via OpStore, support id_token ([#208](https://github.com/marcjazz/authkestra/pull/208))

## [0.4.0](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.3.4...authkestra-op-v0.4.0) - 2026-08-13

### Added

- *(engine)* add Ed25519/EdDSA signing and OKP JWKS support ([#190](https://github.com/marcjazz/authkestra/pull/190))

### Other

- make refresh_token overridable via OpStore, issue id_token on openid scope ([#191](https://github.com/marcjazz/authkestra/pull/191))

## [0.3.4](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.3.3...authkestra-op-v0.3.4) - 2026-08-05

### Other

- updated the following local packages: authkestra-engine, authkestra-resource

## [0.3.3](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.3.2...authkestra-op-v0.3.3) - 2026-08-02

### Fixed

- *(deps)* let consumers choose the TLS backend instead of forcing aws-lc-rs ([#179](https://github.com/marcjazz/authkestra/pull/179))

## [0.3.2](https://github.com/marcjazz/authkestra/compare/authkestra-op-v0.3.1...authkestra-op-v0.3.2) - 2026-08-01

### Added

- upgrade jsonwebtoken to v11.x and resolve docs/promises ([#175](https://github.com/marcjazz/authkestra/pull/175)) ([#176](https://github.com/marcjazz/authkestra/pull/176))

### Other

- clean up scratch dir and bump documentation versions to 0.3.1 ([#173](https://github.com/marcjazz/authkestra/pull/173))

## [0.3.0](https://github.com/marcjazz/authkestra/compare/v0.2.5...v0.3.0) - 2026-07-31

### Other

- release v0.3.0 ([#166](https://github.com/marcjazz/authkestra/pull/166))
