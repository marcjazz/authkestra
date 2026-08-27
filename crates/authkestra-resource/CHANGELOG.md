# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.5.5...authkestra-resource-v0.6.0) - 2026-08-27

### Added

- *(resource)* resolve JWKS per issuer for multi-issuer resource servers ([#254](https://github.com/marcjazz/authkestra/pull/254))

### Fixed

- *(resource)* gracefully reject untrusted issuers and enforce iss claim ([#260](https://github.com/marcjazz/authkestra/pull/260))

### Other

- massive sweep to add non_exhaustive to all public structs ([#259](https://github.com/marcjazz/authkestra/pull/259))
- *(resource)* [**breaking**] mark ValidationConfig non_exhaustive and pin its defaults ([#250](https://github.com/marcjazz/authkestra/pull/250))

## [0.5.4](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.5.3...authkestra-resource-v0.5.4) - 2026-08-24

> **⚠️ Note on Semantic Versioning Break**
> This release introduced a breaking change by adding `require_cert_binding` to `ValidationConfig`, which was an exhaustive struct at the time. Downstream users employing struct-literal construction (`ValidationConfig { ... }`) will face compilation failures ("missing field"). This is permanently corrected in `0.6.0` by making the struct `#[non_exhaustive]`.

### Added

- *(op)* RFC 8705 certificate-bound access tokens for client_credentials ([#231](https://github.com/marcjazz/authkestra/pull/231))

## [0.3.4](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.3.3...authkestra-resource-v0.3.4) - 2026-08-05

### Other

- updated the following local packages: authkestra-engine

## [0.3.3](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.3.2...authkestra-resource-v0.3.3) - 2026-08-02

### Fixed

- *(deps)* let consumers choose the TLS backend instead of forcing aws-lc-rs ([#179](https://github.com/marcjazz/authkestra/pull/179))

## [0.3.2](https://github.com/marcjazz/authkestra/compare/authkestra-resource-v0.3.1...authkestra-resource-v0.3.2) - 2026-08-01

### Added

- upgrade jsonwebtoken to v11.x and resolve docs/promises ([#175](https://github.com/marcjazz/authkestra/pull/175)) ([#176](https://github.com/marcjazz/authkestra/pull/176))

## [0.3.0](https://github.com/marcjazz/authkestra/compare/v0.2.5...v0.3.0) - 2026-07-31

### Other

- release v0.3.0 ([#166](https://github.com/marcjazz/authkestra/pull/166))
