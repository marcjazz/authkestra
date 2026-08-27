# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.5.5...authkestra-oidc-v0.6.0) - 2026-08-27

### Added

- *(resource)* resolve JWKS per issuer for multi-issuer resource servers ([#254](https://github.com/marcjazz/authkestra/pull/254))

### Fixed

- *(oidc)* [**breaking**] make Claims non-exhaustive and omit spec step 3 ([#258](https://github.com/marcjazz/authkestra/pull/258))
- *(oidc)* [**breaking**] accept array-valued `aud` in ID tokens and verify `azp` ([#244](https://github.com/marcjazz/authkestra/pull/244)) ([#251](https://github.com/marcjazz/authkestra/pull/251))

## [0.5.3](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.5.2...authkestra-oidc-v0.5.3) - 2026-08-24

### Fixed

- *(oidc)* derive ID-token Validation from discovery instead of Validation::default() ([#228](https://github.com/marcjazz/authkestra/pull/228))

## [0.3.4](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.3.3...authkestra-oidc-v0.3.4) - 2026-08-05

### Other

- updated the following local packages: authkestra-engine, authkestra-resource

## [0.3.3](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.3.2...authkestra-oidc-v0.3.3) - 2026-08-02

### Fixed

- *(deps)* let consumers choose the TLS backend instead of forcing aws-lc-rs ([#179](https://github.com/marcjazz/authkestra/pull/179))

## [0.3.2](https://github.com/marcjazz/authkestra/compare/authkestra-oidc-v0.3.1...authkestra-oidc-v0.3.2) - 2026-08-01

### Added

- upgrade jsonwebtoken to v11.x and resolve docs/promises ([#175](https://github.com/marcjazz/authkestra/pull/175)) ([#176](https://github.com/marcjazz/authkestra/pull/176))

## [0.3.0](https://github.com/marcjazz/authkestra/compare/v0.2.4...v0.3.0) - 2026-07-31

### Other

- merge develop into main (conflict free) ([#155](https://github.com/marcjazz/authkestra/pull/155))
- Release/v0.2.5 ([#149](https://github.com/marcjazz/authkestra/pull/149))
