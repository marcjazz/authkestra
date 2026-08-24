# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.2](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.5.1...authkestra-axum-v0.5.2) - 2026-08-24

### Fixed

- *(ci)* unblock lint and deny after Rust 1.98 and RUSTSEC-2026-0258 drift ([#227](https://github.com/marcjazz/authkestra/pull/227))

## [0.3.4](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.3.3...authkestra-axum-v0.3.4) - 2026-08-05

### Other

- updated the following local packages: authkestra-engine, authkestra-resource, authkestra-op

## [0.3.3](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.3.2...authkestra-axum-v0.3.3) - 2026-08-02

### Fixed

- *(deps)* let consumers choose the TLS backend instead of forcing aws-lc-rs ([#179](https://github.com/marcjazz/authkestra/pull/179))

## [0.3.2](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.3.1...authkestra-axum-v0.3.2) - 2026-08-01

### Added

- upgrade jsonwebtoken to v11.x and resolve docs/promises ([#175](https://github.com/marcjazz/authkestra/pull/175)) ([#176](https://github.com/marcjazz/authkestra/pull/176))

### Other

- clean up scratch dir and bump documentation versions to 0.3.1 ([#173](https://github.com/marcjazz/authkestra/pull/173))

## [0.3.1](https://github.com/marcjazz/authkestra/compare/v0.2.4...v0.3.1) - 2026-07-31

### Fixed

- move examples to root crate to permanently resolve cyclic publish failures ([#168](https://github.com/marcjazz/authkestra/pull/168))
- remove circular dev-dependencies from axum and actix adapters ([#159](https://github.com/marcjazz/authkestra/pull/159))

### Other

- release v0.3.0 ([#166](https://github.com/marcjazz/authkestra/pull/166))
- rollback workspace version to 0.2.4 ([#165](https://github.com/marcjazz/authkestra/pull/165))
- merge develop into main (conflict free) ([#155](https://github.com/marcjazz/authkestra/pull/155))
- Release/v0.2.5 ([#149](https://github.com/marcjazz/authkestra/pull/149))

## [0.3.0](https://github.com/marcjazz/authkestra/compare/v0.2.4...v0.3.0) - 2026-07-31

### Fixed

- remove circular dev-dependencies from axum and actix adapters ([#159](https://github.com/marcjazz/authkestra/pull/159))

### Other

- rollback workspace version to 0.2.4 ([#165](https://github.com/marcjazz/authkestra/pull/165))
- merge develop into main (conflict free) ([#155](https://github.com/marcjazz/authkestra/pull/155))
- Release/v0.2.5 ([#149](https://github.com/marcjazz/authkestra/pull/149))
