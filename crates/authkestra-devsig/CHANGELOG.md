# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0](https://github.com/marcjazz/authkestra/compare/authkestra-devsig-v0.5.5...authkestra-devsig-v0.6.0) - 2026-08-27

### Fixed

- *(crypto)* [**breaking**] harden authkestra-resource and authkestra-op against low-order Ed25519 keys ([#261](https://github.com/marcjazz/authkestra/pull/261))
- *(devsig)* verify EdDSA strictly, rejecting low-order Ed25519 keys ([#253](https://github.com/marcjazz/authkestra/pull/253))

### Other

- *(examples)* migrate attestation and devsig examples to the unified engine patterns ([#194](https://github.com/marcjazz/authkestra/pull/194)) ([#262](https://github.com/marcjazz/authkestra/pull/262))
- massive sweep to add non_exhaustive to all public structs ([#259](https://github.com/marcjazz/authkestra/pull/259))

## [0.3.2](https://github.com/marcjazz/authkestra/compare/authkestra-devsig-v0.3.1...authkestra-devsig-v0.3.2) - 2026-08-01

### Added

- upgrade jsonwebtoken to v11.x and resolve docs/promises ([#175](https://github.com/marcjazz/authkestra/pull/175)) ([#176](https://github.com/marcjazz/authkestra/pull/176))

## [0.3.0](https://github.com/marcjazz/authkestra/compare/v0.2.5...v0.3.0) - 2026-07-31

### Other

- release v0.3.0 ([#166](https://github.com/marcjazz/authkestra/pull/166))
