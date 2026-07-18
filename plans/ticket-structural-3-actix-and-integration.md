# Structural Cleanup: Actix Parity & Local Integration

## Goal
Address functional gaps in the Actix web framework adapter and align local Docker infrastructure with `CONTRIBUTING.md`.

## Steps
1. **Actix Macro Parity**
   - Investigate creating Actix-specific support in `authkestra-macros` to match the Axum experience.
   - Alternatively, explicitly document Actix as a second-tier adapter in the README if macro support isn't planned.

2. **Local SQL Integration**
   - Either update `docker-compose.yml` to provision PostgreSQL and MySQL services for local integration testing.
   - OR update `CONTRIBUTING.md` to clarify that SQL tests currently only run against SQLite locally.
