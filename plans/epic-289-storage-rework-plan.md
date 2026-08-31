# Plan: Epic #289 — Storage Architecture Rework

Branch: `epic/289-storage-rework`. Tracks GitHub epic #289 ("Rework storage
architecture: executor-composable traits, satellite SQL crate, conformance
test suite"), which grew out of scoping #287 (SqlxOpStore migration
mechanism). See the epic issue body for full motivating context — this doc
exists to name the phases and their status, not to duplicate that write-up.

## Phase A — `authkestra-store-testsuite` conformance crate

**Status: Done.**

A reusable, generic conformance test suite (`authkestra-store-testsuite`)
that any `KvStore`/`AtomicConsume`/`AtomicInsert`/`OpStore`-family
implementation — first-party or third-party — can run against itself to
prove atomicity of consume/insert-if-absent, replay semantics, expiry
behavior, and concurrent-access races. Ported the existing hand-written
`MemoryStore`/`RedisStore` test coverage into it (`kv.rs`, `atomic.rs`,
`op.rs`).

## Phase B — Executor/`&mut self`-composable trait rework

**Status: Done.**

Reworked `ClientStore`/`AuthorizationCodeStore`/`RefreshTokenStore`/
`DeviceCodeStore`/`ClientAssertionStore`/`DpopReplayStore` (and the `OpStore`
supertrait) to take `&mut self` instead of `&self`, and lifted the trait
definitions plus the OAuth2 domain models (`ClientRegistration`,
`AuthorizationCode`, `RefreshToken`, `DeviceCodeSession`) from
`authkestra-op` up into `authkestra-engine` (`store::traits`, `oauth2::*`),
with `authkestra-op` re-exporting them. This is what lets a host application
eventually compose auth-store operations into its own atomic unit of work
(the executor-composable design point of the epic) — the `&mut self`
signature is the prerequisite; actual executor/transaction plumbing is not
yet built.

Breaking-change fallout from the `&mut self` switch, closed out in this
pass:

- `authkestra-actix`/`authkestra-axum`: the OP store handed to route
  handlers is now `Arc<tokio::sync::Mutex<dyn OpStore>>` (was
  `Arc<dyn OpStore>`), locked once per request. `authkestra-op`'s own
  `OpBuilder::store`/`Op::build` updated to match; `authkestra-op` gained a
  direct (non-dev) `tokio` dependency (`features = ["sync"]`) for the
  `Mutex` type in its own public API.
- Every example in `crates/authkestra/examples/` wires the store through
  that same `Arc<Mutex<..>>` shape.
- `SqlxOpStore<DB>`'s `Clone` impl is now hand-written instead of derived —
  `#[derive(Clone)]` was adding a spurious `DB: Clone` bound that
  Postgres/MySql/Sqlite (the marker types, not `sqlx::Pool`) don't satisfy.
  This is what lets the sqlx concurrency tests give each spawned task its
  own owned clone (sharing the same underlying pool) rather than serializing
  access behind a `Mutex`, which would have defeated the point of testing
  the database's own atomic guarantees under concurrency.
- `authkestra-op`'s large `#[cfg(test)]` surface (~180 tests, mostly in
  `handlers/token.rs`'s test-only `Overriding*Store`/`JktDroppingRefreshStore`
  mock wrappers) updated to the new signatures; `NoClientAssertionStore`'s
  "no store configured" contract collapsed from a dedicated
  `OpError::ReplayProtectionUnavailable` error into `Ok(false)` (already
  correctly treated as "reject" by `authenticate_client`), so the one test
  asserting the old error variant was updated to match rather than kept as
  a stale expectation. `cargo fmt`/`cargo clippy --all-features -- -D
  warnings`/`cargo test --workspace --all-features` all pass on the branch
  as of this pass.

## Phase C — Extract SQL storage into `authkestra-store-sqlx`

**Status: Not started.**

Move `SqlxOpStore` (`authkestra-op/src/sqlx_store.rs`) and, if it still
makes sense once isolated, the deprecated generic `SqlKvStore` in
`authkestra-engine`, into a new satellite workspace crate
`authkestra-store-sqlx`. Goal: `authkestra-op` and `authkestra-engine` end
up with zero `sqlx` dependency — `sql-postgres`/`sql-mysql`/`sql-sqlite`
features and the `sqlx` optional dependency move to the new crate entirely.
The reference SQL implementation stays maintained, versioned, and
CI-tested; this is an extraction, not a deletion in favor of docs.

Rough steps:

1. Scaffold `crates/authkestra-store-sqlx` as a new workspace member.
2. Move `sqlx_store.rs` (and its `#[cfg(test)]` module, and the
   `sqlx-postgres`/`sqlx-sqlite`/`sqlx-mysql` Cargo features) there,
   implementing the (now `&mut self`) `OpStore`-family traits against the
   lifted `authkestra-engine` models.
3. Drop the `sqlx` optional dependency and its features from
   `authkestra-op`'s `Cargo.toml`; same for any remaining `sql-*` plumbing
   in `authkestra-engine` if `SqlKvStore` moves too.
4. Update `crates/authkestra/examples/{axum,actix}_op_server_sqlx.rs` and
   `website/src/content/docs/storage/sql-store.md` to import from the new
   crate path.
5. Run `authkestra-store-testsuite`'s conformance suite against the moved
   `SqlxOpStore` to confirm nothing about the extraction changed behavior.

## Phase D — Real, compiled ORM example crates

**Status: Not started.**

Workspace-member example crates (SeaORM, Diesel — CrateStack explicitly
deferred, see the epic issue's "On CrateStack specifically" section) that
build and run in CI against real ORMs, each implementing the traits from
Phase B and passing the conformance suite from Phase A. Not markdown
snippets — compiled, CI-tested code, so integration examples can't silently
rot the way the epic's motivating problem describes.

## DoD (Definition of Done, whole epic)

- `authkestra-op`/`authkestra-engine` have zero `sqlx` dependency (Phase C).
- `authkestra-store-testsuite` is the documented, canonical way a
  third-party backend proves conformance (Phase A, done).
- At least one real compiled ORM example (SeaORM or Diesel) builds and runs
  its tests in CI against the traits from Phase B (Phase D).
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-features --
  -D warnings`, and `cargo test --workspace --all-features` all pass on the
  branch before it's proposed for merge into `next`/`main`.
