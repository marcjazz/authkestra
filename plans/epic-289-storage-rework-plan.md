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
`MemoryStore`/`RedisStore` test coverage into it (`kv.rs`, `atomic.rs`).

**Correction to an earlier pass**: `op.rs`'s `run_op_store_tests` was left
as an empty stub through the Phase 1/2/3 commits ("For Phase 1, we just lay
down the structure") and never actually implemented, despite Phase A being
marked done — the client-assertion suite (`run_client_assertion_store_tests`)
was real, but the `AuthorizationCodeStore`/`RefreshTokenStore`/
`DeviceCodeStore` conformance suite Phase D depends on ("passing the suite
from (3)") was not. Filled in while starting Phase D: single-use/atomic
consume for authorization codes, refresh tokens, and device code sessions;
full device-code lifecycle (store/get/get_by_user_code/update/delete);
revoke-then-unreadable for refresh tokens. `ClientStore` is deliberately
*not* covered — it exposes only `find_client`, so there's no store-agnostic
way to seed a client through the trait itself (registration is out-of-band
by design). Wired into `authkestra-store-testsuite`'s own tests against
`CompositeOpStore<MemoryStore, ...>` and, closing the loop Phase C's own
plan noted but never executed, against `authkestra-store-sqlx`'s
`SqlxOpStore` (in-memory SQLite, seeded with one fixture client via raw SQL
since the FK from codes/tokens to clients needs one to exist).

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

**Status: Done.**

Moved `SqlxOpStore` out of `authkestra-op/src/sqlx_store.rs` into a new
satellite workspace crate, `crates/authkestra-store-sqlx`. `authkestra-op`
now has zero `sqlx` dependency (`cargo tree -p authkestra-op -i sqlx`
matches nothing) — the `sqlx` optional dependency and its
`sqlx`/`sqlx-postgres`/`sqlx-sqlite`/`sqlx-mysql` features, plus the
`testcontainers`/`testcontainers-modules` dev-dependencies they needed,
moved to the new crate entirely, renamed to plain `postgres`/`sqlite`/
`mysql` features (the crate name itself now carries the "sqlx" part, so the
prefix would have stuttered). `sqlx` is a required, non-optional dependency
of the new crate — its whole reason to exist is being the sqlx-backed
implementation, so there's no reason to gate the base dependency behind a
feature the way `authkestra-op` had to when `sqlx` was one option among
several backends in the same crate.

What moved, mechanically: the file itself (`git mv` preserved history),
its three `#[cfg(test)]` backend test modules (14 tests, including the real
Postgres/MySQL/SQLite testcontainers integration tests and the
`sqlx::migrate!` collision regression test), and the
`tests/fixture_migrations/host_app/` fixture that regression test depends
on (`sqlx::migrate!`'s path is resolved relative to `CARGO_MANIFEST_DIR`,
so it has to live in the crate that now owns the test). Internal `crate::`
references became `authkestra_op::`/`authkestra_engine::` (both are now
direct dependencies of the new crate, needed regardless of the `use crate::`
rewrite since Rust doesn't let you reach a transitive dependency's items
without your own `Cargo.toml` entry for it); `authkestra-engine`'s
`SqlKvStore` deprecation notice and a couple of doc-comment mentions
elsewhere were updated to the new import path.

Examples (`crates/authkestra/examples/{axum,actix}_op_server_sqlx.rs`) and
`website/src/content/docs/storage/sql-store.md` updated to the new crate
path and feature names. `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-features --all-targets -- -D warnings`, and
`cargo test --workspace --all-features` all pass — `authkestra-store-sqlx`
carries the 14 tests that used to be `authkestra-op`'s (168 + 14 = the
182 `authkestra-op` had before the move).

**Update**: the deprecated generic `SqlKvStore` in `authkestra-engine`
(`crates/authkestra-engine/src/store/sql/session.rs`) was not moved here —
the epic issue treats that as optional ("if it still makes sense once
isolated") — but was later **removed outright** rather than migrated, per
an explicit follow-up request. See "SqlKvStore removal" below. `sql-postgres`/
`sql-mysql`/`sql-sqlite` and the optional `sqlx` dependency stay on
`authkestra-engine`, unrelated to that removal: `SqlxCredentialStore`
(WebAuthn/TOTP credential storage, `crates/authkestra-engine/src/store/sql/credential.rs`)
still needs them and was never in scope for either the move or the removal.

### SqlKvStore removal

Deleted `session.rs` wholesale (the struct, its `impl_sql_store!` macro
covering all three backends, and its own `#[cfg(test)]` module with real
Postgres/MySQL/SQLite testcontainers integration tests) rather than moving
it to a satellite crate — a direct request superseding the "move it"
framing above. `store/sql/mod.rs` now only wires up `credential.rs`.
Trimmed the now-unneeded pieces from `authkestra-engine/Cargo.toml`: the
`testcontainers-modules` dev-dependency's `postgres`/`mysql` features (kept
`redis`, still needed by `store/redis.rs`'s own test) and a `[dev-dependencies]`
`sqlx` entry that turned out to be fully redundant with what the `sql-*`
features already pull in via the main dependency.

Two examples existed solely to demonstrate `SqlKvStore`:
`axum_sql_store.rs` was deleted outright (nothing left to demonstrate that
`axum_basic_setup.rs`/`axum_session_redis.rs` don't already cover);
`axum_data_layer_macros.rs` — whose actual point is the `#[derive(KvStore)]`
macro, with `SqlKvStore` only ever the backend it happened to wrap — was
rewritten to wrap `RedisStore` instead, preserving the macro demonstration.
A dev-dependency feature enabling `sql-sqlite` on `authkestra-engine` from
the `authkestra` facade crate's `Cargo.toml` came out too, once nothing in
its own examples needed it any more (the two `*_op_server_sqlx.rs` examples
use `authkestra-store-sqlx` and their own direct `sqlx` dev-dependency, not
this). Updated the half-dozen other examples with a passing "or `SqlKvStore`"
mention in a comment, `docs/book/ch08-getting-started-tutorial.md`'s
equivalent comment, and reworked the `website/src/content/docs/storage/kv-store.md`
page (dropped its entire "Generic SQL KV Store" section and the
KV-vs-SQL-store comparison) and the `overview.md`/`sql-store.md` pages'
cross-references to it.

`cargo fmt --all -- --check`, `cargo clippy --workspace --all-features
--all-targets -- -D warnings`, and `cargo test --workspace --all-features`
all pass after the removal.

## Phase D — Real, compiled ORM example crates

**Status: Done — both SeaORM and Diesel examples land; CrateStack stays deferred.**

Workspace-member example crates (SeaORM, Diesel — CrateStack explicitly
deferred, see the epic issue's "On CrateStack specifically" section) that
build and run in CI against real ORMs, each implementing the traits from
Phase B and passing the conformance suite from Phase A. Not markdown
snippets — compiled, CI-tested code, so integration examples can't silently
rot the way the epic's motivating problem describes. No CI workflow changes
needed — `ci.yml`'s existing `cargo test`/`clippy`/`fmt --check` commands
are already workspace-wide, so a new member crate is covered automatically.

### SeaORM (`crates/authkestra-example-seaorm`) — done

A real `SeaOrmOpStore` implementing `ClientStore`/`AuthorizationCodeStore`/
`RefreshTokenStore`/`DeviceCodeStore`/`OpStore` against four SeaORM
entities (`oauth_clients`/`oauth_codes`/`oauth_refresh_tokens`/
`oauth_device_codes`), SQLite-only. Deliberately simpler than
`authkestra-store-sqlx` in two ways, called out in the crate's own doc
comment rather than hidden: no foreign-key constraints between tables (so
no `ON DELETE CASCADE`), and single-use consume for codes/tokens/device
sessions goes through a SeaORM transaction (find-then-delete-or-mark-used)
rather than a single `UPDATE ... RETURNING`/`DELETE ... RETURNING`
statement — correct for SQLite's single-writer model, but a multi-writer
backend would need the conditional-`UPDATE` pattern `authkestra-store-sqlx`
uses instead. Neither is a limitation of the trait design; both are scope
choices to keep the example readable.

Tested for real: `tests/conformance.rs` runs `authkestra-store-testsuite`'s
`run_op_store_tests` against it after seeding one fixture client directly
through a SeaORM `ActiveModel` insert (bypassing `ClientStore`, same
reasoning as `authkestra-store-sqlx`'s own conformance test — see Phase A's
note above). Passes.

### Diesel (`crates/authkestra-example-diesel`) — done

Diesel is sync-only, so `DieselOpStore` hands every trait method's work to
`tokio::task::spawn_blocking` — the standard pattern for embedding a
blocking library in async code, and exactly what a real host application
using Diesel would need to do too. A connection *pool* (`diesel::r2d2`),
not a single connection, is required for this: `SqliteConnection` is
`!Sync`, so each blocking task checks out its own connection rather than
sharing one across threads. JSON-shaped fields (`Vec<String>`, `Identity`,
`DeviceCodeStatus`) are stored as `Text` columns holding a serde_json string
and (de)serialized by hand — Diesel has no built-in JSON column type for
SQLite the way it does for Postgres. Same simplifications as the SeaORM
example otherwise (no foreign keys; transaction-based consume rather than
a single `RETURNING` statement), and the same `run_op_store_tests`
conformance test, seeded the same way.

## DoD (Definition of Done, whole epic)

- `authkestra-op` has zero `sqlx` dependency (Phase C, done).
  `authkestra-engine` still carries one, unrelated to this epic: it backs
  `SqlxCredentialStore` (WebAuthn/TOTP), which was never in scope for either
  a move or removal — see Phase C's "SqlKvStore removal" note.
- `authkestra-store-testsuite` is the documented, canonical way a
  third-party backend proves conformance (Phase A, done).
- At least one real compiled ORM example builds and runs its tests in CI
  against the traits from Phase B (Phase D, done — both
  `authkestra-example-seaorm` and `authkestra-example-diesel`).
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-features --
  -D warnings`, and `cargo test --workspace --all-features` all pass on the
  branch before it's proposed for merge into `next`/`main`.
