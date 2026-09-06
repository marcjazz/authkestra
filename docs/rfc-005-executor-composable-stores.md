# RFC-005 — Executor/transaction-composable stores

Status: implemented (prototype), authkestra#336
Supersedes the deferred half of proposed direction (1) in authkestra#289.

## Problem

A host application that wants "create user + create org + issue refresh token"
as one atomic operation cannot get it. Every `OpStore`-family method takes
`&mut self` and manages its own storage call internally, so an authkestra write
commits independently of whatever transaction the application already has open
for its own schema. If the application's write then fails, the refresh token is
already durable.

Epic #289's Phase B reworked the traits from `&self` to `&mut self` and called
that "the prerequisite; actual executor/transaction plumbing is not yet built."
This RFC builds it.

## The constraint that shapes everything

The obvious design — an executor parameter on each method —

```rust
async fn store_token<E: Executor>(&mut self, ex: &mut E, token: RefreshToken) -> ...;
```

is not available. `authkestra-axum` and `authkestra-actix` hold an
`Arc<dyn CloneableOpStore>` and clone a `Box<dyn OpStore>` out of it per
request. A generic method parameter makes `OpStore` non-dyn-compatible, and
neither of those trait objects can be named any more. An associated
`type Executor` has the same effect by a different route: `dyn OpStore`
becomes `dyn OpStore<Executor = ...>`, which no longer names one type across
backends.

The second constraint is that backends disagree about what an executor even is.
sqlx wants `&mut Connection`, SeaORM wants `&impl ConnectionTrait`, Diesel wants
a `&mut SqliteConnection` inside a blocking closure and has no owned transaction
handle at all. There is no shared shape to make generic over.

## Design

**Put the transaction in the store value, not in the method signatures.** This
is what `&mut self` was always for: a store that owns an open transaction runs
every one of its methods inside it, with no change to any existing signature.

Two new traits, in `authkestra-op::store`:

```rust
#[async_trait]
pub trait OpStoreTransaction: OpStore {
    async fn commit(self: Box<Self>) -> Result<(), StoreError>;
    async fn rollback(self: Box<Self>) -> Result<(), StoreError>;
}

#[async_trait]
pub trait TransactionalOpStore: OpStore {
    async fn begin(&self) -> Result<Box<dyn OpStoreTransaction + Send>, StoreError>;
}
```

Both stay dyn-compatible: `self: Box<Self>` is an object-safe receiver, and
every inherited method already takes `&mut self`. Nothing about the existing
traits, the adapters, or `Arc<dyn CloneableOpStore>` changes. This is a purely
additive, non-breaking capability.

### Where the host's own queries go

The trait deliberately does **not** try to hand back an executor. The host's own
statements are written against a concrete driver, so there is nothing useful a
backend-agnostic trait could return. Each backend exposes its native handle on
its own concrete transaction type instead, in whatever shape is idiomatic there:

| backend | begin | native handle |
|---|---|---|
| `authkestra-store-sqlx` | `SqlxOpStore::begin_tx` | `AsMut<DB::Connection>` — `tx.as_mut()`, as on a bare `sqlx::Transaction` |
| `authkestra-example-seaorm` | `SeaOrmOpStore::begin_tx` | `SeaOrmOpStoreTx::transaction() -> &DatabaseTransaction` |
| `authkestra-example-diesel` | `DieselOpStore::begin_tx` | `DieselOpStoreTx::run(closure)` |

```rust
let mut tx = store.begin_tx().await?;

sqlx::query("INSERT INTO app_users (id, email) VALUES (?1, ?2)")
    .bind(&user_id).bind(&email)
    .execute(tx.as_mut()).await?;      // the application's own write

tx.store_token(refresh_token).await?;  // authkestra's write, same transaction

tx.commit().await?;                    // both, or neither
```

Note the three handle shapes differ (`&mut`, `&`, and a closure). That is the
proof the split is in the right place: everything genuinely shared lives on the
trait, everything genuinely driver-specific stays inherent, and neither has to
compromise for the other.

### Why not defaulted methods on `OpStore`

`TransactionalOpStore` is opt-in so a backend with no transactions — the
in-memory store, Redis — cannot accidentally claim it. There is no honest
default: one that committed each write immediately and made `rollback` a no-op
would hand callers a unit of work that silently isn't one. Those backends do not
implement the trait, and the conformance suite skips them by construction.

## What implementing it surfaced

Three things that a design document alone would not have caught.

**1. Sharing the query bodies is most of the work.** A transaction-scoped store
has to run the same SQL as the pool-backed one. In all three backends the
queries were written inline against the pool (`.execute(&self.pool)`,
`.one(&self.db)`, `pool.get()` inside `spawn_blocking`). Each is now a `queries`
module written once against a *connection*, with two thin impls that differ only
in where the connection comes from. Without that, every backend would carry two
copies of the same SQL.

**2. The single-use consume paths must nest, and one of them couldn't.** The
consume operations open their own transaction where the dialect lacks
`DELETE ... RETURNING`. Called inside a caller's transaction, that has to become
a nested savepoint governed by the outer commit — not an independent transaction
that commits on its own.

- sqlx: free. `Connection::begin()` on a connection already in a transaction
  issues a `SAVEPOINT`. Taking `&mut Connection` rather than a generic
  `Executor` in the `queries` module is what makes this work, since an
  `Executor` cannot `begin()`.
- SeaORM: free, same way, via `TransactionTrait` on `DatabaseTransaction`.
- Diesel: **not** free. The consume paths used `immediate_transaction`
  (`BEGIN IMMEDIATE`, which takes SQLite's write lock up front instead of
  failing at the first write). SQLite has no nested `BEGIN`, so inside a host
  transaction that errors with "cannot start a transaction within a
  transaction". Fixed by choosing on depth: `immediate_transaction` at depth 0,
  Diesel's plain `transaction` (which emits `SAVEPOINT`) when already nested.
  Nothing is lost, because `begin_tx` opens the outer transaction with
  `BEGIN IMMEDIATE` itself, so the write lock is already held.

**3. Two Diesel-specific frictions worth recording.**

- `SqliteConnection` is `Send` but `!Sync`, and the store traits require
  `Send + Sync`. A transaction-scoped store holding a connection therefore
  cannot implement `OpStore` without a `Mutex` whose only job is to satisfy the
  bound — it is never contended, and every access goes through `get_mut`. The
  `Sync` bound buys those traits nothing now that every method takes
  `&mut self`; dropping it would be a breaking change to every implementor, so
  it stays for now. Worth revisiting.
- r2d2 asks Diesel whether a returned connection is broken, and one still inside
  a transaction answers yes — so a dropped transaction would make the pool
  discard the connection and dial a new one. `DieselOpStoreTx` therefore rolls
  back in `Drop`. Synchronously, since `Drop` cannot await, which is a real
  reason to prefer calling `commit`/`rollback` explicitly.

## Conformance

`authkestra-store-testsuite::tx::run_transactional_op_store_tests` is the
generic proof, run by all three backends:

- a write inside a rolled-back transaction is not durable
- a write inside a committed transaction is
- dropping without committing rolls back
- a transaction reads its own uncommitted writes
- **store-then-consume, rolled back as a unit, leaves nothing behind** — the
  assertion that catches a consume path which opened its own transaction and
  committed independently of the caller's

It deliberately does not assert that an uncommitted write is invisible to a
*different* connection. That is the other half of what a transaction means, but
checking it requires holding the transaction open while reading through the
pool, and a backend under test may be on a single-connection pool (in-memory
SQLite necessarily is), where that deadlocks rather than fails.

Each backend additionally has a `test_host_write_and_store_write_commit_as_one_unit`
test covering the actual goal — an application-owned table written alongside an
`OpStore` write, committed and rolled back as one — since that part is
driver-specific and cannot live in the generic suite.

## Not done

- **Composing across two different backends.** A deployment with clients in
  Postgres and codes in Redis gets no atomicity between them; `CompositeOpStore`
  does not implement `TransactionalOpStore`. Distributed transactions are out of
  scope, and probably permanently.
- **Relaxing the `Send + Sync` bound** on the store traits (see friction 3).
- **`authkestra-engine`'s `SqlxCredentialStore`** (WebAuthn/TOTP) has the same
  shape and the same latent problem — see the ordering tradeoff documented in
  `register_totp` (authkestra#326/#330) — but was out of scope here.
