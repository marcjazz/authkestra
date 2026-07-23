# Plan: Implement AtomicConsume and IndexedKvStore for Redis and SQL

Following the successful migration of all `authkestra-op` stores (`ClientStore`, `AuthorizationCodeStore`, `RefreshTokenStore`, `DeviceCodeStore`) to use blanket implementations bounded by the unified `KvStore` extension traits (`AtomicConsume` and `IndexedKvStore`), we must now extend the `authkestra-engine` Redis and SQL backends to support these traits. 

The Memory backend has already been fully updated, serving as the blueprint.

## 1. Redis Backend (`crates/authkestra-engine/src/store/redis.rs`)

### `AtomicConsume` Implementation
- **Mechanism**: Redis 6.2+ supports the `GETDEL` command which atomically returns the value of a key and deletes it. Alternatively, a simple Lua script can provide the same atomicity guarantees across all Redis versions.
- **Approach**: 
  - Execute a single network round-trip using `GETDEL` (or fallback to Lua: `local v = redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]) end; return v;`).
  - Deserialize the returned value.
- **Atomicity Guarantee**: Redis runs commands serially; `GETDEL` inherently prevents race conditions where two concurrent requests might both think they consumed the code.

### `IndexedKvStore` Implementation
- **Mechanism**: Use a secondary key string to map the index to the primary key.
- **`set_indexed(primary, index, value, ttl)`**:
  - Start a Redis transaction (`MULTI` / `EXEC`) or a pipeline.
  - Store the `value` at the primary key `prefix:{primary}`.
  - Store the `primary` key reference at the index key `prefix:idx:{index}`.
  - Set the same TTL on both keys so the index expires when the primary data expires.
- **`get_by_index(index)`**:
  - `GET prefix:idx:{index}` to fetch the primary key.
  - If found, `GET prefix:{primary_key}`.
  - If the primary key is missing (e.g., evicted or manually deleted), we opportunistically delete the orphaned index key.

## 2. SQL Backend (`crates/authkestra-engine/src/store/sql.rs`)

### Schema Updates
- To support `IndexedKvStore`, the underlying generic KV table needs to accommodate an optional secondary index.
- Since SQL is inherently structured, the simplest generic approach is adding a nullable `index_key` column to the KV table, accompanied by a UNIQUE constraint or index depending on the uniqueness requirements (device user codes are unique).

### `AtomicConsume` Implementation
- **Mechanism**: Use `DELETE ... RETURNING *` (supported by PostgreSQL, SQLite, and recent MariaDB versions) for a single-query atomic consume.
- **Fallback Mechanism**: For MySQL or dialects without `RETURNING`, use a transaction with `SELECT ... FOR UPDATE` followed by `DELETE`.
- **Atomicity Guarantee**: Database locks ensure that only the transaction that successfully selects and deletes the row will return the payload.

### `IndexedKvStore` Implementation
- **`set_indexed(primary, index, value, ttl)`**:
  - Insert or update the row with both the `key` (primary) and `index_key`. 
- **`get_by_index(index)`**:
  - `SELECT * FROM kv_store WHERE index_key = ? AND (expires_at IS NULL OR expires_at > NOW())`.
  - This is a standard O(1) indexed lookup avoiding a full table scan.

## 3. Validation & Testing
- Use the exact same abstract test suite created for `MemoryStore` (`test_atomic_consume`, `test_indexed_store`, `test_get_set_delete`, `test_ttl_expiry`).
- Instantiate the suite via macro or shared test function against a local Redis instance (e.g. using `testcontainers`) and a SQLite in-memory database to ensure cross-backend compliance with the trait contracts.
