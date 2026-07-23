# Architecture Dilemma: Unifying OP Stores with the Data Layer

## The Goal
We want to align the specialized OpenID Connect Provider stores (`DeviceCodeStore`, `AuthorizationCodeStore`, `RefreshTokenStore`, `ClientStore`) with the new unified `KvStore` abstraction in `authkestra-engine`. The goal is to drop the custom `InMemory*` stores in `authkestra-op` in favor of production-ready Redis/SQL persistence without tight-coupling `authkestra-op` to database drivers.

## The Dilemmas

### 1. The Secondary Index Problem (`DeviceCodeStore`)
The OAuth 2.0 Device Flow (RFC 8628) strictly uses two distinct keys for the same session:
- **`device_code`**: A secure 32-byte polling token used silently by the device in the background. (Needed by `POST /token`).
- **`user_code`**: A short, typable 8-character string submitted by the human user. (Needed by `POST /device/verify`).

**Why this breaks simple KV:**
A standard Key-Value store (`KvStore<T>`) is designed for Primary Key lookups (`get(key)`). If we use `KvStore`, we must implement a **dual-write / secondary index** pattern manually.
* Example: `set("device_code:123", Session)` AND `set("user_code:ABC", "device_code:123")`.
* **Risk**: Dual writes without distributed transactions can lead to orphaned keys or split-brain records if one write fails.

### 2. The Atomic Consumption Problem (TOCTOU)
`AuthorizationCodeStore` and `DeviceCodeStore` both require **atomic** consumption of codes. An authorization code must be checked, fetched, and invalidated in one indivisible operation.
* If implemented naively on top of `KvStore` as `get(key)` followed by `delete(key)`, there is a Time-Of-Check to Time-Of-Use (TOCTOU) race condition. A concurrent replay attack could theoretically fetch the code twice before the first thread deletes it.

## The Resolution: Extension Traits over KvStore

To securely unify the data layer while adhering to strict OAuth security invariants without bloating the base `KvStore` interface, we will use small, composable extension traits:

1. **`AtomicConsume<T>`**: Backends that can natively and atomically fetch-and-remove a value implement this.
2. **`IndexedKvStore<T>`**: Backends that can atomically write a value under a primary key while simultaneously maintaining a secondary lookup key implement this.

```rust
#[async_trait]
pub trait AtomicConsume<T>: KvStore<T> {
    async fn consume(&self, key: &str) -> Result<Option<T>, StoreError>;
}

#[async_trait]
pub trait IndexedKvStore<T>: KvStore<T> {
    async fn set_indexed(&self, primary_key: &str, secondary_key: &str, value: T, ttl: std::time::Duration) -> Result<(), StoreError>;
    async fn get_by_index(&self, secondary_key: &str) -> Result<Option<T>, StoreError>;
}
```

### Why this is the chosen path:
1. **Compile-Time Safety**: The atomicity requirement becomes a compile-time trait bound in `authkestra-op` (`impl<S: KvStore<T> + AtomicConsume<T>>`). A backend that cannot prove atomicity simply fails to compile when wired up, rather than exposing a subtle runtime race.
2. **Native Atomicity**: `set_indexed` pushes the responsibility of atomic dual-writes down to the storage engine (e.g., SQL `UNIQUE` index or Redis Lua scripts), avoiding brittle multi-step orchestrations in application code.
3. **No Interface Bloat**: The base `KvStore` remains plain and simple for generic use cases like `SessionStore`.
4. **Preserved Goals**: Everything remains inside `authkestra-engine::store` and OP's hand-rolled `InMemory*` stores can be deleted in favor of a clean blanket impl.

### Rollout Strategy
We will implement these traits iteratively per backend to maintain focus and high test quality:
1. **Memory Backend**: Prove the trait design and swap out OP's hand-rolled `InMemory*` stores.
2. **Redis Backend**: Implement atomic `EVAL` scripts and transaction logic.
3. **SQL Backend**: Implement `SELECT ... FOR UPDATE` and schema constraints.
