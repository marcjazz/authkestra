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

## Proposed Resolution

To securely unify the data layer while adhering to strict OAuth security invariants, we have two primary paths:

### Path A: Extend `KvStore` (Recommended)
1. **Add `async fn consume(&self, key: &str) -> Result<Option<T>, StoreError>` to `KvStore`**.
   * In Redis, this is implemented as an atomic Lua script (`GET` then `DEL`).
   * In SQL, this is a transaction with `SELECT ... FOR UPDATE` followed by `DELETE`.
2. **Dual-write inside OP**: Implement `DeviceCodeStore` using `KvStore<DeviceCodeSession> + KvStore<String>`. The OP will handle writing the secondary index pointer and cleaning it up after `consume`.

### Path B: The Adapter/Provider Crate
1. Leave `KvStore` as a pure, simple Key-Value trait in `authkestra-engine`.
2. Create native SQL/Redis implementations for `AuthorizationCodeStore` and `DeviceCodeStore` in a dedicated adapter crate (e.g. `authkestra-op-stores` or utilizing the existing `authkestra-providers` infrastructure).
3. These native implementations use database-specific features (like `UPDATE ... RETURNING` in Postgres) to ensure atomicity and can perform proper SQL secondary indexing without application-level dual writes.

*Decision pending review before proceeding with implementation.*
