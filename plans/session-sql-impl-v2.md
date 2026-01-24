# Session SQL Implementation Redesign (v2)

## Objective
Refactor `SqlSessionStore` in `authly-session` to decompose the `Session` struct into separate database columns instead of storing the entire object as a single JSON blob. This improves queryability and aligns with standard relational database practices.

## Schema Redesign

The `authly_sessions` table will be updated to the following schema.
*Note: This plan assumes the table will be created/migrated by the user or an external process, but the code must support this schema.*

| Column Name | Type (Generic) | Source Field | Description |
| :--- | :--- | :--- | :--- |
| `id` | VARCHAR/TEXT | `Session.id` | Primary Key. Session ID. |
| `provider_name` | VARCHAR/TEXT | `Identity.provider_id` | e.g., "github", "google". |
| `provider_id` | VARCHAR/TEXT | `Identity.external_id` | User's unique ID from the provider. |
| `email` | VARCHAR/TEXT | `Identity.email` | User's email (Nullable). |
| `name` | VARCHAR/TEXT | `Identity.username` | User's display name (Nullable). |
| `claims` | TEXT | `Identity.attributes` | JSON string of additional attributes. |
| `expires_at` | TIMESTAMP | `Session.expires_at` | Expiration timestamp. |

## Implementation Plan

### 1. Update `authly-session/src/sql_store.rs`

We will modify the `SqlSessionStore` implementation for `Postgres`, `Sqlite`, and `MySql`.

#### Common Logic
- **Serialization**: `Identity.attributes` (HashMap) will be serialized to a JSON string using `serde_json::to_string` before saving.
- **Deserialization**: The `claims` column string will be deserialized back to `HashMap<String, String>` using `serde_json::from_str`.
- **Struct Reconstruction**: `Identity` and `Session` structs will be manually constructed from the query results.

#### Database-Specific Queries

**PostgreSQL (`impl SessionStore for SqlStore<sqlx::Postgres>`)**
*   **`save_session`**:
    ```sql
    INSERT INTO authly_sessions 
    (id, provider_name, provider_id, email, name, claims, expires_at) 
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT(id) DO UPDATE SET 
    provider_name = $2, provider_id = $3, email = $4, name = $5, claims = $6, expires_at = $7
    ```
*   **`load_session`**:
    ```sql
    SELECT id, provider_name, provider_id, email, name, claims, expires_at 
    FROM authly_sessions 
    WHERE id = $1 AND expires_at > $2
    ```

**SQLite (`impl SessionStore for SqlStore<sqlx::Sqlite>`)**
*   **`save_session`**:
    ```sql
    INSERT INTO authly_sessions 
    (id, provider_name, provider_id, email, name, claims, expires_at) 
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
    ON CONFLICT(id) DO UPDATE SET 
    provider_name = ?2, provider_id = ?3, email = ?4, name = ?5, claims = ?6, expires_at = ?7
    ```
*   **`load_session`**:
    ```sql
    SELECT id, provider_name, provider_id, email, name, claims, expires_at 
    FROM authly_sessions 
    WHERE id = ?1 AND expires_at > ?2
    ```

**MySQL (`impl SessionStore for SqlStore<sqlx::MySql>`)**
*   **`save_session`**:
    ```sql
    INSERT INTO authly_sessions 
    (id, provider_name, provider_id, email, name, claims, expires_at) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE 
    provider_name = VALUES(provider_name), 
    provider_id = VALUES(provider_id), 
    email = VALUES(email), 
    name = VALUES(name), 
    claims = VALUES(claims), 
    expires_at = VALUES(expires_at)
    ```
*   **`load_session`**:
    ```sql
    SELECT id, provider_name, provider_id, email, name, claims, expires_at 
    FROM authly_sessions 
    WHERE id = ? AND expires_at > ?
    ```

### 2. Verify Field Mappings
- `provider_name` -> `session.identity.provider_id`
- `provider_id` -> `session.identity.external_id`
- `email` -> `session.identity.email`
- `name` -> `session.identity.username`
- `claims` -> `session.identity.attributes`

## Tasks
- [ ] Modify `authly-session/src/sql_store.rs`
    - [ ] Update `load_session` and `save_session` for Postgres
    - [ ] Update `load_session` and `save_session` for SQLite
    - [ ] Update `load_session` and `save_session` for MySQL
