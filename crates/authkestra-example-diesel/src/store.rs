use crate::models::{ClientRow, CodeRow, DeviceCodeRow, RefreshTokenRow};
use crate::schema::{oauth_clients, oauth_codes, oauth_device_codes, oauth_refresh_tokens};
use async_trait::async_trait;
use authkestra_engine::store::StoreError;
use authkestra_op::client::{ClientRegistration, ClientStore};
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStore};
use authkestra_op::refresh::{RefreshToken, RefreshTokenStore};
use authkestra_op::store::OpStore;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sqlite::SqliteConnection;

type SqlitePool = Pool<ConnectionManager<SqliteConnection>>;

fn pool_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Internal(format!("connection pool error: {e}"))
}

fn diesel_err(e: diesel::result::Error) -> StoreError {
    StoreError::Internal(format!("diesel error: {e}"))
}

/// True if `database_url` names a private, per-connection SQLite database —
/// one where a multi-connection pool would scatter this store's rows across
/// several unrelated databases (see [`DieselOpStore::connect`]).
///
/// Covers the bare `:memory:` filename, the URI form `file::memory:`, and
/// `""` (a private temporary on-disk database — same per-connection
/// isolation). `cache=shared` is the one exception: it puts an in-memory
/// database in SQLite's shared cache instead, which every connection in the
/// process can see, so it does not need — and should not get — the
/// single-connection restriction the other forms do.
fn is_private_memory_url(database_url: &str) -> bool {
    let url = database_url.trim();
    if url.is_empty() {
        return true;
    }
    let lower = url.to_ascii_lowercase();
    lower.contains(":memory:") && !lower.contains("cache=shared")
}

/// A real, compiled `OpStore` implementation backed by [`diesel`] —
/// authkestra#289's second proof (alongside `authkestra-example-seaorm`)
/// that the storage traits are implementable by a third-party ORM,
/// including one with a synchronous API.
///
/// Diesel is sync-only, so every trait method here hands its work to
/// [`tokio::task::spawn_blocking`] rather than blocking the async runtime —
/// the standard pattern for embedding a blocking library in async code, and
/// exactly what a real host application using Diesel would need to do too.
/// A connection pool (not a single connection) is required for this: a
/// `SqliteConnection` is `!Sync`, so each blocking task needs to check out
/// its own connection rather than share one across threads.
///
/// Deliberately simpler than `authkestra-store-sqlx` in the same ways
/// `authkestra-example-seaorm` is: no foreign-key constraints between
/// tables, and single-use consume goes through a transaction
/// (find-then-delete-or-mark-used) rather than a single
/// `UPDATE`/`DELETE ... RETURNING` statement.
#[derive(Clone)]
#[non_exhaustive]
pub struct DieselOpStore {
    pool: SqlitePool,
}

impl DieselOpStore {
    /// Builds a connection pool for `database_url` (e.g. `:memory:` or a
    /// file path) and wraps it.
    ///
    /// A private, per-connection in-memory (or temporary) database is
    /// special-cased to a single-connection pool: SQLite gives every such
    /// connection its own independent database, so a pool with r2d2's
    /// default size (10) would silently scatter this store's rows across
    /// ten unrelated in-memory databases — `migrate()` would create tables
    /// in whichever one it happens to check out, and any other checkout
    /// would see "no such table". A real (file-backed) database has no such
    /// problem and keeps the default pool size, since SQLite's own locking
    /// already serializes writers across connections.
    ///
    /// SQLite accepts several spellings of "private in-memory/temporary
    /// database" — the bare `:memory:` filename, the URI form
    /// `file::memory:` (with or without a trailing query string, *unless*
    /// it sets `cache=shared`, which is the actual escape hatch for sharing
    /// one in-memory database across connections), and `""` (a private
    /// temporary on-disk database, same per-connection isolation problem).
    /// Matching only the exact string `":memory:"` misses the other two and
    /// silently reintroduces the ten-independent-databases bug this guard
    /// exists to prevent.
    pub fn connect(database_url: &str) -> Result<Self, diesel::r2d2::PoolError> {
        let manager = ConnectionManager::<SqliteConnection>::new(database_url);
        let mut builder = Pool::builder();
        if is_private_memory_url(database_url) {
            builder = builder.max_size(1);
        }
        let pool = builder.build(manager)?;
        Ok(Self { pool })
    }

    /// Wraps an already-built connection pool.
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// The underlying connection pool, for host-application code that wants
    /// to run its own queries against the same database (e.g. seeding a
    /// `ClientRegistration` — `ClientStore` has no generic write path).
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Creates the four tables this store needs, if they don't already
    /// exist. Idempotent — safe to call on every startup, same contract as
    /// `authkestra-store-sqlx::SqlxOpStore::migrate`.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            diesel::sql_query(
                "CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_secret_hash TEXT,
                    require_pkce BOOLEAN NOT NULL,
                    redirect_uris TEXT NOT NULL,
                    grant_types TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    allowed_audiences TEXT NOT NULL,
                    token_endpoint_auth_method TEXT,
                    jwks TEXT
                )",
            )
            .execute(&mut conn)
            .map_err(diesel_err)?;
            diesel::sql_query(
                "CREATE TABLE IF NOT EXISTS oauth_codes (
                    code TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    code_challenge TEXT,
                    code_challenge_method TEXT,
                    nonce TEXT,
                    identity TEXT NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN NOT NULL
                )",
            )
            .execute(&mut conn)
            .map_err(diesel_err)?;
            diesel::sql_query(
                "CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
                    token TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    identity TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    jkt TEXT
                )",
            )
            .execute(&mut conn)
            .map_err(diesel_err)?;
            diesel::sql_query(
                "CREATE TABLE IF NOT EXISTS oauth_device_codes (
                    device_code TEXT PRIMARY KEY,
                    user_code TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    status TEXT NOT NULL,
                    last_polled_at TIMESTAMP
                )",
            )
            .execute(&mut conn)
            .map_err(diesel_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }
}

#[async_trait]
impl ClientStore for DieselOpStore {
    async fn find_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientRegistration>, StoreError> {
        let pool = self.pool.clone();
        let client_id = client_id.to_string();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            let row: Option<ClientRow> = oauth_clients::table
                .find(client_id)
                .first(&mut conn)
                .optional()
                .map_err(diesel_err)?;
            row.map(ClientRow::into_domain).transpose()
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }
}

#[async_trait]
impl AuthorizationCodeStore for DieselOpStore {
    async fn store_code(&mut self, code: AuthorizationCode) -> Result<(), StoreError> {
        let pool = self.pool.clone();
        let row = CodeRow::from_domain(&code)?;
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            diesel::insert_into(oauth_codes::table)
                .values(&row)
                .execute(&mut conn)
                .map_err(diesel_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }

    async fn consume_code(&mut self, code: &str) -> Result<Option<AuthorizationCode>, StoreError> {
        let pool = self.pool.clone();
        let code = code.to_string();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            // Single-use, atomically: SQLite serializes writers, so the
            // transaction below is exact for this backend — a multi-writer
            // backend would need a conditional `UPDATE ... WHERE used =
            // false` instead, same reasoning as authkestra-store-sqlx's own
            // consume_code.
            conn.transaction(|conn| {
                let row: Option<CodeRow> = oauth_codes::table.find(&code).first(conn).optional()?;
                let Some(row) = row else {
                    return Ok(None);
                };
                if row.used {
                    return Ok(None);
                }
                diesel::update(oauth_codes::table.find(&code))
                    .set(oauth_codes::used.eq(true))
                    .execute(conn)?;
                Ok::<_, diesel::result::Error>(Some(row))
            })
            .map_err(diesel_err)?
            .map(CodeRow::into_domain)
            .transpose()
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }
}

#[async_trait]
impl RefreshTokenStore for DieselOpStore {
    async fn store_token(&mut self, token: RefreshToken) -> Result<(), StoreError> {
        let pool = self.pool.clone();
        let row = RefreshTokenRow::from_domain(&token)?;
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            diesel::insert_into(oauth_refresh_tokens::table)
                .values(&row)
                .execute(&mut conn)
                .map_err(diesel_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }

    async fn get_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        let pool = self.pool.clone();
        let token = token.to_string();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            let row: Option<RefreshTokenRow> = oauth_refresh_tokens::table
                .find(token)
                .first(&mut conn)
                .optional()
                .map_err(diesel_err)?;
            row.map(RefreshTokenRow::into_domain).transpose()
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }

    async fn revoke_token(&mut self, token: &str) -> Result<(), StoreError> {
        let pool = self.pool.clone();
        let token = token.to_string();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            diesel::delete(oauth_refresh_tokens::table.find(token))
                .execute(&mut conn)
                .map_err(diesel_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }

    async fn consume_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        let pool = self.pool.clone();
        let token = token.to_string();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            conn.transaction(|conn| {
                let row: Option<RefreshTokenRow> = oauth_refresh_tokens::table
                    .find(&token)
                    .first(conn)
                    .optional()?;
                let Some(row) = row else {
                    return Ok(None);
                };
                diesel::delete(oauth_refresh_tokens::table.find(&token)).execute(conn)?;
                Ok::<_, diesel::result::Error>(Some(row))
            })
            .map_err(diesel_err)?
            .map(RefreshTokenRow::into_domain)
            .transpose()
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }
}

#[async_trait]
impl DeviceCodeStore for DieselOpStore {
    async fn store_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        let pool = self.pool.clone();
        let row = DeviceCodeRow::from_domain(&session)?;
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            diesel::insert_into(oauth_device_codes::table)
                .values(&row)
                .execute(&mut conn)
                .map_err(diesel_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }

    async fn get_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let pool = self.pool.clone();
        let device_code = device_code.to_string();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            let row: Option<DeviceCodeRow> = oauth_device_codes::table
                .find(device_code)
                .first(&mut conn)
                .optional()
                .map_err(diesel_err)?;
            row.map(DeviceCodeRow::into_domain).transpose()
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }

    async fn get_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let pool = self.pool.clone();
        let user_code = user_code.to_string();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            let row: Option<DeviceCodeRow> = oauth_device_codes::table
                .filter(oauth_device_codes::user_code.eq(user_code))
                .first(&mut conn)
                .optional()
                .map_err(diesel_err)?;
            row.map(DeviceCodeRow::into_domain).transpose()
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }

    async fn update_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        let pool = self.pool.clone();
        let row = DeviceCodeRow::from_domain(&session)?;
        let device_code = session.device_code.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            diesel::update(oauth_device_codes::table.find(device_code))
                .set(&row)
                .execute(&mut conn)
                .map_err(diesel_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }

    async fn delete_device_code(&mut self, device_code: &str) -> Result<(), StoreError> {
        let pool = self.pool.clone();
        let device_code = device_code.to_string();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            diesel::delete(oauth_device_codes::table.find(device_code))
                .execute(&mut conn)
                .map_err(diesel_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }

    async fn consume_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let pool = self.pool.clone();
        let device_code = device_code.to_string();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            conn.transaction(|conn| {
                let row: Option<DeviceCodeRow> = oauth_device_codes::table
                    .find(&device_code)
                    .first(conn)
                    .optional()?;
                let Some(row) = row else {
                    return Ok(None);
                };
                diesel::delete(oauth_device_codes::table.find(&device_code)).execute(conn)?;
                Ok::<_, diesel::result::Error>(Some(row))
            })
            .map_err(diesel_err)?
            .map(DeviceCodeRow::into_domain)
            .transpose()
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }
}

impl OpStore for DieselOpStore {}

#[cfg(test)]
mod tests {
    use super::is_private_memory_url;

    #[test]
    fn bare_memory_filename_is_private() {
        assert!(is_private_memory_url(":memory:"));
    }

    #[test]
    fn empty_url_is_a_private_temporary_database() {
        assert!(is_private_memory_url(""));
        assert!(is_private_memory_url("   "));
    }

    #[test]
    fn file_uri_memory_form_is_private() {
        assert!(is_private_memory_url("file::memory:"));
        assert!(is_private_memory_url("file::memory:?cache=private"));
    }

    #[test]
    fn shared_cache_memory_uri_is_not_private() {
        assert!(!is_private_memory_url("file::memory:?cache=shared"));
    }

    #[test]
    fn a_real_file_path_is_not_private() {
        assert!(!is_private_memory_url("/tmp/authkestra-example.sqlite"));
        assert!(!is_private_memory_url("sqlite://data.db"));
    }
}
