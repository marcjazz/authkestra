use crate::models::{ClientRow, CodeRow, DeviceCodeRow, RefreshTokenRow};
use crate::schema::{oauth_clients, oauth_codes, oauth_device_codes, oauth_refresh_tokens};
use async_trait::async_trait;
use authkestra_engine::store::sqlite::is_private_memory_url;
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

/// Sets SQLite's `busy_timeout` on every connection r2d2 hands out.
///
/// Without it, SQLite's default is to fail a write immediately with
/// "database is locked" the instant it can't grab the single writer lock,
/// rather than waiting for the current writer to finish — turning any two
/// genuinely concurrent writers (e.g. two `consume_code` calls racing on
/// separate pooled connections, exactly the case the compare-and-swap in
/// `AuthorizationCodeStore::consume_code` is meant to resolve cleanly into
/// one winner and one `None`) into a hard error on whichever one loses,
/// instead of the loser simply waiting its turn and then correctly
/// observing the row as already consumed.
#[derive(Debug, Clone, Copy)]
struct SetBusyTimeout;

impl diesel::r2d2::CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SetBusyTimeout {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
        diesel::sql_query("PRAGMA busy_timeout = 5000;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        // WAL mode lets readers proceed without waiting on the single
        // writer (rollback-journal mode's default), which is what actually
        // lets `busy_timeout` matter under real concurrent load rather than
        // every reader also contending for the same lock. A silent no-op
        // for a `:memory:`/temporary database, which SQLite doesn't support
        // WAL for — harmless there since that path is already capped to a
        // single connection anyway (see `connect`).
        diesel::sql_query("PRAGMA journal_mode = WAL;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        Ok(())
    }
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
    /// already serializes writers across connections. See
    /// [`authkestra_engine::store::sqlite::is_private_memory_url`] for
    /// exactly which URL forms count as private — shared with
    /// `authkestra-example-seaorm`'s identical guard, since both examples
    /// need to recognize the same set of SQLite spellings.
    pub fn connect(database_url: &str) -> Result<Self, diesel::r2d2::PoolError> {
        let manager = ConnectionManager::<SqliteConnection>::new(database_url);
        let mut builder = Pool::builder().connection_customizer(Box::new(SetBusyTimeout));
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
            conn.immediate_transaction(|conn| {
                let row: Option<CodeRow> = oauth_codes::table.find(&code).first(conn).optional()?;
                let Some(mut row) = row else {
                    return Ok(None);
                };
                // Single-use, atomically: the `UPDATE ... WHERE used =
                // false` below is the actual compare-and-swap — two
                // concurrent consumers can both reach this point having
                // read `used: false` above, but only the one whose UPDATE
                // affects a row (still `used = false` at write time) may
                // treat the code as consumed. Same shape, and the same
                // reasoning, as authkestra-store-sqlx's own consume_code;
                // the `find` above is a read for the fields to return, not
                // the authority on whether this call wins the race.
                let affected = diesel::update(
                    oauth_codes::table
                        .filter(oauth_codes::code.eq(&code))
                        .filter(oauth_codes::used.eq(false)),
                )
                .set(oauth_codes::used.eq(true))
                .execute(conn)?;
                if affected != 1 {
                    return Ok(None);
                }
                row.used = true;
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
            conn.immediate_transaction(|conn| {
                let row: Option<RefreshTokenRow> = oauth_refresh_tokens::table
                    .find(&token)
                    .first(conn)
                    .optional()?;
                let Some(row) = row else {
                    return Ok(None);
                };
                // The DELETE, not the `find` above, is what's atomic: two
                // concurrent consumers can both read the row present, but
                // only the one whose DELETE actually removes it (checked
                // via the affected-row count) may treat the token as
                // consumed — same compare-and-swap reasoning as
                // `consume_code`.
                let affected =
                    diesel::delete(oauth_refresh_tokens::table.find(&token)).execute(conn)?;
                if affected != 1 {
                    return Ok(None);
                }
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
            conn.immediate_transaction(|conn| {
                let row: Option<DeviceCodeRow> = oauth_device_codes::table
                    .find(&device_code)
                    .first(conn)
                    .optional()?;
                let Some(row) = row else {
                    return Ok(None);
                };
                // Same compare-and-swap reasoning as `consume_token`: the
                // DELETE's affected-row count, not the read above, decides
                // whether this call wins the race against a concurrent
                // consumer of the same device code.
                let affected =
                    diesel::delete(oauth_device_codes::table.find(&device_code)).execute(conn)?;
                if affected != 1 {
                    return Ok(None);
                }
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
