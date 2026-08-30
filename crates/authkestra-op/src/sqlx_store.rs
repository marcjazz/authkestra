use crate::client::{ClientRegistration, ClientStore, TokenEndpointAuthMethod};
use crate::code::{AuthorizationCode, AuthorizationCodeStore};
use crate::device::{DeviceCodeSession, DeviceCodeStore};
use crate::error::OpError;
use crate::refresh::{RefreshToken, RefreshTokenStore};
use async_trait::async_trait;

// Model for database rows, using sqlx::FromRow would require fields to match perfectly.
// Since we are mapping JSON strings back into structs, we will map rows manually.

/// Opinionated, native SQL implementation of OpStore using sqlx.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SqlxOpStore<DB: sqlx::Database> {
    pool: sqlx::Pool<DB>,
}

macro_rules! impl_opstore_sql {
    (
        $backend:path,
        $feature:literal,
        $placeholder_fmt:expr,
        $schema_prefix:literal,
        $migrate_impl:item,
        $consume_code_impl:item,
        $consume_token_impl:item,
        $consume_device_impl:item
    ) => {
        #[cfg(feature = $feature)]
        impl SqlxOpStore<$backend> {
            /// Create a new SqlxOpStore from a sqlx connection pool.
            pub fn new(pool: sqlx::Pool<$backend>) -> Self {
                Self { pool }
            }

            $migrate_impl
        }

        #[cfg(feature = $feature)]
        impl crate::store::OpStore for SqlxOpStore<$backend> {}

        #[cfg(feature = $feature)]
        #[async_trait]
        impl ClientStore for SqlxOpStore<$backend> {
            #[allow(deprecated)] // `require_pkce` (authkestra#273) — still round-tripped for wire/storage compatibility
            async fn find_client(&self, client_id: &str) -> Result<Option<ClientRegistration>, OpError> {
                let query = format!(
                    "SELECT
                        client_id,
                        client_secret_hash,
                        require_pkce,
                        redirect_uris,
                        grant_types,
                        scopes,
                        allowed_audiences,
                        token_endpoint_auth_method,
                        jwks
                    FROM {schema}oauth_clients
                    WHERE client_id = {p1}",
                    schema = $schema_prefix,
                    p1 = $placeholder_fmt(1)
                );

                let row = sqlx::query(&query)
                    .bind(client_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "sqlx find_client error");
                        OpError::Storage
                    })?;

                if let Some(row) = row {
                    use sqlx::Row;
                    let client_id: String = row.try_get("client_id").unwrap_or_default();
                    let client_secret_hash: Option<String> = row.try_get("client_secret_hash").unwrap_or_default();
                    let require_pkce: bool = row.try_get("require_pkce").unwrap_or(true);

                    // SQLite might return these as Strings (from TEXT) while Postgres might return JsonValue (from JSONB)
                    // The safest way across all drivers is to deserialize from whatever String they provide, or handle types cleanly.
                    // For now, we'll assume we can get it as a string or fallback. We will use `try_get` as string.
                    // Since sqlx::types::Json is cross-platform, we can use that!

                    let redirect_uris: sqlx::types::Json<Vec<String>> = row.try_get("redirect_uris").map_err(|_| OpError::Storage)?;
                    let grant_types: sqlx::types::Json<Vec<crate::client::GrantType>> = row.try_get("grant_types").map_err(|_| OpError::Storage)?;
                    let scopes: sqlx::types::Json<Vec<String>> = row.try_get("scopes").map_err(|_| OpError::Storage)?;
                    let allowed_audiences: sqlx::types::Json<Vec<String>> = row.try_get("allowed_audiences").map_err(|_| OpError::Storage)?;
                    // Nullable: a client registered before authkestra#287's
                    // migration added these columns simply has no value in
                    // them yet, same as any other pre-existing row and a
                    // newly-added nullable column.
                    let token_endpoint_auth_method: Option<TokenEndpointAuthMethod> = row
                        .try_get::<Option<sqlx::types::Json<TokenEndpointAuthMethod>>, _>("token_endpoint_auth_method")
                        .ok()
                        .flatten()
                        .map(|j| j.0);
                    let jwks: Option<serde_json::Value> = row
                        .try_get::<Option<sqlx::types::Json<serde_json::Value>>, _>("jwks")
                        .ok()
                        .flatten()
                        .map(|j| j.0);

                    Ok(Some(ClientRegistration {
                        client_id,
                        client_secret_hash,
                        require_pkce,
                        redirect_uris: redirect_uris.0,
                        grant_types: grant_types.0,
                        scopes: scopes.0,
                        allowed_audiences: allowed_audiences.0,
                        token_endpoint_auth_method,
                        jwks,
                    }))
                } else {
                    Ok(None)
                }
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl AuthorizationCodeStore for SqlxOpStore<$backend> {
            async fn store_code(&self, code: AuthorizationCode) -> Result<(), OpError> {
                let query = format!(
                    "INSERT INTO {schema}oauth_codes 
                    (code, client_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, identity, expires_at, used) 
                    VALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6}, {p7}, {p8}, {p9}, {p10})",
                    schema = $schema_prefix,
                    p1 = $placeholder_fmt(1), p2 = $placeholder_fmt(2), p3 = $placeholder_fmt(3),
                    p4 = $placeholder_fmt(4), p5 = $placeholder_fmt(5), p6 = $placeholder_fmt(6),
                    p7 = $placeholder_fmt(7), p8 = $placeholder_fmt(8), p9 = $placeholder_fmt(9),
                    p10 = $placeholder_fmt(10)
                );

                let identity_json = sqlx::types::Json(code.identity);

                sqlx::query(&query)
                    .bind(code.code)
                    .bind(code.client_id)
                    .bind(code.redirect_uri)
                    .bind(code.scope)
                    .bind(code.code_challenge)
                    .bind(code.code_challenge_method)
                    .bind(code.nonce)
                    .bind(identity_json)
                    .bind(code.expires_at)
                    .bind(code.used)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "sqlx store_code error");
                        OpError::Storage
                    })?;
                Ok(())
            }

            $consume_code_impl
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl RefreshTokenStore for SqlxOpStore<$backend> {
            async fn store_token(&self, token: RefreshToken) -> Result<(), OpError> {
                let query = format!(
                    "INSERT INTO {schema}oauth_refresh_tokens
                    (token, client_id, identity, scope, expires_at, jkt)
                    VALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6})",
                    schema = $schema_prefix,
                    p1 = $placeholder_fmt(1), p2 = $placeholder_fmt(2), p3 = $placeholder_fmt(3),
                    p4 = $placeholder_fmt(4), p5 = $placeholder_fmt(5), p6 = $placeholder_fmt(6)
                );

                let identity_json = sqlx::types::Json(token.identity);

                sqlx::query(&query)
                    .bind(token.token)
                    .bind(token.client_id)
                    .bind(identity_json)
                    .bind(token.scope)
                    .bind(token.expires_at)
                    .bind(token.jkt)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "sqlx store_token error");
                        OpError::Storage
                    })?;
                Ok(())
            }

            async fn get_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
                let query = format!(
                    "SELECT token, client_id, identity, scope, expires_at, jkt
                    FROM {schema}oauth_refresh_tokens
                    WHERE token = {p1} AND revoked_at IS NULL AND expires_at > {p2}",
                    schema = $schema_prefix,
                    p1 = $placeholder_fmt(1),
                    p2 = $placeholder_fmt(2)
                );

                let row = sqlx::query(&query)
                    .bind(token)
                    .bind(chrono::Utc::now())
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "sqlx get_token error");
                        OpError::Storage
                    })?;

                if let Some(row) = row {
                    use sqlx::Row;
                    let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|_| OpError::Storage)?;

                    Ok(Some(RefreshToken {
                        token: row.try_get("token").map_err(|_| OpError::Storage)?,
                        client_id: row.try_get("client_id").map_err(|_| OpError::Storage)?,
                        identity: identity.0,
                        scope: row.try_get("scope").map_err(|_| OpError::Storage)?,
                        expires_at: row.try_get("expires_at").map_err(|_| OpError::Storage)?,
                        jkt: row.try_get("jkt").ok(),
                    }))
                } else {
                    Ok(None)
                }
            }

            async fn revoke_token(&self, token: &str) -> Result<(), OpError> {
                let query = format!(
                    "UPDATE {schema}oauth_refresh_tokens SET revoked_at = {p1} WHERE token = {p2}",
                    schema = $schema_prefix,
                    p1 = $placeholder_fmt(1),
                    p2 = $placeholder_fmt(2)
                );

                sqlx::query(&query)
                    .bind(chrono::Utc::now())
                    .bind(token)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "sqlx revoke_token error");
                        OpError::Storage
                    })?;
                Ok(())
            }

            $consume_token_impl
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl DeviceCodeStore for SqlxOpStore<$backend> {
            async fn store_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError> {
                let query = format!(
                    "INSERT INTO {schema}oauth_device_codes 
                    (device_code, user_code, client_id, scope, expires_at, status, last_polled_at) 
                    VALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6}, {p7})",
                    schema = $schema_prefix,
                    p1 = $placeholder_fmt(1), p2 = $placeholder_fmt(2), p3 = $placeholder_fmt(3),
                    p4 = $placeholder_fmt(4), p5 = $placeholder_fmt(5), p6 = $placeholder_fmt(6),
                    p7 = $placeholder_fmt(7)
                );

                let status_json = sqlx::types::Json(session.status);

                sqlx::query(&query)
                    .bind(session.device_code)
                    .bind(session.user_code)
                    .bind(session.client_id)
                    .bind(session.scope)
                    .bind(session.expires_at)
                    .bind(status_json)
                    .bind(session.last_polled_at)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "sqlx store_device_code error");
                        OpError::Storage
                    })?;
                Ok(())
            }

            async fn get_device_code(&self, device_code: &str) -> Result<Option<DeviceCodeSession>, OpError> {
                let query = format!(
                    "SELECT device_code, user_code, client_id, scope, expires_at, status, last_polled_at 
                    FROM {schema}oauth_device_codes 
                    WHERE device_code = {p1}",
                    schema = $schema_prefix,
                    p1 = $placeholder_fmt(1)
                );

                let row = sqlx::query(&query)
                    .bind(device_code)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "sqlx get_device_code error");
                        OpError::Storage
                    })?;

                if let Some(row) = row {
                    use sqlx::Row;
                    let status: sqlx::types::Json<crate::device::DeviceCodeStatus> = row.try_get("status").map_err(|_| OpError::Storage)?;

                    Ok(Some(DeviceCodeSession {
                        device_code: row.try_get("device_code").map_err(|_| OpError::Storage)?,
                        user_code: row.try_get("user_code").map_err(|_| OpError::Storage)?,
                        client_id: row.try_get("client_id").map_err(|_| OpError::Storage)?,
                        scope: row.try_get("scope").map_err(|_| OpError::Storage)?,
                        expires_at: row.try_get("expires_at").map_err(|_| OpError::Storage)?,
                        status: status.0,
                        last_polled_at: row.try_get("last_polled_at").ok(),
                    }))
                } else {
                    Ok(None)
                }
            }

            async fn get_by_user_code(&self, user_code: &str) -> Result<Option<DeviceCodeSession>, OpError> {
                let query = format!(
                    "SELECT device_code, user_code, client_id, scope, expires_at, status, last_polled_at 
                    FROM {schema}oauth_device_codes 
                    WHERE user_code = {p1}",
                    schema = $schema_prefix,
                    p1 = $placeholder_fmt(1)
                );

                let row = sqlx::query(&query)
                    .bind(user_code)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "sqlx get_by_user_code error");
                        OpError::Storage
                    })?;

                if let Some(row) = row {
                    use sqlx::Row;
                    let status: sqlx::types::Json<crate::device::DeviceCodeStatus> = row.try_get("status").map_err(|_| OpError::Storage)?;

                    Ok(Some(DeviceCodeSession {
                        device_code: row.try_get("device_code").map_err(|_| OpError::Storage)?,
                        user_code: row.try_get("user_code").map_err(|_| OpError::Storage)?,
                        client_id: row.try_get("client_id").map_err(|_| OpError::Storage)?,
                        scope: row.try_get("scope").map_err(|_| OpError::Storage)?,
                        expires_at: row.try_get("expires_at").map_err(|_| OpError::Storage)?,
                        status: status.0,
                        last_polled_at: row.try_get("last_polled_at").ok(),
                    }))
                } else {
                    Ok(None)
                }
            }

            async fn update_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError> {
                let query = format!(
                    "UPDATE {schema}oauth_device_codes 
                    SET status = {p1}, last_polled_at = {p2} 
                    WHERE device_code = {p3}",
                    schema = $schema_prefix,
                    p1 = $placeholder_fmt(1), p2 = $placeholder_fmt(2), p3 = $placeholder_fmt(3)
                );

                let status_json = sqlx::types::Json(session.status);

                sqlx::query(&query)
                    .bind(status_json)
                    .bind(session.last_polled_at)
                    .bind(session.device_code)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "sqlx update_device_code error");
                        OpError::Storage
                    })?;
                Ok(())
            }

            async fn delete_device_code(&self, device_code: &str) -> Result<(), OpError> {
                let query = format!(
                    "DELETE FROM {schema}oauth_device_codes WHERE device_code = {p1}",
                    schema = $schema_prefix,
                    p1 = $placeholder_fmt(1)
                );

                sqlx::query(&query)
                    .bind(device_code)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "sqlx delete_device_code error");
                        OpError::Storage
                    })?;
                Ok(())
            }

            $consume_device_impl
        }
    };
}

// Generate the Postgres implementation
impl_opstore_sql! {
    sqlx::Postgres,
    "sqlx-postgres",
    |i| format!("${}", i),
    "authkestra.",
    /// Run necessary database migrations to set up schema and tables.
    ///
    /// Backed by `sqlx::migrate!` (authkestra#287) — versioned, checksummed
    /// `.sql` files under `migrations/postgres/`, tracked in this
    /// database's own `_sqlx_migrations` table so each one runs exactly
    /// once, ever. That guarantee is what makes it safe to *add* a column
    /// to an existing deployment's table (migration 2) as well as create
    /// the schema fresh (migration 1) — the old `CREATE TABLE IF NOT
    /// EXISTS`-only approach this replaces had no such guarantee, so it
    /// could only ever create tables, never evolve them.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::migrate!("./migrations/postgres").run(&self.pool).await?;
        Ok(())
    },
    // consume_code (Postgres specific)
    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>, OpError> {
        let query = "UPDATE authkestra.oauth_codes SET used = TRUE WHERE code = $1 AND used = FALSE RETURNING *";
        let row = sqlx::query(query)
            .bind(code)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| OpError::Storage)?;

        if let Some(row) = row {
            use sqlx::Row;
            let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|_| OpError::Storage)?;
            Ok(Some(AuthorizationCode {
                code: row.try_get("code").unwrap_or_default(),
                client_id: row.try_get("client_id").unwrap_or_default(),
                redirect_uri: row.try_get("redirect_uri").unwrap_or_default(),
                scope: row.try_get("scope").unwrap_or_default(),
                code_challenge: row.try_get("code_challenge").ok(),
                code_challenge_method: row.try_get("code_challenge_method").ok(),
                nonce: row.try_get("nonce").ok(),
                identity: identity.0,
                expires_at: row.try_get("expires_at").map_err(|_| OpError::Storage)?,
                used: row.try_get("used").unwrap_or(true),
            }))
        } else {
            Ok(None)
        }
    },
    // consume_token (Postgres specific)
    async fn consume_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
        let query = "DELETE FROM authkestra.oauth_refresh_tokens WHERE token = $1 AND revoked_at IS NULL RETURNING *";
        let row = sqlx::query(query)
            .bind(token)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| OpError::Storage)?;

        if let Some(row) = row {
            use sqlx::Row;
            let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|_| OpError::Storage)?;
            Ok(Some(RefreshToken {
                token: row.try_get("token").unwrap_or_default(),
                client_id: row.try_get("client_id").unwrap_or_default(),
                identity: identity.0,
                scope: row.try_get("scope").unwrap_or_default(),
                expires_at: row.try_get("expires_at").map_err(|_| OpError::Storage)?,
                jkt: row.try_get("jkt").ok(),
            }))
        } else {
            Ok(None)
        }
    },
    // consume_device_impl (Postgres specific)
    async fn consume_device_code(&self, device_code: &str) -> Result<Option<DeviceCodeSession>, OpError> {
        let query = "DELETE FROM authkestra.oauth_device_codes WHERE device_code = $1 RETURNING *";
        let row = sqlx::query(query)
            .bind(device_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| OpError::Storage)?;

        if let Some(row) = row {
            use sqlx::Row;
            let status: sqlx::types::Json<crate::device::DeviceCodeStatus> = row.try_get("status").map_err(|_| OpError::Storage)?;
            Ok(Some(DeviceCodeSession {
                device_code: row.try_get("device_code").unwrap_or_default(),
                user_code: row.try_get("user_code").unwrap_or_default(),
                client_id: row.try_get("client_id").unwrap_or_default(),
                scope: row.try_get("scope").unwrap_or_default(),
                status: status.0,
                expires_at: row.try_get("expires_at").map_err(|_| OpError::Storage)?,
                last_polled_at: row.try_get("last_polled_at").ok(),
            }))
        } else {
            Ok(None)
        }
    }
}

// Generate the SQLite implementation
impl_opstore_sql! {
    sqlx::Sqlite,
    "sqlx-sqlite",
    |_| "?".to_string(),
    "authkestra_",
    /// Run necessary database migrations to set up schema and tables.
    ///
    /// See the Postgres impl's identical doc comment: backed by
    /// `sqlx::migrate!` (authkestra#287) against `migrations/sqlite/`.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::migrate!("./migrations/sqlite").run(&self.pool).await?;
        Ok(())
    },
    // consume_code (SQLite specific)
    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>, OpError> {
        let query = "UPDATE authkestra_oauth_codes SET used = TRUE WHERE code = ? AND used = FALSE RETURNING *";
        let row = sqlx::query(query)
            .bind(code)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| OpError::Storage)?;

        if let Some(row) = row {
            use sqlx::Row;
            let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|_| OpError::Storage)?;
            Ok(Some(AuthorizationCode {
                code: row.try_get("code").unwrap_or_default(),
                client_id: row.try_get("client_id").unwrap_or_default(),
                redirect_uri: row.try_get("redirect_uri").unwrap_or_default(),
                scope: row.try_get("scope").unwrap_or_default(),
                code_challenge: row.try_get("code_challenge").ok(),
                code_challenge_method: row.try_get("code_challenge_method").ok(),
                nonce: row.try_get("nonce").ok(),
                identity: identity.0,
                expires_at: row.try_get("expires_at").map_err(|_| OpError::Storage)?,
                used: row.try_get("used").unwrap_or(true),
            }))
        } else {
            Ok(None)
        }
    },
    // consume_token (SQLite specific)
    async fn consume_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
        let query = "DELETE FROM authkestra_oauth_refresh_tokens WHERE token = ? AND revoked_at IS NULL RETURNING *";
        let row = sqlx::query(query)
            .bind(token)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| OpError::Storage)?;

        if let Some(row) = row {
            use sqlx::Row;
            let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|_| OpError::Storage)?;
            Ok(Some(RefreshToken {
                token: row.try_get("token").unwrap_or_default(),
                client_id: row.try_get("client_id").unwrap_or_default(),
                identity: identity.0,
                scope: row.try_get("scope").unwrap_or_default(),
                expires_at: row.try_get("expires_at").map_err(|_| OpError::Storage)?,
                jkt: row.try_get("jkt").ok(),
            }))
        } else {
            Ok(None)
        }
    },
    // consume_device_impl (SQLite specific)
    async fn consume_device_code(&self, device_code: &str) -> Result<Option<DeviceCodeSession>, OpError> {
        let query = "DELETE FROM authkestra_oauth_device_codes WHERE device_code = ? RETURNING *";
        let row = sqlx::query(query)
            .bind(device_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| OpError::Storage)?;

        if let Some(row) = row {
            use sqlx::Row;
            let status: sqlx::types::Json<crate::device::DeviceCodeStatus> = row.try_get("status").map_err(|_| OpError::Storage)?;
            Ok(Some(DeviceCodeSession {
                device_code: row.try_get("device_code").unwrap_or_default(),
                user_code: row.try_get("user_code").unwrap_or_default(),
                client_id: row.try_get("client_id").unwrap_or_default(),
                scope: row.try_get("scope").unwrap_or_default(),
                status: status.0,
                expires_at: row.try_get("expires_at").map_err(|_| OpError::Storage)?,
                last_polled_at: row.try_get("last_polled_at").ok(),
            }))
        } else {
            Ok(None)
        }
    }
}

// Generate the MySQL implementation
impl_opstore_sql! {
    sqlx::MySql,
    "sqlx-mysql",
    |_| "?".to_string(),
    "authkestra_",
    /// Run necessary database migrations to set up schema and tables.
    ///
    /// See the Postgres impl's identical doc comment: backed by
    /// `sqlx::migrate!` (authkestra#287) against `migrations/mysql/`.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::migrate!("./migrations/mysql").run(&self.pool).await?;
        Ok(())
    },
    // consume_code (MySQL specific - needs transaction and FOR UPDATE since no RETURNING)
    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>, OpError> {
        let mut tx = self.pool.begin().await.map_err(|_| OpError::Storage)?;

        let select_query = "SELECT * FROM authkestra_oauth_codes WHERE code = ? AND used = FALSE FOR UPDATE";
        let row = sqlx::query(select_query)
            .bind(code)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| OpError::Storage)?;

        if let Some(row) = row {
            let update_query = "UPDATE authkestra_oauth_codes SET used = TRUE WHERE code = ?";
            sqlx::query(update_query)
                .bind(code)
                .execute(&mut *tx)
                .await
                .map_err(|_| OpError::Storage)?;

            tx.commit().await.map_err(|_| OpError::Storage)?;

            use sqlx::Row;
            let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|_| OpError::Storage)?;
            Ok(Some(AuthorizationCode {
                code: row.try_get("code").unwrap_or_default(),
                client_id: row.try_get("client_id").unwrap_or_default(),
                redirect_uri: row.try_get("redirect_uri").unwrap_or_default(),
                scope: row.try_get("scope").unwrap_or_default(),
                code_challenge: row.try_get("code_challenge").ok(),
                code_challenge_method: row.try_get("code_challenge_method").ok(),
                nonce: row.try_get("nonce").ok(),
                identity: identity.0,
                expires_at: row.try_get("expires_at").map_err(|_| OpError::Storage)?,
                used: row.try_get("used").unwrap_or(true),
            }))
        } else {
            tx.rollback().await.map_err(|_| OpError::Storage)?;
            Ok(None)
        }
    },
    // consume_token (MySQL specific)
    async fn consume_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
        let mut tx = self.pool.begin().await.map_err(|_| OpError::Storage)?;

        let select_query = "SELECT * FROM authkestra_oauth_refresh_tokens WHERE token = ? AND revoked_at IS NULL FOR UPDATE";
        let row = sqlx::query(select_query)
            .bind(token)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| OpError::Storage)?;

        if let Some(row) = row {
            let delete_query = "DELETE FROM authkestra_oauth_refresh_tokens WHERE token = ?";
            sqlx::query(delete_query)
                .bind(token)
                .execute(&mut *tx)
                .await
                .map_err(|_| OpError::Storage)?;

            tx.commit().await.map_err(|_| OpError::Storage)?;

            use sqlx::Row;
            let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|_| OpError::Storage)?;
            Ok(Some(RefreshToken {
                token: row.try_get("token").unwrap_or_default(),
                client_id: row.try_get("client_id").unwrap_or_default(),
                identity: identity.0,
                scope: row.try_get("scope").unwrap_or_default(),
                expires_at: row.try_get("expires_at").map_err(|_| OpError::Storage)?,
                jkt: row.try_get("jkt").ok(),
            }))
        } else {
            tx.rollback().await.map_err(|_| OpError::Storage)?;
            Ok(None)
        }
    },
    // consume_device_impl (MySQL specific)
    async fn consume_device_code(&self, device_code: &str) -> Result<Option<DeviceCodeSession>, OpError> {
        let mut tx = self.pool.begin().await.map_err(|_| OpError::Storage)?;

        let select_query = "SELECT * FROM authkestra_oauth_device_codes WHERE device_code = ? FOR UPDATE";
        let row = sqlx::query(select_query)
            .bind(device_code)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| OpError::Storage)?;

        if let Some(row) = row {
            let delete_query = "DELETE FROM authkestra_oauth_device_codes WHERE device_code = ?";
            sqlx::query(delete_query)
                .bind(device_code)
                .execute(&mut *tx)
                .await
                .map_err(|_| OpError::Storage)?;

            tx.commit().await.map_err(|_| OpError::Storage)?;

            use sqlx::Row;
            let status: sqlx::types::Json<crate::device::DeviceCodeStatus> = row.try_get("status").map_err(|_| OpError::Storage)?;
            Ok(Some(DeviceCodeSession {
                device_code: row.try_get("device_code").unwrap_or_default(),
                user_code: row.try_get("user_code").unwrap_or_default(),
                client_id: row.try_get("client_id").unwrap_or_default(),
                scope: row.try_get("scope").unwrap_or_default(),
                status: status.0,
                expires_at: row.try_get("expires_at").map_err(|_| OpError::Storage)?,
                last_polled_at: row.try_get("last_polled_at").ok(),
            }))
        } else {
            tx.rollback().await.map_err(|_| OpError::Storage)?;
            Ok(None)
        }
    }
}

#[cfg(all(test, feature = "sqlx-postgres"))]
mod postgres_tests {
    use super::*;
    use crate::code::{AuthorizationCode, AuthorizationCodeStore};
    use chrono::{Duration, Utc};
    use sqlx::postgres::PgPoolOptions;
    use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    async fn setup_db() -> (SqlxOpStore<sqlx::Postgres>, ContainerAsync<Postgres>) {
        let container = Postgres::default()
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_USER", "postgres")
            .with_env_var("POSTGRES_DB", "postgres")
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();

        let store = SqlxOpStore::<sqlx::Postgres>::new(pool);
        store.migrate().await.unwrap();

        (store, container)
    }

    #[tokio::test]
    async fn test_postgres_authorization_code_cascading_delete() {
        let (store, _c) = setup_db().await;

        // Manually insert a client
        sqlx::query(
            "INSERT INTO authkestra.oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind("test_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode {
            code: "test_code_123".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scope: "openid".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            identity: authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            expires_at: Utc::now() + Duration::try_minutes(10).unwrap(),
            used: false,
        };

        store.store_code(code.clone()).await.unwrap();

        // Consume it to verify it exists
        let consumed = store.consume_code("test_code_123").await.unwrap();
        assert!(consumed.is_some());
        assert_eq!(consumed.unwrap().client_id, "test_client");

        // Test cascade delete
        // Re-insert the code
        let code2 = AuthorizationCode {
            code: "test_code_456".to_string(),
            ..code
        };
        store.store_code(code2.clone()).await.unwrap();

        // Delete the client
        sqlx::query("DELETE FROM authkestra.oauth_clients WHERE client_id = 'test_client'")
            .execute(&store.pool)
            .await
            .unwrap();

        // Ensure the code is also deleted due to CASCADE
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM authkestra.oauth_codes WHERE code = 'test_code_456'",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();

        assert_eq!(count.0, 0);
    }

    #[tokio::test]
    async fn test_postgres_concurrency() {
        let (store, _c) = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra.oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind("concurrency_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode {
            code: "concurrent_code".to_string(),
            client_id: "concurrency_client".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scope: "openid".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            identity: authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            expires_at: Utc::now() + Duration::try_minutes(10).unwrap(),
            used: false,
        };
        store.store_code(code.clone()).await.unwrap();

        let mut handles = vec![];
        let store_arc = std::sync::Arc::new(store);

        // Spawn 10 simultaneous consumers
        for _ in 0..10 {
            let s = store_arc.clone();
            handles.push(tokio::spawn(async move {
                s.consume_code("concurrent_code").await.unwrap()
            }));
        }

        let mut successes = 0;
        let mut failures = 0;
        for h in handles {
            let res = h.await.unwrap();
            if res.is_some() {
                successes += 1;
            } else {
                failures += 1;
            }
        }

        assert_eq!(successes, 1);
        assert_eq!(failures, 9);
    }

    fn test_identity() -> authkestra_engine::auth::state::Identity {
        authkestra_engine::auth::state::Identity {
            provider_id: "local".to_string(),
            external_id: "user_1".to_string(),
            email: None,
            username: None,
            attributes: std::collections::HashMap::new(),
        }
    }

    /// authkestra#287: `jkt` (RFC 9449 DPoP refresh-token continuity) and
    /// `token_endpoint_auth_method`/`jwks` (RFC 7523 private_key_jwt) must
    /// actually round-trip through a fresh install, not just exist as
    /// columns nothing reads or writes.
    #[tokio::test]
    async fn test_postgres_fresh_install_persists_jkt_and_client_auth_fields() {
        let (store, _c) = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra.oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences, token_endpoint_auth_method, jwks)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        )
        .bind("auth287_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .bind(sqlx::types::Json(TokenEndpointAuthMethod::PrivateKeyJwt))
        .bind(sqlx::types::Json(serde_json::json!({"keys": []})))
        .execute(&store.pool)
        .await
        .unwrap();

        let client = store
            .find_client("auth287_client")
            .await
            .unwrap()
            .expect("client must be found");
        assert_eq!(
            client.token_endpoint_auth_method,
            Some(TokenEndpointAuthMethod::PrivateKeyJwt)
        );
        assert_eq!(client.jwks, Some(serde_json::json!({"keys": []})));

        let rt = RefreshToken {
            token: "rt-287".to_string(),
            client_id: "auth287_client".to_string(),
            identity: test_identity(),
            scope: "openid".to_string(),
            expires_at: Utc::now() + Duration::try_days(1).unwrap(),
            jkt: Some("expected-jkt-thumbprint".to_string()),
        };
        store.store_token(rt).await.unwrap();

        let fetched = store
            .get_token("rt-287")
            .await
            .unwrap()
            .expect("token must be found");
        assert_eq!(fetched.jkt, Some("expected-jkt-thumbprint".to_string()));

        let consumed = store
            .consume_token("rt-287")
            .await
            .unwrap()
            .expect("token must be consumable");
        assert_eq!(consumed.jkt, Some("expected-jkt-thumbprint".to_string()));
    }

    /// The actual point of authkestra#287: a deployment that already ran
    /// the *old* `migrate()` (before `jkt`/`token_endpoint_auth_method`/
    /// `jwks` existed) must upgrade safely when it starts running the new
    /// code — no "table already exists" failure, no data loss for
    /// pre-existing rows, and the new columns must actually work
    /// afterwards. This is the scenario `CREATE TABLE IF NOT EXISTS`
    /// alone could never handle.
    #[tokio::test]
    async fn test_postgres_migration_upgrades_a_pre_existing_deployment_without_the_new_columns() {
        let container = Postgres::default()
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_USER", "postgres")
            .with_env_var("POSTGRES_DB", "postgres")
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();

        // The pre-#287 schema, created directly — bypassing
        // `store.migrate()` entirely, exactly like an existing deployment
        // that ran the old code would already have. Uses the raw simple
        // query protocol (`Executor::execute`, same as the old `migrate()`
        // this replaces used), since multiple `;`-separated statements
        // aren't accepted by `sqlx::query(...).execute(...)`'s prepared-
        // statement protocol.
        use sqlx::Executor;
        pool.execute(
            "CREATE SCHEMA IF NOT EXISTS authkestra;
             CREATE TABLE authkestra.oauth_clients (
                client_id VARCHAR(255) PRIMARY KEY,
                client_secret_hash VARCHAR(255),
                require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
                redirect_uris JSONB NOT NULL,
                grant_types JSONB NOT NULL,
                scopes JSONB NOT NULL,
                allowed_audiences JSONB NOT NULL
            );
            CREATE TABLE authkestra.oauth_refresh_tokens (
                token VARCHAR(255) PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL REFERENCES authkestra.oauth_clients(client_id) ON DELETE CASCADE,
                identity JSONB NOT NULL,
                scope TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                revoked_at TIMESTAMPTZ
            );",
        )
        .await
        .unwrap();

        // A client registered under the old schema, before this
        // deployment ever knew about these fields.
        sqlx::query(
            "INSERT INTO authkestra.oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences)
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind("pre_existing_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&pool)
        .await
        .unwrap();

        let store = SqlxOpStore::<sqlx::Postgres>::new(pool);

        store
            .migrate()
            .await
            .expect("migrating an existing pre-authkestra#287 database must succeed");

        let client = store
            .find_client("pre_existing_client")
            .await
            .unwrap()
            .expect("the pre-existing client must survive the migration");
        assert_eq!(client.token_endpoint_auth_method, None);
        assert_eq!(client.jwks, None);

        let rt = RefreshToken {
            token: "rt-upgrade".to_string(),
            client_id: "pre_existing_client".to_string(),
            identity: test_identity(),
            scope: "openid".to_string(),
            expires_at: Utc::now() + Duration::try_days(1).unwrap(),
            jkt: Some("post-upgrade-jkt".to_string()),
        };
        store
            .store_token(rt)
            .await
            .expect("storing a DPoP-bound refresh token must work after the upgrade");
        let fetched = store
            .get_token("rt-upgrade")
            .await
            .unwrap()
            .expect("token must be found");
        assert_eq!(fetched.jkt, Some("post-upgrade-jkt".to_string()));
    }
}

#[cfg(all(test, feature = "sqlx-sqlite"))]
mod sqlite_tests {
    use super::*;
    use crate::code::{AuthorizationCode, AuthorizationCodeStore};
    use chrono::{Duration, Utc};
    use sqlx::sqlite::SqlitePoolOptions;

    async fn setup_db() -> SqlxOpStore<sqlx::Sqlite> {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let store = SqlxOpStore::<sqlx::Sqlite>::new(pool);
        store.migrate().await.unwrap();

        // Enable foreign keys in SQLite for this connection
        sqlx::query("PRAGMA foreign_keys = ON;")
            .execute(&store.pool)
            .await
            .unwrap();

        store
    }

    #[tokio::test]
    async fn test_sqlite_cascading_delete() {
        let store = setup_db().await;

        // Manually insert a client
        sqlx::query(
            "INSERT INTO authkestra_oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("test_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode {
            code: "test_code_123".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scope: "openid".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            identity: authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            expires_at: Utc::now() + Duration::try_minutes(10).unwrap(),
            used: false,
        };

        store.store_code(code.clone()).await.unwrap();

        // Consume it to verify it exists
        let consumed = store.consume_code("test_code_123").await.unwrap();
        assert!(consumed.is_some());
        assert_eq!(consumed.unwrap().client_id, "test_client");

        // Test cascade delete
        let code2 = AuthorizationCode {
            code: "test_code_456".to_string(),
            ..code
        };
        store.store_code(code2.clone()).await.unwrap();

        // Delete the client
        sqlx::query("DELETE FROM authkestra_oauth_clients WHERE client_id = 'test_client'")
            .execute(&store.pool)
            .await
            .unwrap();

        // Ensure the code is also deleted due to CASCADE
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM authkestra_oauth_codes WHERE code = 'test_code_456'",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();

        assert_eq!(count.0, 0);
    }

    #[tokio::test]
    async fn test_sqlite_concurrency() {
        let store = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra_oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("concurrency_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode {
            code: "concurrent_code".to_string(),
            client_id: "concurrency_client".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scope: "openid".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            identity: authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            expires_at: Utc::now() + Duration::try_minutes(10).unwrap(),
            used: false,
        };
        store.store_code(code.clone()).await.unwrap();

        let mut handles = vec![];
        let store_arc = std::sync::Arc::new(store);

        // Spawn 10 simultaneous consumers
        for _ in 0..10 {
            let s = store_arc.clone();
            handles.push(tokio::spawn(async move {
                s.consume_code("concurrent_code").await.unwrap()
            }));
        }

        let mut successes = 0;
        let mut failures = 0;
        for h in handles {
            let res = h.await.unwrap();
            if res.is_some() {
                successes += 1;
            } else {
                failures += 1;
            }
        }

        assert_eq!(successes, 1);
        assert_eq!(failures, 9);
    }

    fn test_identity() -> authkestra_engine::auth::state::Identity {
        authkestra_engine::auth::state::Identity {
            provider_id: "local".to_string(),
            external_id: "user_1".to_string(),
            email: None,
            username: None,
            attributes: std::collections::HashMap::new(),
        }
    }

    /// authkestra#287: `jkt` (RFC 9449 DPoP refresh-token continuity) and
    /// `token_endpoint_auth_method`/`jwks` (RFC 7523 private_key_jwt) must
    /// actually round-trip through a fresh install, not just exist as
    /// columns nothing reads or writes.
    #[tokio::test]
    async fn test_sqlite_fresh_install_persists_jkt_and_client_auth_fields() {
        let store = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra_oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences, token_endpoint_auth_method, jwks)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("auth287_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .bind(sqlx::types::Json(TokenEndpointAuthMethod::PrivateKeyJwt))
        .bind(sqlx::types::Json(serde_json::json!({"keys": []})))
        .execute(&store.pool)
        .await
        .unwrap();

        let client = store
            .find_client("auth287_client")
            .await
            .unwrap()
            .expect("client must be found");
        assert_eq!(
            client.token_endpoint_auth_method,
            Some(TokenEndpointAuthMethod::PrivateKeyJwt)
        );
        assert_eq!(client.jwks, Some(serde_json::json!({"keys": []})));

        let rt = RefreshToken {
            token: "rt-287".to_string(),
            client_id: "auth287_client".to_string(),
            identity: test_identity(),
            scope: "openid".to_string(),
            expires_at: Utc::now() + Duration::try_days(1).unwrap(),
            jkt: Some("expected-jkt-thumbprint".to_string()),
        };
        store.store_token(rt).await.unwrap();

        let fetched = store
            .get_token("rt-287")
            .await
            .unwrap()
            .expect("token must be found");
        assert_eq!(fetched.jkt, Some("expected-jkt-thumbprint".to_string()));

        let consumed = store
            .consume_token("rt-287")
            .await
            .unwrap()
            .expect("token must be consumable");
        assert_eq!(consumed.jkt, Some("expected-jkt-thumbprint".to_string()));
    }

    /// The actual point of authkestra#287: a deployment that already ran
    /// the *old* `migrate()` (before `jkt`/`token_endpoint_auth_method`/
    /// `jwks` existed) must upgrade safely when it starts running the new
    /// code — no "table already exists" failure, no data loss for
    /// pre-existing rows, and the new columns must actually work
    /// afterwards. This is the scenario `CREATE TABLE IF NOT EXISTS`
    /// alone could never handle.
    #[tokio::test]
    async fn test_sqlite_migration_upgrades_a_pre_existing_deployment_without_the_new_columns() {
        // The pre-#287 schema, created directly — bypassing
        // `store.migrate()` entirely, exactly like an existing deployment
        // that ran the old code would already have.
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE authkestra_oauth_clients (
                client_id TEXT PRIMARY KEY,
                client_secret_hash TEXT,
                require_pkce BOOLEAN NOT NULL DEFAULT 1,
                redirect_uris TEXT NOT NULL,
                grant_types TEXT NOT NULL,
                scopes TEXT NOT NULL,
                allowed_audiences TEXT NOT NULL
            );",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE authkestra_oauth_refresh_tokens (
                token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE,
                identity TEXT NOT NULL,
                scope TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                revoked_at DATETIME
            );",
        )
        .execute(&pool)
        .await
        .unwrap();

        // A client registered under the old schema, before this
        // deployment ever knew about these fields.
        sqlx::query(
            "INSERT INTO authkestra_oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("pre_existing_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&pool)
        .await
        .unwrap();

        let store = SqlxOpStore::<sqlx::Sqlite>::new(pool);

        store
            .migrate()
            .await
            .expect("migrating an existing pre-authkestra#287 database must succeed");

        // The pre-existing client survives untouched — the new fields are
        // simply absent, not an error.
        let client = store
            .find_client("pre_existing_client")
            .await
            .unwrap()
            .expect("the pre-existing client must survive the migration");
        assert_eq!(client.token_endpoint_auth_method, None);
        assert_eq!(client.jwks, None);

        // And the new columns are now genuinely usable.
        let rt = RefreshToken {
            token: "rt-upgrade".to_string(),
            client_id: "pre_existing_client".to_string(),
            identity: test_identity(),
            scope: "openid".to_string(),
            expires_at: Utc::now() + Duration::try_days(1).unwrap(),
            jkt: Some("post-upgrade-jkt".to_string()),
        };
        store
            .store_token(rt)
            .await
            .expect("storing a DPoP-bound refresh token must work after the upgrade");
        let fetched = store
            .get_token("rt-upgrade")
            .await
            .unwrap()
            .expect("token must be found");
        assert_eq!(fetched.jkt, Some("post-upgrade-jkt".to_string()));
    }
}

#[cfg(all(test, feature = "sqlx-mysql"))]
mod mysql_tests {
    use super::*;
    use crate::code::{AuthorizationCode, AuthorizationCodeStore};
    use chrono::{Duration, Utc};
    use sqlx::mysql::MySqlPoolOptions;
    use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
    use testcontainers_modules::mysql::Mysql;

    async fn setup_db() -> (SqlxOpStore<sqlx::MySql>, ContainerAsync<Mysql>) {
        let container = Mysql::default()
            .with_env_var("MYSQL_ROOT_PASSWORD", "mysql")
            .with_env_var("MYSQL_DATABASE", "mysql")
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(3306).await.unwrap();
        let url = format!("mysql://root:mysql@127.0.0.1:{port}/mysql");

        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();

        let store = SqlxOpStore::<sqlx::MySql>::new(pool);
        store.migrate().await.unwrap();

        (store, container)
    }

    #[tokio::test]
    async fn test_mysql_cascading_delete() {
        let (store, _c) = setup_db().await;

        // Manually insert a client
        sqlx::query(
            "INSERT INTO authkestra_oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("test_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode {
            code: "test_code_123".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scope: "openid".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            identity: authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            expires_at: Utc::now() + Duration::try_minutes(10).unwrap(),
            used: false,
        };

        store.store_code(code.clone()).await.unwrap();

        // Consume it to verify it exists
        let consumed = store.consume_code("test_code_123").await.unwrap();
        assert!(consumed.is_some());
        assert_eq!(consumed.unwrap().client_id, "test_client");

        // Test cascade delete
        let code2 = AuthorizationCode {
            code: "test_code_456".to_string(),
            ..code
        };
        store.store_code(code2.clone()).await.unwrap();

        // Delete the client
        sqlx::query("DELETE FROM authkestra_oauth_clients WHERE client_id = 'test_client'")
            .execute(&store.pool)
            .await
            .unwrap();

        // Ensure the code is also deleted due to CASCADE
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM authkestra_oauth_codes WHERE code = 'test_code_456'",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();

        assert_eq!(count.0, 0);
    }

    #[tokio::test]
    async fn test_mysql_concurrency() {
        let (store, _c) = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra_oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("concurrency_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode {
            code: "concurrent_code".to_string(),
            client_id: "concurrency_client".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scope: "openid".to_string(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            identity: authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            expires_at: Utc::now() + Duration::try_minutes(10).unwrap(),
            used: false,
        };
        store.store_code(code.clone()).await.unwrap();

        let mut handles = vec![];
        let store_arc = std::sync::Arc::new(store);

        // Spawn 10 simultaneous consumers
        for _ in 0..10 {
            let s = store_arc.clone();
            handles.push(tokio::spawn(async move {
                s.consume_code("concurrent_code").await.unwrap()
            }));
        }

        let mut successes = 0;
        let mut failures = 0;
        for h in handles {
            let res = h.await.unwrap();
            if res.is_some() {
                successes += 1;
            } else {
                failures += 1;
            }
        }

        assert_eq!(successes, 1);
        assert_eq!(failures, 9);
    }

    fn test_identity() -> authkestra_engine::auth::state::Identity {
        authkestra_engine::auth::state::Identity {
            provider_id: "local".to_string(),
            external_id: "user_1".to_string(),
            email: None,
            username: None,
            attributes: std::collections::HashMap::new(),
        }
    }

    /// authkestra#287: `jkt` (RFC 9449 DPoP refresh-token continuity) and
    /// `token_endpoint_auth_method`/`jwks` (RFC 7523 private_key_jwt) must
    /// actually round-trip through a fresh install, not just exist as
    /// columns nothing reads or writes.
    #[tokio::test]
    async fn test_mysql_fresh_install_persists_jkt_and_client_auth_fields() {
        let (store, _c) = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra_oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences, token_endpoint_auth_method, jwks)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("auth287_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .bind(sqlx::types::Json(TokenEndpointAuthMethod::PrivateKeyJwt))
        .bind(sqlx::types::Json(serde_json::json!({"keys": []})))
        .execute(&store.pool)
        .await
        .unwrap();

        let client = store
            .find_client("auth287_client")
            .await
            .unwrap()
            .expect("client must be found");
        assert_eq!(
            client.token_endpoint_auth_method,
            Some(TokenEndpointAuthMethod::PrivateKeyJwt)
        );
        assert_eq!(client.jwks, Some(serde_json::json!({"keys": []})));

        let rt = RefreshToken {
            token: "rt-287".to_string(),
            client_id: "auth287_client".to_string(),
            identity: test_identity(),
            scope: "openid".to_string(),
            expires_at: Utc::now() + Duration::try_days(1).unwrap(),
            jkt: Some("expected-jkt-thumbprint".to_string()),
        };
        store.store_token(rt).await.unwrap();

        let fetched = store
            .get_token("rt-287")
            .await
            .unwrap()
            .expect("token must be found");
        assert_eq!(fetched.jkt, Some("expected-jkt-thumbprint".to_string()));

        let consumed = store
            .consume_token("rt-287")
            .await
            .unwrap()
            .expect("token must be consumable");
        assert_eq!(consumed.jkt, Some("expected-jkt-thumbprint".to_string()));
    }

    /// The actual point of authkestra#287: a deployment that already ran
    /// the *old* `migrate()` (before `jkt`/`token_endpoint_auth_method`/
    /// `jwks` existed) must upgrade safely when it starts running the new
    /// code — no "table already exists" failure, no data loss for
    /// pre-existing rows, and the new columns must actually work
    /// afterwards. This is the scenario `CREATE TABLE IF NOT EXISTS`
    /// alone could never handle.
    #[tokio::test]
    async fn test_mysql_migration_upgrades_a_pre_existing_deployment_without_the_new_columns() {
        let container = Mysql::default()
            .with_env_var("MYSQL_ROOT_PASSWORD", "mysql")
            .with_env_var("MYSQL_DATABASE", "mysql")
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(3306).await.unwrap();
        let url = format!("mysql://root:mysql@127.0.0.1:{port}/mysql");
        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();

        // The pre-#287 schema, created directly — bypassing
        // `store.migrate()` entirely, exactly like an existing deployment
        // that ran the old code would already have. Each statement is its
        // own `sqlx::query` call: MySQL's protocol (like Postgres's)
        // doesn't accept multiple `;`-separated statements through a
        // single prepared-statement execution.
        sqlx::query(
            "CREATE TABLE authkestra_oauth_clients (
                client_id VARCHAR(255) PRIMARY KEY,
                client_secret_hash VARCHAR(255),
                require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
                redirect_uris JSON NOT NULL,
                grant_types JSON NOT NULL,
                scopes JSON NOT NULL,
                allowed_audiences JSON NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE authkestra_oauth_refresh_tokens (
                token VARCHAR(255) PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL,
                identity JSON NOT NULL,
                scope TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                revoked_at DATETIME,
                FOREIGN KEY (client_id) REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        // A client registered under the old schema, before this
        // deployment ever knew about these fields.
        sqlx::query(
            "INSERT INTO authkestra_oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("pre_existing_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&pool)
        .await
        .unwrap();

        let store = SqlxOpStore::<sqlx::MySql>::new(pool);

        store
            .migrate()
            .await
            .expect("migrating an existing pre-authkestra#287 database must succeed");

        let client = store
            .find_client("pre_existing_client")
            .await
            .unwrap()
            .expect("the pre-existing client must survive the migration");
        assert_eq!(client.token_endpoint_auth_method, None);
        assert_eq!(client.jwks, None);

        let rt = RefreshToken {
            token: "rt-upgrade".to_string(),
            client_id: "pre_existing_client".to_string(),
            identity: test_identity(),
            scope: "openid".to_string(),
            expires_at: Utc::now() + Duration::try_days(1).unwrap(),
            jkt: Some("post-upgrade-jkt".to_string()),
        };
        store
            .store_token(rt)
            .await
            .expect("storing a DPoP-bound refresh token must work after the upgrade");
        let fetched = store
            .get_token("rt-upgrade")
            .await
            .unwrap()
            .expect("token must be found");
        assert_eq!(fetched.jkt, Some("post-upgrade-jkt".to_string()));
    }
}
