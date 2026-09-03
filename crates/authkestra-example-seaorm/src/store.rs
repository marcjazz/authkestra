use crate::entities::{client, code, device_code, refresh_token};
use async_trait::async_trait;
use authkestra_engine::store::sqlite_url::is_private_memory_url;
use authkestra_engine::store::StoreError;
use authkestra_op::client::{ClientRegistration, ClientStore, GrantType, TokenEndpointAuthMethod};
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStatus, DeviceCodeStore};
use authkestra_op::refresh::{RefreshToken, RefreshTokenStore};
use authkestra_op::store::OpStore;
use sea_orm::{
    sea_query::Expr, ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, Database,
    DatabaseConnection, DbErr, EntityTrait, QueryFilter, Schema, TransactionTrait,
};

fn db_err(e: DbErr) -> StoreError {
    StoreError::Internal(format!("sea_orm error: {e}"))
}

fn decode_json<T: serde::de::DeserializeOwned>(value: sea_orm::JsonValue) -> Result<T, StoreError> {
    serde_json::from_value(value)
        .map_err(|e| StoreError::Internal(format!("failed to decode stored JSON: {e}")))
}

/// A real, compiled `OpStore` implementation backed by [`sea_orm`] —
/// authkestra#289's proof that the storage traits `authkestra-op` exposes
/// are implementable by a third-party ORM, not just the first-party
/// `authkestra-store-sqlx`.
///
/// Deliberately simpler than `authkestra-store-sqlx` in ways a production
/// integration would likely harden: no foreign-key constraints between
/// tables (so no `ON DELETE CASCADE`), and only a SQLite backend is wired
/// up. Both are choices made for this to stay readable as an example, not
/// limitations of the trait design itself.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SeaOrmOpStore {
    db: DatabaseConnection,
}

impl SeaOrmOpStore {
    /// Connects to `database_url` (e.g. `sqlite::memory:` or
    /// `sqlite://path/to/db.sqlite`) via SeaORM.
    ///
    /// A private, per-connection in-memory (or temporary) database is
    /// special-cased to a single-connection pool: SQLite gives every such
    /// connection its own independent database, so SeaORM/sqlx's default
    /// pool size (5) would silently scatter this store's rows across
    /// several unrelated in-memory databases — `migrate()` would create
    /// tables in whichever one it happens to check out, and any other
    /// checkout would see "no such table: oauth_clients". A real
    /// (file-backed) database has no such problem and keeps the default
    /// pool size, since SQLite's own locking already serializes writers
    /// across connections. See
    /// [`authkestra_engine::store::sqlite_url::is_private_memory_url`] for
    /// exactly which URL forms count as private — shared with
    /// `authkestra-example-diesel`'s identical guard, since both examples
    /// need to recognize the same set of SQLite spellings.
    pub async fn connect(database_url: &str) -> Result<Self, DbErr> {
        let mut opt = sea_orm::ConnectOptions::new(database_url);
        if is_private_memory_url(database_url) {
            opt.max_connections(1);
        }
        let db = Database::connect(opt).await?;
        Ok(Self { db })
    }

    /// Wraps an already-open SeaORM connection.
    pub fn from_connection(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// The underlying SeaORM connection, for host-application code that
    /// wants to compose its own queries or entities against the same
    /// database (e.g. seeding a `ClientRegistration` — see this crate's
    /// module docs for why that has no generic path through `ClientStore`).
    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    /// Creates the four tables this store needs, if they don't already
    /// exist. Idempotent — safe to call on every startup, same contract as
    /// `authkestra-store-sqlx::SqlxOpStore::migrate`.
    pub async fn migrate(&self) -> Result<(), DbErr> {
        let backend = self.db.get_database_backend();
        let schema = Schema::new(backend);

        for stmt in [
            schema.create_table_from_entity(client::Entity),
            schema.create_table_from_entity(code::Entity),
            schema.create_table_from_entity(refresh_token::Entity),
            schema.create_table_from_entity(device_code::Entity),
        ] {
            let mut stmt = stmt;
            self.db.execute(backend.build(stmt.if_not_exists())).await?;
        }

        // `create_table_from_entity` does not emit the `#[sea_orm(indexed)]`
        // columns' indexes (e.g. `device_code::Model::user_code`, on the
        // device-flow's `/device/verify` hot path via `get_by_user_code`) —
        // that needs `create_index_from_entity` explicitly.
        for stmt in schema
            .create_index_from_entity(client::Entity)
            .into_iter()
            .chain(schema.create_index_from_entity(code::Entity))
            .chain(schema.create_index_from_entity(refresh_token::Entity))
            .chain(schema.create_index_from_entity(device_code::Entity))
        {
            let mut stmt = stmt;
            self.db.execute(backend.build(stmt.if_not_exists())).await?;
        }

        Ok(())
    }
}

#[allow(deprecated)] // require_pkce (authkestra#273) — PKCE is mandatory unconditionally now
fn client_from_model(model: client::Model) -> Result<ClientRegistration, StoreError> {
    let token_endpoint_auth_method: Option<TokenEndpointAuthMethod> =
        match model.token_endpoint_auth_method {
            Some(v) => Some(decode_json(v)?),
            None => None,
        };
    Ok(ClientRegistration {
        client_id: model.client_id,
        client_secret_hash: model.client_secret_hash,
        redirect_uris: decode_json(model.redirect_uris)?,
        grant_types: decode_json::<Vec<GrantType>>(model.grant_types)?,
        scopes: decode_json(model.scopes)?,
        require_pkce: model.require_pkce,
        allowed_audiences: decode_json(model.allowed_audiences)?,
        token_endpoint_auth_method,
        jwks: model.jwks,
    })
}

#[async_trait]
impl ClientStore for SeaOrmOpStore {
    async fn find_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientRegistration>, StoreError> {
        let model = client::Entity::find_by_id(client_id)
            .one(&self.db)
            .await
            .map_err(db_err)?;
        model.map(client_from_model).transpose()
    }
}

fn code_from_model(model: code::Model) -> Result<AuthorizationCode, StoreError> {
    Ok({
        let mut code = AuthorizationCode::new(
            model.code,
            model.client_id,
            model.redirect_uri,
            model.scope,
            decode_json(model.identity)?,
            model.expires_at,
            model.used,
        );
        code.code_challenge = model.code_challenge;
        code.code_challenge_method = model.code_challenge_method;
        code.nonce = model.nonce;
        code
    })
}

#[async_trait]
impl AuthorizationCodeStore for SeaOrmOpStore {
    async fn store_code(&mut self, code: AuthorizationCode) -> Result<(), StoreError> {
        let identity = serde_json::to_value(&code.identity)
            .map_err(|e| StoreError::Internal(format!("failed to encode value as JSON: {e}")))?;
        let active = code::ActiveModel {
            code: ActiveValue::Set(code.code),
            client_id: ActiveValue::Set(code.client_id),
            redirect_uri: ActiveValue::Set(code.redirect_uri),
            scope: ActiveValue::Set(code.scope),
            code_challenge: ActiveValue::Set(code.code_challenge),
            code_challenge_method: ActiveValue::Set(code.code_challenge_method),
            nonce: ActiveValue::Set(code.nonce),
            identity: ActiveValue::Set(identity),
            expires_at: ActiveValue::Set(code.expires_at),
            used: ActiveValue::Set(code.used),
        };
        active.insert(&self.db).await.map_err(db_err)?;
        Ok(())
    }

    async fn consume_code(&mut self, code: &str) -> Result<Option<AuthorizationCode>, StoreError> {
        let txn = self.db.begin().await.map_err(db_err)?;
        let model = code::Entity::find_by_id(code)
            .one(&txn)
            .await
            .map_err(db_err)?;
        let Some(mut model) = model else {
            txn.rollback().await.map_err(db_err)?;
            return Ok(None);
        };
        // Single-use, atomically: the `UPDATE ... WHERE used = false` is
        // the actual compare-and-swap — two concurrent consumers can both
        // reach this point having read `used: false` above, but only the
        // one whose UPDATE affects a row (still `used = false` at write
        // time) may treat the code as consumed. Same shape, and the same
        // reasoning, as authkestra-store-sqlx's own consume_code; the
        // `find_by_id` above is a read for the fields to return, not the
        // authority on whether this call wins the race.
        let result = code::Entity::update_many()
            .col_expr(code::Column::Used, Expr::value(true))
            .filter(code::Column::Code.eq(code))
            .filter(code::Column::Used.eq(false))
            .exec(&txn)
            .await
            .map_err(db_err)?;
        if result.rows_affected != 1 {
            txn.rollback().await.map_err(db_err)?;
            return Ok(None);
        }
        txn.commit().await.map_err(db_err)?;
        model.used = true;
        code_from_model(model).map(Some)
    }
}

fn refresh_token_from_model(model: refresh_token::Model) -> Result<RefreshToken, StoreError> {
    Ok(RefreshToken::new(
        model.token,
        model.client_id,
        decode_json(model.identity)?,
        model.scope,
        model.expires_at,
        model.jkt,
    ))
}

#[async_trait]
impl RefreshTokenStore for SeaOrmOpStore {
    async fn store_token(&mut self, token: RefreshToken) -> Result<(), StoreError> {
        let identity = serde_json::to_value(&token.identity)
            .map_err(|e| StoreError::Internal(format!("failed to encode value as JSON: {e}")))?;
        let active = refresh_token::ActiveModel {
            token: ActiveValue::Set(token.token),
            client_id: ActiveValue::Set(token.client_id),
            identity: ActiveValue::Set(identity),
            scope: ActiveValue::Set(token.scope),
            expires_at: ActiveValue::Set(token.expires_at),
            jkt: ActiveValue::Set(token.jkt),
        };
        active.insert(&self.db).await.map_err(db_err)?;
        Ok(())
    }

    async fn get_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        let model = refresh_token::Entity::find_by_id(token)
            .one(&self.db)
            .await
            .map_err(db_err)?;
        model.map(refresh_token_from_model).transpose()
    }

    async fn revoke_token(&mut self, token: &str) -> Result<(), StoreError> {
        refresh_token::Entity::delete_by_id(token)
            .exec(&self.db)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn consume_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        let txn = self.db.begin().await.map_err(db_err)?;
        let model = refresh_token::Entity::find_by_id(token)
            .one(&txn)
            .await
            .map_err(db_err)?;
        let Some(model) = model else {
            txn.rollback().await.map_err(db_err)?;
            return Ok(None);
        };
        // The DELETE, not the `find_by_id` above, is what's atomic: two
        // concurrent consumers can both read the row present, but only the
        // one whose DELETE actually removes it (checked via
        // `rows_affected`) may treat the token as consumed — same
        // compare-and-swap reasoning as `consume_code`.
        let result = refresh_token::Entity::delete_by_id(token)
            .exec(&txn)
            .await
            .map_err(db_err)?;
        if result.rows_affected != 1 {
            txn.rollback().await.map_err(db_err)?;
            return Ok(None);
        }
        txn.commit().await.map_err(db_err)?;
        refresh_token_from_model(model).map(Some)
    }
}

fn device_code_from_model(model: device_code::Model) -> Result<DeviceCodeSession, StoreError> {
    let status: DeviceCodeStatus = decode_json(model.status)?;
    Ok({
        let mut session = DeviceCodeSession::new(
            model.device_code,
            model.user_code,
            model.client_id,
            model.scope,
            model.expires_at,
            status,
        );
        session.last_polled_at = model.last_polled_at;
        session
    })
}

fn device_code_active_model(
    session: &DeviceCodeSession,
) -> Result<device_code::ActiveModel, StoreError> {
    let status = serde_json::to_value(&session.status)
        .map_err(|e| StoreError::Internal(format!("failed to encode value as JSON: {e}")))?;
    Ok(device_code::ActiveModel {
        device_code: ActiveValue::Set(session.device_code.clone()),
        user_code: ActiveValue::Set(session.user_code.clone()),
        client_id: ActiveValue::Set(session.client_id.clone()),
        scope: ActiveValue::Set(session.scope.clone()),
        expires_at: ActiveValue::Set(session.expires_at),
        status: ActiveValue::Set(status),
        last_polled_at: ActiveValue::Set(session.last_polled_at),
    })
}

#[async_trait]
impl DeviceCodeStore for SeaOrmOpStore {
    async fn store_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        device_code_active_model(&session)?
            .insert(&self.db)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn get_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let model = device_code::Entity::find_by_id(device_code)
            .one(&self.db)
            .await
            .map_err(db_err)?;
        model.map(device_code_from_model).transpose()
    }

    async fn get_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        use sea_orm::{ColumnTrait, QueryFilter};
        let model = device_code::Entity::find()
            .filter(device_code::Column::UserCode.eq(user_code))
            .one(&self.db)
            .await
            .map_err(db_err)?;
        model.map(device_code_from_model).transpose()
    }

    async fn update_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        device_code_active_model(&session)?
            .update(&self.db)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn delete_device_code(&mut self, device_code: &str) -> Result<(), StoreError> {
        device_code::Entity::delete_by_id(device_code)
            .exec(&self.db)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn consume_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let txn = self.db.begin().await.map_err(db_err)?;
        let model = device_code::Entity::find_by_id(device_code)
            .one(&txn)
            .await
            .map_err(db_err)?;
        let Some(model) = model else {
            txn.rollback().await.map_err(db_err)?;
            return Ok(None);
        };
        // Same compare-and-swap reasoning as `consume_token`: the DELETE's
        // `rows_affected`, not the read above, decides whether this call
        // wins the race against a concurrent consumer of the same device
        // code.
        let result = device_code::Entity::delete_by_id(device_code)
            .exec(&txn)
            .await
            .map_err(db_err)?;
        if result.rows_affected != 1 {
            txn.rollback().await.map_err(db_err)?;
            return Ok(None);
        }
        txn.commit().await.map_err(db_err)?;
        device_code_from_model(model).map(Some)
    }
}

impl OpStore for SeaOrmOpStore {}
