//! Row structs mapping the `schema.rs` tables to/from
//! `authkestra_op`/`authkestra_engine` domain types.

use crate::schema::{oauth_clients, oauth_codes, oauth_device_codes, oauth_refresh_tokens};
use authkestra_engine::store::StoreError;
use authkestra_op::client::{ClientRegistration, GrantType, TokenEndpointAuthMethod};
use authkestra_op::code::AuthorizationCode;
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStatus};
use authkestra_op::refresh::RefreshToken;
use chrono::{DateTime, NaiveDateTime, Utc};
use diesel::prelude::*;

fn to_naive(dt: DateTime<Utc>) -> NaiveDateTime {
    dt.naive_utc()
}

fn from_naive(dt: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(dt, Utc)
}

fn to_json(value: &impl serde::Serialize) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|_| StoreError::Internal("db".into()))
}

fn from_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, StoreError> {
    serde_json::from_str(value).map_err(|_| StoreError::Internal("db".into()))
}

#[derive(Queryable, Insertable, AsChangeset)]
#[diesel(table_name = oauth_clients)]
pub struct ClientRow {
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub require_pkce: bool,
    pub redirect_uris: String,
    pub grant_types: String,
    pub scopes: String,
    pub allowed_audiences: String,
    pub token_endpoint_auth_method: Option<String>,
    pub jwks: Option<String>,
}

impl ClientRow {
    #[allow(deprecated)] // require_pkce (authkestra#273) — PKCE is mandatory unconditionally now
    pub fn from_domain(c: &ClientRegistration) -> Result<Self, StoreError> {
        Ok(Self {
            client_id: c.client_id.clone(),
            client_secret_hash: c.client_secret_hash.clone(),
            require_pkce: c.require_pkce,
            redirect_uris: to_json(&c.redirect_uris)?,
            grant_types: to_json(&c.grant_types)?,
            scopes: to_json(&c.scopes)?,
            allowed_audiences: to_json(&c.allowed_audiences)?,
            token_endpoint_auth_method: c
                .token_endpoint_auth_method
                .as_ref()
                .map(to_json)
                .transpose()?,
            jwks: c.jwks.as_ref().map(to_json).transpose()?,
        })
    }

    #[allow(deprecated)]
    pub fn into_domain(self) -> Result<ClientRegistration, StoreError> {
        let token_endpoint_auth_method: Option<TokenEndpointAuthMethod> = self
            .token_endpoint_auth_method
            .as_deref()
            .map(from_json)
            .transpose()?;
        Ok(ClientRegistration {
            client_id: self.client_id,
            client_secret_hash: self.client_secret_hash,
            redirect_uris: from_json(&self.redirect_uris)?,
            grant_types: from_json::<Vec<GrantType>>(&self.grant_types)?,
            scopes: from_json(&self.scopes)?,
            require_pkce: self.require_pkce,
            allowed_audiences: from_json(&self.allowed_audiences)?,
            token_endpoint_auth_method,
            jwks: self.jwks.as_deref().map(from_json).transpose()?,
        })
    }
}

#[derive(Queryable, Insertable, AsChangeset)]
#[diesel(table_name = oauth_codes)]
pub struct CodeRow {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub identity: String,
    pub expires_at: NaiveDateTime,
    pub used: bool,
}

impl CodeRow {
    pub fn from_domain(c: &AuthorizationCode) -> Result<Self, StoreError> {
        Ok(Self {
            code: c.code.clone(),
            client_id: c.client_id.clone(),
            redirect_uri: c.redirect_uri.clone(),
            scope: c.scope.clone(),
            code_challenge: c.code_challenge.clone(),
            code_challenge_method: c.code_challenge_method.clone(),
            nonce: c.nonce.clone(),
            identity: to_json(&c.identity)?,
            expires_at: to_naive(c.expires_at),
            used: c.used,
        })
    }

    pub fn into_domain(self) -> Result<AuthorizationCode, StoreError> {
        Ok(AuthorizationCode {
            code: self.code,
            client_id: self.client_id,
            redirect_uri: self.redirect_uri,
            scope: self.scope,
            code_challenge: self.code_challenge,
            code_challenge_method: self.code_challenge_method,
            nonce: self.nonce,
            identity: from_json(&self.identity)?,
            expires_at: from_naive(self.expires_at),
            used: self.used,
        })
    }
}

#[derive(Queryable, Insertable, AsChangeset)]
#[diesel(table_name = oauth_refresh_tokens)]
pub struct RefreshTokenRow {
    pub token: String,
    pub client_id: String,
    pub identity: String,
    pub scope: String,
    pub expires_at: NaiveDateTime,
    pub jkt: Option<String>,
}

impl RefreshTokenRow {
    pub fn from_domain(t: &RefreshToken) -> Result<Self, StoreError> {
        Ok(Self {
            token: t.token.clone(),
            client_id: t.client_id.clone(),
            identity: to_json(&t.identity)?,
            scope: t.scope.clone(),
            expires_at: to_naive(t.expires_at),
            jkt: t.jkt.clone(),
        })
    }

    pub fn into_domain(self) -> Result<RefreshToken, StoreError> {
        Ok(RefreshToken {
            token: self.token,
            client_id: self.client_id,
            identity: from_json(&self.identity)?,
            scope: self.scope,
            expires_at: from_naive(self.expires_at),
            jkt: self.jkt,
        })
    }
}

#[derive(Queryable, Insertable, AsChangeset)]
#[diesel(table_name = oauth_device_codes)]
pub struct DeviceCodeRow {
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub expires_at: NaiveDateTime,
    pub status: String,
    pub last_polled_at: Option<NaiveDateTime>,
}

impl DeviceCodeRow {
    pub fn from_domain(s: &DeviceCodeSession) -> Result<Self, StoreError> {
        Ok(Self {
            device_code: s.device_code.clone(),
            user_code: s.user_code.clone(),
            client_id: s.client_id.clone(),
            scope: s.scope.clone(),
            expires_at: to_naive(s.expires_at),
            status: to_json(&s.status)?,
            last_polled_at: s.last_polled_at.map(to_naive),
        })
    }

    pub fn into_domain(self) -> Result<DeviceCodeSession, StoreError> {
        let status: DeviceCodeStatus = from_json(&self.status)?;
        Ok(DeviceCodeSession {
            device_code: self.device_code,
            user_code: self.user_code,
            client_id: self.client_id,
            scope: self.scope,
            expires_at: from_naive(self.expires_at),
            status,
            last_polled_at: self.last_polled_at.map(from_naive),
        })
    }
}
