//! SeaORM entity for `oauth_clients`. Read-only from `ClientStore`'s
//! perspective — see `SeaOrmOpStore`'s doc comment for why this example
//! still seeds rows through it directly (bypassing the trait) for its own
//! tests.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "oauth_clients")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub require_pkce: bool,
    pub redirect_uris: Json,
    pub grant_types: Json,
    pub scopes: Json,
    pub allowed_audiences: Json,
    pub token_endpoint_auth_method: Option<Json>,
    pub jwks: Option<Json>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
