//! SeaORM entity for `oauth_codes`.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "oauth_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub identity: Json,
    pub expires_at: DateTimeUtc,
    pub used: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
