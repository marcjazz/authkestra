//! SeaORM entity for `oauth_refresh_tokens`.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "oauth_refresh_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub token: String,
    pub client_id: String,
    pub identity: Json,
    pub scope: String,
    pub expires_at: DateTimeUtc,
    pub jkt: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
