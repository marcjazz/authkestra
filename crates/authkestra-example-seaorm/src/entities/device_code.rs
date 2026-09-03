//! SeaORM entity for `oauth_device_codes`.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "oauth_device_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_code: String,
    #[sea_orm(indexed)]
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub expires_at: DateTimeUtc,
    pub status: Json,
    pub last_polled_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
