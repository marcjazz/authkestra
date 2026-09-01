//! A real, compiled SeaORM-backed `OpStore` implementation
//! (authkestra#289, Phase D) — proof that `authkestra-op`'s storage traits
//! are implementable against a third-party ORM, not just the first-party
//! `authkestra-store-sqlx`. See [`SeaOrmOpStore`]'s doc comment for what
//! this deliberately simplifies relative to that crate.

mod entities;
mod store;

pub use entities::{client, code, device_code, refresh_token};
pub use store::SeaOrmOpStore;
