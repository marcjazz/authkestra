//! A real, compiled Diesel-backed `OpStore` implementation
//! (authkestra#289, Phase D) — the second proof, alongside
//! `authkestra-example-seaorm`, that `authkestra-op`'s storage traits are
//! implementable against a third-party ORM. See [`DieselOpStore`]'s doc
//! comment for how a sync ORM fits async traits, and what this
//! deliberately simplifies relative to `authkestra-store-sqlx`.

mod models;
mod schema;
mod store;

pub use store::DieselOpStore;
