#[cfg(any(
    feature = "sql-postgres",
    feature = "sql-sqlite",
    feature = "sql-mysql"
))]
pub mod session;

#[cfg(any(
    feature = "sql-postgres",
    feature = "sql-sqlite",
    feature = "sql-mysql"
))]
pub mod credential;

#[cfg(any(
    feature = "sql-postgres",
    feature = "sql-sqlite",
    feature = "sql-mysql"
))]
pub use session::{SqlKvModel, SqlKvStore, SqlStore};

#[cfg(any(
    feature = "sql-postgres",
    feature = "sql-sqlite",
    feature = "sql-mysql"
))]
pub use credential::SqlxCredentialStore;
