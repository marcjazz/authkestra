#[cfg(any(
    feature = "sql-postgres",
    feature = "sql-sqlite",
    feature = "sql-mysql"
))]
pub mod session;

#[cfg(all(
    any(
        feature = "sql-postgres",
        feature = "sql-sqlite",
        feature = "sql-mysql"
    ),
    any(feature = "webauthn", feature = "totp")
))]
pub mod credential;

#[cfg(any(
    feature = "sql-postgres",
    feature = "sql-sqlite",
    feature = "sql-mysql"
))]
#[allow(deprecated)]
pub use session::{SqlKvModel, SqlKvStore, SqlStore};

#[cfg(all(
    any(
        feature = "sql-postgres",
        feature = "sql-sqlite",
        feature = "sql-mysql"
    ),
    any(feature = "webauthn", feature = "totp")
))]
pub use credential::SqlxCredentialStore;
