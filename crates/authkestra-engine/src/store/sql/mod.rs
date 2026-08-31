#[cfg(all(
    any(
        feature = "sql-postgres",
        feature = "sql-sqlite",
        feature = "sql-mysql"
    ),
    any(feature = "webauthn", feature = "totp")
))]
pub mod credential;

#[cfg(all(
    any(
        feature = "sql-postgres",
        feature = "sql-sqlite",
        feature = "sql-mysql"
    ),
    any(feature = "webauthn", feature = "totp")
))]
pub use credential::SqlxCredentialStore;
