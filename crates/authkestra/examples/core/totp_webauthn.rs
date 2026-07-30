use authkestra_engine::auth::{AuthInput, CredentialStore};
use authkestra_engine::auth::totp::TotpAuthMethod;
use authkestra_engine::store::sql::SqlxCredentialStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize an in-memory SQLite connection for the example store
    #[cfg(feature = "sql-sqlite")]
    {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await?;
        
        // 2. Initialize the SqlxCredentialStore
        let store = SqlxCredentialStore::new(pool);
        
        // 3. Create schema tables
        println!("Running SQLite migrations for credentials table...");
        store.migrate().await?;
        
        // 4. Create the TOTP Authenticator Method
        let totp_method = TotpAuthMethod::new(store);
        
        // 5. Register a new TOTP secret for a user
        let user_id = "user_987";
        println!("Registering TOTP key for user '{user_id}'...");
        let (secret_b32, otpauth_uri) = totp_method.register_totp(user_id, "AuthkestraDemo", "user@example.com").await?;
        
        println!("TOTP Secret (Base32): {secret_b32}");
        println!("Scan this URI in Google Authenticator / 1Password: {otpauth_uri}");
        
        // 6. Generate current code using totp-rs
        use totp_rs::{Algorithm, TOTP, Secret};
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret_b32).to_bytes()?,
            None,
            "".to_string(),
        )?;
        
        let current_code = totp.generate_current()?;
        println!("Current valid 6-digit code is: {current_code}");
        
        // 7. Verify the code using the authenticator
        println!("Verifying the current code...");
        let auth_input = AuthInput::Totp {
            user_id: user_id.to_string(),
            code: current_code,
        };
        
        let identity = totp_method.authenticate(auth_input).await?;
        println!("Authentication successful! User ID: {}", identity.external_id);
    }

    #[cfg(not(feature = "sql-sqlite"))]
    {
        println!("Please run this example with `sql-sqlite` feature enabled!");
    }

    Ok(())
}
