use authkestra_engine::auth::totp::TotpAuthMethod;
use authkestra_engine::auth::{
    AuthInput, AuthMethod, Identity, ReproofRequirement, IDENTITY_ATTR_AUTH_TIME,
};
use authkestra_engine::store::sql::SqlxCredentialStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize an in-memory SQLite connection for the example store
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await?;

    // 2. Initialize the SqlxCredentialStore
    let store = SqlxCredentialStore::new(pool);

    // 3. Create schema tables
    println!("Running SQLite migrations for credentials table...");
    store.migrate().await?;

    // 4. Create the TOTP Authenticator Method
    let totp_method = TotpAuthMethod::new(store);

    // 5. Register a new TOTP secret for a user.
    //
    // Enrolment is gated on a fresh re-proof of identity: a live session is
    // not enough, because a stolen one could otherwise enrol a factor its
    // holder controls. In a real application the `Identity` comes out of the
    // session store — `Engine::authenticate` stamps `auth_time` onto it — and
    // a failed check is where you send the user back through a login or
    // step-up challenge. Here it is built by hand, since there is no login
    // flow in this example.
    let user_id = "user_987";
    let mut attributes = std::collections::HashMap::new();
    attributes.insert(
        IDENTITY_ATTR_AUTH_TIME.to_string(),
        chrono::Utc::now().timestamp().to_string(),
    );
    let identity = Identity {
        provider_id: "example".to_string(),
        external_id: user_id.to_string(),
        email: None,
        username: None,
        attributes,
    };
    // Five minutes: long enough to survive typing a password and scanning a
    // QR code, short enough that a session left open yesterday does not
    // qualify. Pick this per operation — there is deliberately no default.
    let gate = ReproofRequirement::new(300);

    println!("Registering TOTP key for user '{user_id}'...");
    let (secret_b32, otpauth_uri) = totp_method
        .register_totp(&identity, &gate, "AuthkestraDemo", "user@example.com")
        .await?;

    println!("TOTP Secret (Base32): {secret_b32}");
    println!("Scan this URI in Google Authenticator / 1Password: {otpauth_uri}");

    // 6. Generate current code using totp-rs
    use totp_rs::{Algorithm, Secret, TOTP};
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
    println!(
        "Authentication successful! User ID: {}",
        identity.external_id
    );

    Ok(())
}
