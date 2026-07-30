use authkestra_engine::auth::{totp::TotpAuthMethod, webauthn::WebAuthnAuthMethod};
use authkestra_engine::auth::{AuthInput, AuthResult, CredentialStore};
use authkestra_engine::engine::Engine;
use axum::{routing::post, Json, Router};
use std::sync::Arc;
use url::Url;
use webauthn_rs::prelude::WebauthnBuilder;

/// A simple in-memory credential store for the example.
#[derive(Clone, Default)]
struct MemoryCredentialStore;

#[async_trait::async_trait]
impl CredentialStore for MemoryCredentialStore {
    async fn get_credentials(
        &self,
        _user_id: &str,
        _cred_type: &str,
    ) -> Result<Vec<serde_json::Value>, authkestra_engine::auth::AuthError> {
        Ok(vec![]) // Simulate no credentials for the example
    }

    async fn save_credential(
        &self,
        _user_id: &str,
        _cred_type: &str,
        _data: serde_json::Value,
    ) -> Result<(), authkestra_engine::auth::AuthError> {
        Ok(())
    }

    async fn update_credential(
        &self,
        _credential_id: &str,
        _data: serde_json::Value,
    ) -> Result<(), authkestra_engine::auth::AuthError> {
        Ok(())
    }
}

// Shared App State
struct AppState {
    engine: Engine<authkestra_engine::engine::Missing, authkestra_engine::engine::Missing>, // Using stateless engine for this example
}

#[tokio::main]
async fn main() {
    // 1. Setup Data Store
    let store = MemoryCredentialStore;

    // 2. Setup WebAuthn
    let rp_id = "localhost";
    let origin = Url::parse("http://localhost:3000").unwrap();
    let webauthn = WebauthnBuilder::new(rp_id, &origin)
        .unwrap()
        .rp_name("Authkestra MFA Demo")
        .build()
        .unwrap();

    // 3. Build Unified Engine
    let engine = Engine::builder()
        .with_auth_method(TotpAuthMethod::new(store.clone()))
        .with_auth_method(WebAuthnAuthMethod::new(Arc::new(webauthn), store.clone()))
        // In a real app, you would also add a password AuthMethod here
        .build();

    let state = Arc::new(AppState { engine });

    // 4. Create Axum Router
    let app = Router::new()
        .route("/login", post(login_handler))
        .route("/mfa-verify", post(mfa_verify_handler))
        .with_state(state);

    println!("Starting server on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// The unified login endpoint.
async fn login_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(input): Json<AuthInput>,
) -> Json<serde_json::Value> {
    match state.engine.authenticate(input).await {
        Ok(AuthResult::Success(identity)) => {
            // Give them a session/token!
            Json(serde_json::json!({
                "status": "success",
                "identity": identity,
            }))
        }
        Ok(AuthResult::MfaRequired {
            mfa_token,
            allowed_methods,
            ..
        }) => {
            // Ask the client for their second factor!
            Json(serde_json::json!({
                "status": "mfa_required",
                "mfa_token": mfa_token,
                "allowed_methods": allowed_methods,
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": e.to_string(),
        })),
    }
}

/// The endpoint for completing MFA.
async fn mfa_verify_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(input): Json<AuthInput>, // Should be AuthInput::MfaChallenge
) -> Json<serde_json::Value> {
    match state.engine.authenticate(input).await {
        Ok(AuthResult::Success(identity)) => Json(serde_json::json!({
            "status": "success",
            "message": "MFA verified!",
            "identity": identity,
        })),
        Ok(AuthResult::MfaRequired { .. }) => {
            // Technically shouldn't happen unless triple-factor is enabled!
            Json(serde_json::json!({"status": "error", "message": "Unexpected MFA state"}))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": e.to_string(),
        })),
    }
}
