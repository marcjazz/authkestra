//! # Axum + multi-factor authentication
//!
//! Where the OAuth examples plug *providers* into [`Engine::builder`], this one
//! plugs in *auth methods*: the same unified engine drives first-factor and
//! step-up authentication through one call, [`Engine::authenticate`].
//!
//! The return type is the whole design. `AuthResult::MfaRequired` is a value
//! your handler must deal with, not an error — so "we forgot to challenge for
//! the second factor" is not a reachable state.
//!
//! `with_auth_method` registers a first factor; `with_mfa_method` registers a
//! method usable *only* to satisfy a step-up challenge. Both delegate to the
//! same [`AuthMethod`] plugin interface, so a custom factor drops in the same
//! way the built-in TOTP and WebAuthn ones do.
//!
//! ```sh
//! cargo run -p authkestra --example axum_mfa_server --all-features
//! ```
//!
//! Set `PORT` to bind somewhere other than 3000.

use authkestra_engine::auth::{AuthError, AuthInput, AuthResult, CredentialStore};
use authkestra_engine::Engine;
use axum::{extract::State, routing::post, Json, Router};
use std::sync::Arc;
use url::Url;
use webauthn_rs::prelude::WebauthnBuilder;

/// A stub credential store so the example needs no database.
///
/// It reports no enrolled credentials, which is enough to exercise the
/// `MfaRequired` branch below; a real implementation would persist these via
/// whatever backend you already use (see `authkestra_engine::store`).
#[derive(Clone, Default)]
struct MemoryCredentialStore;

#[async_trait::async_trait]
impl CredentialStore for MemoryCredentialStore {
    async fn get_credentials(
        &self,
        _user_id: &str,
        _cred_type: &str,
    ) -> Result<Vec<serde_json::Value>, AuthError> {
        Ok(vec![])
    }

    async fn save_credential(
        &self,
        _user_id: &str,
        _cred_type: &str,
        _data: serde_json::Value,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    async fn update_credential(
        &self,
        _credential_id: &str,
        _data: serde_json::Value,
    ) -> Result<(), AuthError> {
        Ok(())
    }
}

/// No session store and no token manager: this example stops at "who are
/// you?", so the engine stays in its default `Missing`/`Missing` typestate.
/// Issuing a session or a JWT afterwards is what the other examples cover.
#[derive(Clone)]
struct AppState {
    engine: Engine,
}

#[tokio::main]
async fn main() {
    // `RUST_LOG=authkestra=debug` surfaces the engine's own instrumentation.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,authkestra=debug".into()),
        )
        .init();

    let port = port_from_env();
    let store = MemoryCredentialStore;

    // The relying-party origin must match the URL the browser actually uses,
    // so it follows `PORT` too.
    let origin = Url::parse(&format!("http://localhost:{port}")).expect("valid origin URL");
    let webauthn = WebauthnBuilder::new("localhost", &origin)
        .expect("valid relying party")
        .rp_name("Authkestra MFA Demo")
        .build()
        .expect("valid WebAuthn configuration");

    // `with_totp` / `with_webauthn` are the shorthands for the built-in
    // methods; both are thin wrappers over `with_auth_method`, so a custom
    // `AuthMethod` registers exactly the same way.
    let engine = Engine::builder()
        .with_webauthn(Arc::new(webauthn), store.clone())
        // TOTP is registered as step-up only: it cannot be used as a first
        // factor on its own, only to answer an `MfaRequired` challenge.
        .with_mfa_method(authkestra_engine::auth::totp::TotpAuthMethod::new(store))
        // A real app would also register a password method here.
        .build();

    let app = Router::new()
        .route("/login", post(login_handler))
        .route("/mfa-verify", post(mfa_verify_handler))
        .with_state(AppState { engine });

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind example server");

    tracing::info!(%port, "Axum MFA server listening on http://localhost:{port}");
    axum::serve(listener, app).await.unwrap();
}

/// First-factor login. Returns either a completed identity or an MFA challenge.
async fn login_handler(
    State(state): State<AppState>,
    Json(input): Json<AuthInput>,
) -> Json<serde_json::Value> {
    match state.engine.authenticate(input).await {
        Ok(AuthResult::Success(identity)) => {
            tracing::info!(user = %identity.external_id, "first factor sufficient");
            // A real app would mint a session or JWT here.
            Json(serde_json::json!({ "status": "success", "identity": identity }))
        }
        Ok(AuthResult::MfaRequired {
            mfa_token,
            allowed_methods,
            ..
        }) => {
            tracing::info!(?allowed_methods, "step-up authentication required");
            // `mfa_token` is a short-lived JWT the client must echo back to
            // `/mfa-verify`; it is what binds the two requests together.
            Json(serde_json::json!({
                "status": "mfa_required",
                "mfa_token": mfa_token,
                "allowed_methods": allowed_methods,
            }))
        }
        Err(err) => {
            tracing::warn!(%err, "authentication failed");
            Json(serde_json::json!({ "status": "error", "message": err.to_string() }))
        }
    }
}

/// Second-factor verification. Expects an `AuthInput::MfaChallenge` carrying
/// the `mfa_token` issued by `/login`.
async fn mfa_verify_handler(
    State(state): State<AppState>,
    Json(input): Json<AuthInput>,
) -> Json<serde_json::Value> {
    match state.engine.authenticate(input).await {
        Ok(AuthResult::Success(identity)) => {
            tracing::info!(user = %identity.external_id, "step-up verified");
            Json(serde_json::json!({
                "status": "success",
                "message": "MFA verified!",
                "identity": identity,
            }))
        }
        // Only reachable if a third factor were configured; surfaced rather
        // than swallowed so the state is visible if that ever changes.
        Ok(AuthResult::MfaRequired { .. }) => {
            tracing::warn!("a further factor was requested after step-up");
            Json(serde_json::json!({
                "status": "error",
                "message": "Unexpected MFA state",
            }))
        }
        Err(err) => {
            tracing::warn!(%err, "step-up verification failed");
            Json(serde_json::json!({ "status": "error", "message": err.to_string() }))
        }
    }
}

/// Bind port, overridable via `PORT` so several examples can run without
/// colliding on 3000.
fn port_from_env() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000)
}
