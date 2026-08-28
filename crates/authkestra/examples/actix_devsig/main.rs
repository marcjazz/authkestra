//! # Actix Web devsig example
//!
//! Demonstrates protecting an Actix Web route with
//! `authkestra_actix::devsig::DeviceSignatureAuth` (device-bound signature authentication --
//! see `authkestra-devsig` and
//! [authkestra#137](https://github.com/marcjazz/authkestra/issues/137)). This is the Actix
//! mirror of `authkestra-axum`'s `axum_devsig` example -- same demo Issuer/device keypair setup,
//! same protected route shape, different framework glue.
//!
//! This example generates its own demo Issuer + device keypair at startup (see `signing.rs`),
//! registers the Issuer's public key in an in-memory JWKS cache, and mints a fresh, currently
//! valid `X-Signature` / `X-Attestation` pair for a sample `POST /v1/transfer` request. It then
//! starts the server and prints a ready-to-run `curl` command demonstrating both a valid
//! (200 OK) and an invalid (401 Unauthorized) call.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p authkestra --example actix_devsig --all-features
//! ```
//!
//! A valid signed request looks like this (values are freshly minted on every run, hence the
//! placeholders -- copy the actual `curl` command this example prints to stdout):
//!
//! ```text
//! curl -i -X POST http://127.0.0.1:8090/v1/transfer \
//!   -H 'Content-Type: application/json' \
//!   -H 'X-Signature: <compact JWS signed by the device key>' \
//!   -H 'X-Attestation: <compact JWS signed by the Issuer, binding the device key>' \
//!   -d '{"amount_cents":1000,"to":"acct_demo"}'
//! ```

mod signing;

use std::sync::Arc;

use actix_web::{post, web, App, HttpServer, Responder};
use authkestra_actix::devsig::{AuthDeviceSignature, DeviceSignatureAuth};
use serde_json::json;

use signing::Demo;

const TRANSFER_BODY: &str = r#"{"amount_cents":1000,"to":"acct_demo"}"#;

#[post("/v1/transfer")]
async fn transfer_handler(identity: AuthDeviceSignature) -> impl Responder {
    let AuthDeviceSignature(identity) = identity;
    web::Json(json!({
        "status": "accepted",
        "subject": identity.subject,
        "device": identity.device,
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let demo = Demo::new().await;
    let attestation = demo.mint_attestation();
    let valid_signature =
        demo.mint_signature("POST", "/v1/transfer", Some(TRANSFER_BODY.as_bytes()));

    let replay_store: Arc<dyn authkestra_devsig::ReplayStore> = Arc::new(demo.replay_store);
    let devsig = authkestra_devsig::DevSig::builder()
        .config(demo.config)
        .jwks(Arc::new(demo.jwks))
        .replay_store(replay_store)
        .build();

    let port = port_from_env();
    let addr = format!("127.0.0.1:{}", port);
    tracing::info!("authkestra-actix devsig example listening on http://{addr}");
    tracing::info!("");
    tracing::info!("Valid request (expect 200 OK):");
    tracing::info!(
        "curl -i -X POST http://{addr}/v1/transfer \\\n  \
         -H 'Content-Type: application/json' \\\n  \
         -H 'X-Signature: {valid_signature}' \\\n  \
         -H 'X-Attestation: {attestation}' \\\n  \
         -d '{TRANSFER_BODY}'"
    );
    tracing::info!("");
    tracing::info!("Unauthenticated request (expect 401 Unauthorized):");
    tracing::info!(
        "curl -i -X POST http://{addr}/v1/transfer \\\n  \
         -H 'Content-Type: application/json' \\\n  \
         -d '{TRANSFER_BODY}'"
    );
    tracing::info!("");

    HttpServer::new(move || {
        let auth = DeviceSignatureAuth::from(devsig.clone());
        App::new().wrap(auth).service(transfer_handler)
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}

/// Bind port, overridable via `PORT` so examples can run without colliding.
fn port_from_env() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8090)
}
