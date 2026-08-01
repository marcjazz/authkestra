//! Minimal, self-contained "Issuer" + "Device" for this example.
//!
//! In production, the Issuer is `authkestra-op`'s enrolment ceremony (tracked separately in
//! authkestra#136) and the device key never leaves the device. Here, for a runnable demo, both
//! keypairs are generated in-process at startup, and this module mints the two JWSes
//! (`X-Signature`, `X-Attestation`) exactly the way a real device + a real Issuer would -- see
//! `crates/authkestra-devsig/tests/support/mod.rs` for the conformance-test twin of this code.

use std::time::{SystemTime, UNIX_EPOCH};

use authkestra_devsig::{InMemoryReplayStore, IssuerJwks, VerifierConfig};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{crypto, Algorithm, EncodingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The audience these demo requests are signed for.
pub const AUDIENCE: &str = "authkestra-devsig-example";
/// The trusted attestation issuer for this demo.
pub const ISSUER: &str = "https://issuer.example.com";
/// The demo subject bound to the attestation.
pub const SUBJECT: &str = "demo-user-1";
/// The demo device identifier bound to the attestation.
pub const DEVICE_ID: &str = "demo-device-1";

/// Everything needed to run the example server and mint demo requests against it.
pub struct Demo {
    pub config: VerifierConfig,
    pub jwks: IssuerJwks,
    pub replay_store: InMemoryReplayStore,
    issuer_kid: String,
    issuer_key: EncodingKey,
    device_jwk_json: Value,
    device_key: EncodingKey,
}

impl Demo {
    /// Generates a fresh Issuer keypair (RSA-2048) and device keypair (P-256 / ES256), and
    /// registers the Issuer's public key in an in-memory JWKS cache.
    pub async fn new() -> Self {
        let issuer_kid = "issuer-key-1".to_string();
        let (issuer_key, issuer_jwk) = generate_rsa_keypair(&issuer_kid);
        let (device_key, device_jwk_json) = generate_ec_keypair();

        let jwks = IssuerJwks::new();
        jwks.insert(ISSUER, issuer_kid.clone(), issuer_jwk).await;

        let config = VerifierConfig::new(
            [ISSUER],
            [Algorithm::ES256, Algorithm::RS256],
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(300),
            AUDIENCE,
        );

        Self {
            config,
            jwks,
            replay_store: InMemoryReplayStore::default(),
            issuer_kid,
            issuer_key,
            device_jwk_json,
            device_key,
        }
    }

    /// Mints a valid, currently-active `X-Attestation` binding [`SUBJECT`]/[`DEVICE_ID`] to this
    /// demo's device key.
    pub fn mint_attestation(&self) -> String {
        let jwk: Jwk = serde_json::from_value(self.device_jwk_json.clone())
            .expect("device jwk parses back as Jwk");
        let thumbprint = jwk
            .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
            .expect("compute thumbprint");

        let now = now_unix();
        let header =
            json!({ "alg": "RS256", "kid": self.issuer_kid, "typ": "authkestra-attest+jws" });
        let claims = json!({
            "iss": ISSUER,
            "sub": SUBJECT,
            "cnf": { "jkt": thumbprint },
            "did": DEVICE_ID,
            "iat": now,
            "exp": now + 30 * 24 * 3600,
            "att": { "status": "active" },
        });

        let signing_key = self.issuer_key.clone();
        build_compact_jws(&header, &claims, |msg| {
            crypto::sign(msg, &signing_key, Algorithm::RS256).expect("sign demo attestation")
        })
    }

    /// Mints a valid `X-Signature` for a request with the given method/path/body, tied to
    /// [`AUDIENCE`]. `body`, if present, is bound via `bdh` -- exactly the check this scheme
    /// exists to make possible without a session store.
    pub fn mint_signature(&self, method: &str, path: &str, body: Option<&[u8]>) -> String {
        let now = now_unix();
        let header =
            json!({ "alg": "ES256", "typ": "authkestra-devsig+jws", "jwk": self.device_jwk_json });
        let mut claims = json!({
            "iat": now,
            "exp": now + 90,
            "jti": format!("demo-{now}"),
            "mth": method,
            "pth": path,
            "aud": AUDIENCE,
        });
        if let Some(body) = body {
            claims["bdh"] = json!(hex_sha256(body));
        }

        let signing_key = self.device_key.clone();
        build_compact_jws(&header, &claims, |msg| {
            crypto::sign(msg, &signing_key, Algorithm::ES256).expect("sign demo request")
        })
    }
}

fn generate_rsa_keypair(kid: &str) -> (EncodingKey, Jwk) {
    let mut rng = rand::rngs::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA-2048 key");
    let pem = {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("encode RSA key to PKCS1 PEM")
    };
    let encoding_key =
        EncodingKey::from_rsa_pem(pem.as_bytes()).expect("EncodingKey::from_rsa_pem");
    let mut jwk =
        Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).expect("derive public jwk");
    jwk.common.key_id = Some(kid.to_string());
    (encoding_key, jwk)
}

fn generate_ec_keypair() -> (EncodingKey, Value) {
    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let pem = {
        use p256::pkcs8::EncodePrivateKey;
        secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("encode EC key to PKCS8 PEM")
    };
    let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes()).expect("EncodingKey::from_ec_pem");
    let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::ES256).expect("derive public jwk");
    let jwk_json = serde_json::to_value(&jwk).expect("serialize device jwk");
    (encoding_key, jwk_json)
}

fn build_compact_jws(header: &Value, claims: &Value, sign: impl Fn(&[u8]) -> String) -> String {
    let header_b64 = b64url(&serde_json::to_vec(header).expect("serialize header"));
    let payload_b64 = b64url(&serde_json::to_vec(claims).expect("serialize claims"));
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature_b64 = sign(signing_input.as_bytes());
    format!("{header_b64}.{payload_b64}.{signature_b64}")
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hex_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970-01-01")
        .as_secs() as i64
}
