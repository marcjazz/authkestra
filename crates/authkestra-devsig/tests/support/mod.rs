//! Test-only "Issuer" and "Device" — mints attestations and request signatures matching the
//! wire format `verify()` expects, since no live Issuer exists in this repo yet
//! (`authkestra-op`'s enrolment/attestation-minting side is tracked separately in
//! [authkestra#136](https://github.com/marcjazz/authkestra/issues/136)).

use std::cell::Cell;
use std::sync::OnceLock;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{crypto, Algorithm, EncodingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use authkestra_devsig::{IssuerJwks, VerifierConfig};

pub const SUBJECT: &str = "user-7f3a9c12";
pub const DEVICE_ID: &str = "dev-8821bc04";
pub const ISSUER: &str = "https://id.example.com";
pub const AUD: &str = "api.example.com";

/// An asymmetric keypair plus its public `jsonwebtoken::jwk::Jwk` (both typed and as raw JSON,
/// ready to splice into a JOSE header).
#[derive(Clone)]
pub struct KeyPair {
    pub encoding_key: EncodingKey,
    pub alg: Algorithm,
    pub jwk_json: Value,
    pub thumbprint: String,
}

impl KeyPair {
    fn generate_ec() -> Self {
        let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let pem = {
            use p256::pkcs8::EncodePrivateKey;
            secret
                .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                .expect("encode EC key to PKCS8 PEM")
        };
        let encoding_key =
            EncodingKey::from_ec_pem(pem.as_bytes()).expect("EncodingKey::from_ec_pem");
        let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::ES256)
            .expect("derive public jwk from EC encoding key");
        let thumbprint = jwk
            .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
            .expect("compute thumbprint");
        let jwk_json = serde_json::to_value(&jwk).expect("serialize device jwk");
        Self {
            encoding_key,
            alg: Algorithm::ES256,
            jwk_json,
            thumbprint,
        }
    }

    fn alg_name(&self) -> &'static str {
        match self.alg {
            Algorithm::ES256 => "ES256",
            other => panic!("unexpected test keypair alg {other:?}"),
        }
    }
}

/// The test "Issuer": an RSA keypair playing the role of `authkestra-op`.
#[derive(Clone)]
pub struct Issuer {
    pub kid: String,
    pub encoding_key: EncodingKey,
}

impl Issuer {
    fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let private_key =
            rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA-2048 issuer key");
        let pem = {
            use rsa::pkcs1::EncodeRsaPrivateKey;
            private_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .expect("encode RSA key to PKCS1 PEM")
        };
        let encoding_key =
            EncodingKey::from_rsa_pem(pem.as_bytes()).expect("EncodingKey::from_rsa_pem");
        Self {
            kid: "issuer-key-1".to_string(),
            encoding_key,
        }
    }

    fn public_jwk(&self) -> Jwk {
        let mut jwk = Jwk::from_encoding_key(&self.encoding_key, Algorithm::RS256)
            .expect("derive public jwk from RSA encoding key");
        jwk.common.key_id = Some(self.kid.clone());
        jwk
    }
}

/// RSA-2048 keygen in a pure-Rust bignum implementation is not fast; the issuer identity is the
/// same across every test in this suite, so generate it once and clone the (cheap) key handle
/// rather than paying for it in every `TestSetup::new()`.
fn shared_issuer() -> Issuer {
    static ISSUER_KEY: OnceLock<Issuer> = OnceLock::new();
    ISSUER_KEY.get_or_init(Issuer::generate).clone()
}

pub struct TestSetup {
    pub config: VerifierConfig,
    pub jwks: IssuerJwks,
    pub issuer: Issuer,
    /// The legitimate device's keypair — the one bound in every attestation this setup mints.
    pub device: KeyPair,
    /// A second, unrelated keypair. Represents an attacker who has captured a victim's
    /// attestation (public, travels in every request) but does not hold the victim's private
    /// key. Used by the key-binding conformance case.
    pub attacker: KeyPair,
    jti_counter: Cell<u64>,
}

impl TestSetup {
    pub async fn new() -> Self {
        let issuer = shared_issuer();
        let device = KeyPair::generate_ec();
        let attacker = KeyPair::generate_ec();

        let jwks = IssuerJwks::new();
        jwks.insert(ISSUER, issuer.kid.clone(), issuer.public_jwk())
            .await;

        let config = VerifierConfig::new(
            [ISSUER],
            [Algorithm::ES256, Algorithm::RS256],
            Duration::from_secs(30),
            Duration::from_secs(120),
            AUD,
        );

        Self {
            config,
            jwks,
            issuer,
            device,
            attacker,
            jti_counter: Cell::new(0),
        }
    }

    fn next_jti(&self) -> String {
        let n = self.jti_counter.get();
        self.jti_counter.set(n + 1);
        format!("01JQZX3F7K8N4Y2M6P1R9T5V{n:06}")
    }

    // ---- Attestations ----

    pub fn valid_attestation(&self) -> String {
        self.attestation_full(
            ISSUER,
            &self.issuer.kid,
            SUBJECT,
            &self.device.thumbprint,
            DEVICE_ID,
            "active",
            0,
            30 * 24 * 3600,
        )
    }

    pub fn attestation_with_issuer(&self, iss: &str) -> String {
        self.attestation_full(
            iss,
            &self.issuer.kid,
            SUBJECT,
            &self.device.thumbprint,
            DEVICE_ID,
            "active",
            0,
            30 * 24 * 3600,
        )
    }

    pub fn attestation_with_kid(&self, kid: &str) -> String {
        self.attestation_full(
            ISSUER,
            kid,
            SUBJECT,
            &self.device.thumbprint,
            DEVICE_ID,
            "active",
            0,
            30 * 24 * 3600,
        )
    }

    pub fn attestation_with_status(&self, status: &str) -> String {
        self.attestation_full(
            ISSUER,
            &self.issuer.kid,
            SUBJECT,
            &self.device.thumbprint,
            DEVICE_ID,
            status,
            0,
            30 * 24 * 3600,
        )
    }

    /// Builds an attestation whose JOSE header carries an arbitrary, possibly-illegal `alg`
    /// (e.g. `"none"`), signed with a placeholder signature — `alg` is expected to be rejected
    /// before the placeholder signature is ever inspected.
    pub fn attestation_with_raw_header_alg(&self, alg: &str) -> String {
        let now = now_unix();
        let header = json!({ "alg": alg, "kid": self.issuer.kid, "typ": "webank-attest+jws" });
        let claims = attestation_claims(
            ISSUER,
            SUBJECT,
            &self.device.thumbprint,
            DEVICE_ID,
            now,
            now + 30 * 24 * 3600,
            "active",
        );
        build_raw_compact_jws(&header, &claims, |_msg| "AA".to_string())
    }

    #[allow(clippy::too_many_arguments)]
    fn attestation_full(
        &self,
        iss: &str,
        kid: &str,
        sub: &str,
        jkt: &str,
        did: &str,
        status: &str,
        iat_offset: i64,
        exp_offset: i64,
    ) -> String {
        let now = now_unix();
        let header = json!({ "alg": "RS256", "kid": kid, "typ": "webank-attest+jws" });
        let claims = attestation_claims(
            iss,
            sub,
            jkt,
            did,
            now + iat_offset,
            now + exp_offset,
            status,
        );
        let encoding_key = self.issuer.encoding_key.clone();
        build_raw_compact_jws(&header, &claims, |msg| {
            crypto::sign(msg, &encoding_key, Algorithm::RS256).expect("sign test attestation")
        })
    }

    // ---- Request signatures ----

    pub fn valid_signature(
        &self,
        key: &KeyPair,
        mth: &str,
        pth: &str,
        query: Option<&str>,
        body: Option<&[u8]>,
    ) -> String {
        self.signature_full(key, mth, pth, &self.next_jti(), 0, 90, AUD, query, body)
    }

    pub fn valid_signature_with_query(
        &self,
        key: &KeyPair,
        mth: &str,
        pth: &str,
        query: &str,
    ) -> String {
        self.valid_signature(key, mth, pth, Some(query), None)
    }

    pub fn valid_signature_with_body(
        &self,
        key: &KeyPair,
        mth: &str,
        pth: &str,
        body: &[u8],
    ) -> String {
        self.valid_signature(key, mth, pth, None, Some(body))
    }

    pub fn valid_signature_with_jti(
        &self,
        key: &KeyPair,
        mth: &str,
        pth: &str,
        jti: &str,
    ) -> String {
        self.signature_full(key, mth, pth, jti, 0, 90, AUD, None, None)
    }

    pub fn signature_with_aud(&self, key: &KeyPair, mth: &str, pth: &str, aud: &str) -> String {
        self.signature_full(key, mth, pth, &self.next_jti(), 0, 90, aud, None, None)
    }

    pub fn signature_with_time_offsets(
        &self,
        key: &KeyPair,
        mth: &str,
        pth: &str,
        iat_offset: i64,
        exp_offset: i64,
    ) -> String {
        self.signature_full(
            key,
            mth,
            pth,
            &self.next_jti(),
            iat_offset,
            exp_offset,
            AUD,
            None,
            None,
        )
    }

    /// Same shape as [`Self::signature_full`] but with an illegal `alg` in the header (e.g.
    /// `"none"`) and a placeholder signature — `alg` is expected to be rejected first.
    pub fn signature_with_raw_header_alg(
        &self,
        alg: &str,
        mth: &str,
        pth: &str,
        query: Option<&str>,
        body: Option<&[u8]>,
    ) -> String {
        let header = json!({ "alg": alg, "typ": "webank-devsig+jws", "jwk": self.device.jwk_json });
        let claims = signature_claims(
            mth,
            pth,
            &self.next_jti(),
            now_unix(),
            now_unix() + 90,
            AUD,
            query,
            body,
        );
        build_raw_compact_jws(&header, &claims, |_msg| "AA".to_string())
    }

    /// A request signature whose embedded `jwk` carries a private component (`d`) alongside the
    /// legitimate public members. Still actually signed with the real private key, since the
    /// point of this test is that the *presence* of `d` is rejected outright — the verifier must
    /// never get far enough to consider whether it could have used it.
    pub fn signature_with_private_component_in_jwk(
        &self,
        key: &KeyPair,
        mth: &str,
        pth: &str,
    ) -> String {
        let mut jwk_json = key.jwk_json.clone();
        jwk_json["d"] = json!("fake-private-scalar-must-never-be-trusted-or-even-looked-at");
        let header = json!({ "alg": key.alg_name(), "typ": "webank-devsig+jws", "jwk": jwk_json });
        let claims = signature_claims(
            mth,
            pth,
            &self.next_jti(),
            now_unix(),
            now_unix() + 90,
            AUD,
            None,
            None,
        );
        let encoding_key = key.encoding_key.clone();
        let alg = key.alg;
        build_raw_compact_jws(&header, &claims, |msg| {
            crypto::sign(msg, &encoding_key, alg).expect("sign test request")
        })
    }

    /// A request signature whose embedded `jwk` claims `"kty":"EC","crv":"Ed25519"` — a
    /// structurally-inconsistent pairing that `jsonwebtoken` 10.4.0's `Jwk::thumbprint()` panics
    /// on rather than erroring. The signature bytes are nonsense (there is no real Ed25519-over-EC
    /// key to sign with) since the point is that this must be rejected before the signature is
    /// ever checked, purely on the strength of the malformed key shape.
    pub fn signature_with_inconsistent_curve(&self, mth: &str, pth: &str) -> String {
        let jwk_json = json!({
            "kty": "EC",
            "crv": "Ed25519",
            "x": self.device.jwk_json["x"],
            "y": self.device.jwk_json["y"],
        });
        let header = json!({ "alg": "ES256", "typ": "webank-devsig+jws", "jwk": jwk_json });
        let claims = signature_claims(
            mth,
            pth,
            &self.next_jti(),
            now_unix(),
            now_unix() + 90,
            AUD,
            None,
            None,
        );
        build_raw_compact_jws(&header, &claims, |_msg| "AA".to_string())
    }

    /// A request signature legitimately produced under HS256 (a real HMAC, with a key an
    /// "attacker" might plausibly have guessed or leaked). Rejected on `alg` alone; the
    /// signature itself is not defective.
    pub fn signature_signed_with_hmac(&self, key: &KeyPair, mth: &str, pth: &str) -> String {
        let header = json!({ "alg": "HS256", "typ": "webank-devsig+jws", "jwk": key.jwk_json });
        let claims = signature_claims(
            mth,
            pth,
            &self.next_jti(),
            now_unix(),
            now_unix() + 90,
            AUD,
            None,
            None,
        );
        let hmac_key =
            EncodingKey::from_secret(b"a-symmetric-secret-this-scheme-must-never-accept");
        build_raw_compact_jws(&header, &claims, |msg| {
            crypto::sign(msg, &hmac_key, Algorithm::HS256).expect("sign test request with HS256")
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn signature_full(
        &self,
        key: &KeyPair,
        mth: &str,
        pth: &str,
        jti: &str,
        iat_offset: i64,
        exp_offset: i64,
        aud: &str,
        query: Option<&str>,
        body: Option<&[u8]>,
    ) -> String {
        let now = now_unix();
        let header =
            json!({ "alg": key.alg_name(), "typ": "webank-devsig+jws", "jwk": key.jwk_json });
        let claims = signature_claims(
            mth,
            pth,
            jti,
            now + iat_offset,
            now + exp_offset,
            aud,
            query,
            body,
        );
        let encoding_key = key.encoding_key.clone();
        let alg = key.alg;
        build_raw_compact_jws(&header, &claims, |msg| {
            crypto::sign(msg, &encoding_key, alg).expect("sign test request")
        })
    }
}

fn attestation_claims(
    iss: &str,
    sub: &str,
    jkt: &str,
    did: &str,
    iat: i64,
    exp: i64,
    status: &str,
) -> Value {
    json!({
        "iss": iss,
        "sub": sub,
        "cnf": { "jkt": jkt },
        "did": did,
        "iat": iat,
        "exp": exp,
        "att": { "kyc_level": 2, "roles": ["customer"], "status": status },
    })
}

#[allow(clippy::too_many_arguments)]
fn signature_claims(
    mth: &str,
    pth: &str,
    jti: &str,
    iat: i64,
    exp: i64,
    aud: &str,
    query: Option<&str>,
    body: Option<&[u8]>,
) -> Value {
    let mut claims = json!({
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "mth": mth,
        "pth": pth,
        "aud": aud,
    });
    if let Some(q) = query {
        claims["qsh"] = json!(hex_sha256(q.as_bytes()));
    }
    if let Some(b) = body {
        claims["bdh"] = json!(hex_sha256(b));
    }
    claims
}

fn build_raw_compact_jws(header: &Value, claims: &Value, sign: impl Fn(&[u8]) -> String) -> String {
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
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970-01-01")
        .as_secs() as i64
}
