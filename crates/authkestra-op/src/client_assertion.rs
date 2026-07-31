//! Asymmetric client authentication — `private_key_jwt` (RFC 7523 §2.2,
//! OIDC Core §9).
//!
//! A confidential client that is a *backend service* often cannot use a
//! shared `client_secret` at all. Signing anything with a shared secret means
//! HMAC, and a deployment that bans symmetric algorithms outright — because
//! verifying an HMAC requires holding the same secret, which defeats the
//! point of asking the client to prove anything — has nowhere to put one.
//! The alternatives are worse: `client_credentials` or token exchange add a
//! network round trip per request, which a hot path cannot absorb.
//! `private_key_jwt` is the standard answer: the client owns an asymmetric
//! keypair, the OP stores only the **public** half, and the client
//! authenticates by signing a short-lived JWT assertion.
//!
//! **Inline `jwks`, no `jwks_uri`.** OIDC permits either. `jwks_uri` would
//! make the OP an HTTP client — outbound fetch, cache, refresh task, and a
//! new failure mode where client authentication depends on a third party
//! being reachable, plus an attacker-influenced URL to fetch (SSRF). This
//! crate today has no HTTP client dependency at all, and the simpler option
//! is fully sufficient for the machine-to-machine case this exists to serve.
//! An inline JWK Set can hold several keys, so rotation is still just
//! "publish both, then drop the old one".
//!
//! Everything here exists to make exactly one thing impossible: accepting an
//! assertion that the client's registered *public* key did not sign. Hence
//! the algorithm is derived from the key rather than from the
//! attacker-controlled header (see `assertion_algorithms`), symmetric
//! algorithms are refused before the key is even loaded, and a `jti` may be
//! spent only once ([`ClientAssertionStore`]).

use crate::attestation::parse_public_jwk;
use crate::client::ClientRegistration;
use crate::error::OpError;
use async_trait::async_trait;
use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

/// The only `client_assertion_type` this OP accepts (RFC 7523 §2.2).
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Upper bound on how far in the future a client assertion's `exp` may sit.
///
/// RFC 7523 §3 requires `exp` to be present and unexpired but sets no ceiling,
/// and an assertion is a bearer credential for its whole lifetime. Two things
/// follow: a decade-long assertion is a permanent password in JWT clothing,
/// and — because replay tracking has to remember every `jti` until it expires
/// — it is also an unbounded write into the replay store. A constant rather
/// than an `OpConfig` field on purpose: `OpConfig`'s fields are all public and
/// it is constructed with struct literals throughout this workspace, so
/// growing it is a breaking change that this feature does not need to make.
pub const MAX_CLIENT_ASSERTION_LIFETIME_SECS: i64 = 300;

/// What a caller learns from a successfully verified client assertion.
///
/// Only the replay-relevant parts: identity was already checked against the
/// `client_id` during verification, so there is nothing else worth handing
/// back.
#[derive(Debug, Clone)]
pub struct VerifiedClientAssertion {
    /// The assertion's `jti`, to be spent exactly once.
    pub jti: String,
    /// The assertion's `exp`. Replay tracking need only remember `jti` until
    /// this instant — after it, the assertion is refused on `exp` anyway.
    pub expires_at: DateTime<Utc>,
}

/// Records that a client assertion's `jti` has been spent.
///
/// `record_jti` **must** be atomic — a `get`-then-`set` implemented as two
/// separate storage calls is a TOCTOU race, and the race is precisely the
/// replay this trait exists to prevent: two concurrent presentations of the
/// same captured assertion would both observe "not yet seen". Same
/// requirement, and the same reasoning, as
/// `AuthorizationCodeStore::consume_code`.
#[async_trait]
pub trait ClientAssertionStore: Send + Sync {
    /// Atomically records `jti` as spent until `expires_at`.
    ///
    /// Returns `Ok(true)` if this is its first use (accept the assertion) and
    /// `Ok(false)` if it was already recorded (a replay — reject).
    async fn record_jti(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<bool, OpError>;
}

/// The fail-closed default: refuses every assertion.
///
/// A deployment that has not wired replay tracking cannot provide the
/// single-use guarantee RFC 7523 §3 requires, and accepting assertions
/// without it would be strictly worse than not supporting the method —
/// clients would believe they had proof-of-possession authentication while a
/// captured assertion stayed replayable for its whole lifetime. So the
/// default refuses rather than silently degrades.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoClientAssertionStore;

#[async_trait]
impl ClientAssertionStore for NoClientAssertionStore {
    async fn record_jti(&self, _jti: &str, _expires_at: DateTime<Utc>) -> Result<bool, OpError> {
        tracing::error!(
            "a private_key_jwt assertion was presented but no ClientAssertionStore is wired; \
             refusing it rather than accepting an assertion that could be replayed"
        );
        Err(OpError::ReplayProtectionUnavailable)
    }
}

/// Single-process, in-memory replay tracking.
///
/// Atomic **within one process** — the map is behind a single `Mutex`, so the
/// check and the insert cannot interleave. Across processes it is not shared,
/// so a multi-node deployment gets one accepted replay per node; such a
/// deployment must supply a store backed by something shared (Redis `SET NX`,
/// a SQL unique index) instead. Same trade-off, and the same intended use, as
/// `authkestra_engine::store::memory::MemoryStore`: correct for single-node
/// and for tests, not a production cluster answer.
#[derive(Debug, Default)]
pub struct MemoryClientAssertionStore {
    seen: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl MemoryClientAssertionStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ClientAssertionStore for MemoryClientAssertionStore {
    async fn record_jti(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<bool, OpError> {
        let now = Utc::now();
        let mut seen = self.seen.lock().map_err(|_| {
            // A poisoned mutex means a previous holder panicked mid-update, so
            // the map's contents can no longer be trusted to be complete —
            // and an incomplete replay set is indistinguishable from no
            // replay protection. Refuse rather than guess.
            tracing::error!("client assertion replay map is poisoned; refusing the assertion");
            OpError::Storage
        })?;

        // Expired entries can never cause a rejection again (the assertion
        // itself would fail `exp`), so drop them here rather than growing the
        // map forever or running a sweeper task for it.
        seen.retain(|_, exp| *exp > now);

        if seen.contains_key(jti) {
            return Ok(false);
        }
        seen.insert(jti.to_string(), expires_at);
        Ok(true)
    }
}

/// The signature algorithms a given registered public key may legitimately
/// have produced.
///
/// Derived from the **key**, never from the assertion's header — the same
/// "`alg` comes from configuration, never from the token" rule
/// `attestation::verify_challenge_signature` follows. An attacker who could
/// choose the algorithm could choose `HS256` and have the OP verify an HMAC
/// keyed by the *public* key bytes, which are public: the classic JWT
/// algorithm-confusion attack. Because the returned set never contains an
/// `HS*` variant, that attack has nowhere to land even if the header peek
/// below were removed.
///
/// A set rather than the single algorithm
/// `attestation::expected_algorithm` returns, because an RSA key carries no
/// hint of which RSASSA variant its owner signs with, and refusing all but
/// `RS256` would reject conformant clients for no security gain — every
/// member of the returned set still requires the same private key.
fn assertion_algorithms(jwk: &Jwk) -> Result<Vec<Algorithm>, OpError> {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(params) => match params.curve {
            EllipticCurve::P256 => Ok(vec![Algorithm::ES256]),
            EllipticCurve::P384 => Ok(vec![Algorithm::ES384]),
            EllipticCurve::P521 => Err(OpError::BadJwk(
                "P-521 has no corresponding jsonwebtoken::Algorithm".to_string(),
            )),
            EllipticCurve::Ed25519 => Err(OpError::BadJwk(
                "Ed25519 must be represented as an OctetKeyPair, not an EllipticCurve key"
                    .to_string(),
            )),
        },
        AlgorithmParameters::RSA(_) => Ok(vec![
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ]),
        AlgorithmParameters::OctetKeyPair(_) => Ok(vec![Algorithm::EdDSA]),
        AlgorithmParameters::OctetKey(_) => {
            unreachable!("symmetric keys are rejected by parse_public_jwk before this is reached")
        }
    }
}

/// The protected header fields this module reads before handing a compact JWS
/// to `jsonwebtoken`'s typed API.
#[derive(Debug, Deserialize)]
struct AssertionHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// Decodes the protected header of a compact JWS without verifying anything.
///
/// Peeking the raw `alg` as a *string* is deliberate:
/// `jsonwebtoken::Algorithm`'s deserializer hard-fails on `"none"` or an
/// unrecognised value, which would collapse the specific "you offered a
/// disallowed algorithm" case into an opaque parse failure. Same technique,
/// same reason, as `attestation::verify_challenge_signature`.
fn peek_header(compact_jws: &str) -> Result<AssertionHeader, OpError> {
    let header_b64 = compact_jws
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or(OpError::InvalidClientAssertion)?;

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| OpError::InvalidClientAssertion)?;

    serde_json::from_slice(&header_bytes).map_err(|_| OpError::InvalidClientAssertion)
}

/// The claims RFC 7523 §3 requires an authentication assertion to carry.
///
/// `aud` is deliberately absent: it may be a string or an array, and
/// `jsonwebtoken`'s `Validation` already handles both shapes correctly.
/// Everything listed here is non-`Option`, so a missing claim fails
/// deserialization — presence checking and parsing in one step, rather than
/// relying on `required_spec_claims` for claims it documents as ignored
/// (it only honours `exp`, `nbf`, `aud`, `iss`, `sub`).
#[derive(Debug, Deserialize)]
struct ClientAssertionClaims {
    iss: String,
    sub: String,
    jti: String,
    exp: i64,
}

/// Reads the `sub` of a compact JWS **without verifying its signature**,
/// purely to look up which client to verify against.
///
/// Safe only because of what happens next: the looked-up client's registered
/// key must then verify the signature, and `iss`/`sub` are re-checked against
/// that client's `client_id` (see [`verify_client_assertion`]). An attacker
/// naming someone else's `client_id` here only selects the key their
/// assertion will fail against. Needed because RFC 7521 §4.2 makes the
/// `client_id` parameter optional when a `client_assertion` is present.
pub fn peek_client_assertion_subject(compact_jws: &str) -> Option<String> {
    let payload_b64 = compact_jws.split('.').nth(1)?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload
        .get("sub")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Selects the registered key that should verify this assertion.
///
/// With a `kid` in the header, only the key carrying that exact `kid` is
/// considered — no "try them all" fallback, so a client with several
/// registered keys cannot have a signature attributed to a key it did not
/// use. Without a `kid`, the set must hold exactly one key; anything else is
/// ambiguous, and resolving ambiguity by trial is how a revoked-but-still-
/// listed key ends up authenticating someone.
fn select_key(jwks: &Value, kid: Option<&str>) -> Result<Jwk, OpError> {
    let keys = jwks.get("keys").and_then(Value::as_array).ok_or_else(|| {
        OpError::BadJwk("client jwks must be an object with a `keys` array".into())
    })?;

    let raw = match kid {
        Some(kid) => keys
            .iter()
            .find(|k| k.get("kid").and_then(Value::as_str) == Some(kid))
            .ok_or_else(|| {
                tracing::warn!(kid = %kid, "client assertion names a kid that is not registered");
                OpError::InvalidClientAssertion
            })?,
        None => {
            if keys.len() != 1 {
                tracing::warn!(
                    key_count = keys.len(),
                    "client assertion carries no kid and the client's jwks does not hold exactly \
                     one key; refusing to guess which key signed it"
                );
                return Err(OpError::InvalidClientAssertion);
            }
            &keys[0]
        }
    };

    // Re-validated from scratch at every use, never trusted because it was
    // accepted at registration time — this is what catches a JWK Set carrying
    // a private component or a symmetric key.
    parse_public_jwk(raw)
}

/// Verifies a `private_key_jwt` client assertion against `client`, per RFC
/// 7523 §3.
///
/// On success the caller still owes one step: spending the returned `jti`
/// through a [`ClientAssertionStore`]. Replay tracking is left out of this
/// function so that it stays pure — every claim and signature rule below is
/// unit-testable without a store, and the store's own failure modes cannot be
/// mistaken for a verification failure.
///
/// `expected_audiences` should hold the OP's token endpoint URL and its
/// issuer identifier. RFC 7523 §3 names the token endpoint; OIDC Core §9 says
/// the OP's Issuer identifier is also acceptable, and real clients emit both.
pub fn verify_client_assertion(
    assertion: &str,
    client: &ClientRegistration,
    expected_audiences: &[String],
) -> Result<VerifiedClientAssertion, OpError> {
    let header = peek_header(assertion)?;

    // First gate, before a key is even loaded: an assertion is only ever
    // verified against a *public* key, so a symmetric algorithm — or `none` —
    // can never be legitimate here, whatever the client registered.
    if header.alg.eq_ignore_ascii_case("none")
        || matches!(header.alg.as_str(), "HS256" | "HS384" | "HS512")
    {
        tracing::warn!(
            client_id = %client.client_id,
            alg = %header.alg,
            "client assertion offers a symmetric or `none` algorithm; refusing"
        );
        return Err(OpError::BadAlg(header.alg));
    }

    let jwks = client.jwks.as_ref().ok_or_else(|| {
        tracing::warn!(
            client_id = %client.client_id,
            "client presented a client_assertion but has no registered jwks"
        );
        OpError::InvalidClientAssertion
    })?;

    let jwk = select_key(jwks, header.kid.as_deref())?;
    let algorithms = assertion_algorithms(&jwk)?;
    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
        tracing::warn!(client_id = %client.client_id, error = %e, "registered jwk is unusable");
        OpError::BadJwk(e.to_string())
    })?;

    let mut validation = Validation::new(algorithms[0]);
    validation.algorithms = algorithms;
    validation.validate_exp = true;
    // `nbf` is optional in RFC 7523 §3, but an assertion that carries one and
    // is not yet valid must not be accepted early.
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "aud"]);
    validation.set_audience(expected_audiences);
    // `leeway` stays at jsonwebtoken's 60s default: an assertion is minted
    // seconds before it is presented, and the clocks of the client and the OP
    // are not the same clock.

    let data = jsonwebtoken::decode::<ClientAssertionClaims>(assertion, &decoding_key, &validation)
        .map_err(|e| {
            tracing::warn!(
                client_id = %client.client_id,
                error = %e,
                "client assertion failed signature or claim validation"
            );
            OpError::InvalidClientAssertion
        })?;

    // RFC 7523 §3 points 1-2: the assertion must be self-issued for the
    // client it authenticates. Checked against the registration we actually
    // loaded, which is what makes the unverified `sub` peek used for client
    // lookup harmless.
    if data.claims.iss != client.client_id || data.claims.sub != client.client_id {
        tracing::warn!(
            client_id = %client.client_id,
            iss = %data.claims.iss,
            sub = %data.claims.sub,
            "client assertion iss/sub do not both equal the client_id"
        );
        return Err(OpError::InvalidClientAssertion);
    }

    let expires_at = match Utc.timestamp_opt(data.claims.exp, 0).single() {
        Some(t) => t,
        None => {
            tracing::warn!(client_id = %client.client_id, exp = data.claims.exp, "client assertion exp is not a representable timestamp");
            return Err(OpError::InvalidClientAssertion);
        }
    };

    if expires_at > Utc::now() + chrono::Duration::seconds(MAX_CLIENT_ASSERTION_LIFETIME_SECS) {
        tracing::warn!(
            client_id = %client.client_id,
            "client assertion exp is further out than MAX_CLIENT_ASSERTION_LIFETIME_SECS"
        );
        return Err(OpError::InvalidClientAssertion);
    }

    tracing::debug!(
        client_id = %client.client_id,
        "client assertion signature and claims verified; jti still to be spent"
    );

    Ok(VerifiedClientAssertion {
        jti: data.claims.jti,
        expires_at,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::client::{GrantType, TokenEndpointAuthMethod};
    use jsonwebtoken::{EncodingKey, Header};
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::{JwkEcKey, PublicKey};
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;

    pub(crate) struct TestKey {
        pub(crate) pkcs8_der: Vec<u8>,
        pub(crate) public_jwk: Value,
    }

    pub(crate) fn generate_test_key(kid: Option<&str>) -> TestKey {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key: PublicKey<p256::NistP256> = signing_key.verifying_key().into();
        let mut public_jwk = serde_json::to_value(JwkEcKey::from(&public_key)).unwrap();
        if let Some(kid) = kid {
            public_jwk["kid"] = Value::String(kid.to_string());
        }
        TestKey {
            pkcs8_der: signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
            public_jwk,
        }
    }

    pub(crate) fn jwks_of(keys: &[&TestKey]) -> Value {
        serde_json::json!({ "keys": keys.iter().map(|k| k.public_jwk.clone()).collect::<Vec<_>>() })
    }

    pub(crate) fn test_client(jwks: Option<Value>) -> ClientRegistration {
        ClientRegistration {
            client_id: "svc-1".to_string(),
            client_secret_hash: None,
            redirect_uris: vec![],
            grant_types: vec![GrantType::ClientCredentials],
            scopes: vec![],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks,
        }
    }

    fn audiences() -> Vec<String> {
        vec![
            "https://auth.example.com/token".to_string(),
            "https://auth.example.com".to_string(),
        ]
    }

    /// Mints an assertion, letting each test bend exactly one thing.
    pub(crate) fn sign_assertion(
        key: &TestKey,
        kid: Option<&str>,
        claims: Value,
        alg: Algorithm,
    ) -> String {
        let mut header = Header::new(alg);
        header.kid = kid.map(str::to_string);
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ec_der(&key.pkcs8_der)).unwrap()
    }

    pub(crate) fn good_claims() -> Value {
        serde_json::json!({
            "iss": "svc-1",
            "sub": "svc-1",
            "aud": "https://auth.example.com/token",
            "jti": "jti-1",
            "exp": (Utc::now() + chrono::Duration::seconds(60)).timestamp(),
            "iat": Utc::now().timestamp(),
        })
    }

    #[test]
    fn accepts_a_well_formed_assertion() {
        let key = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&key])));
        let assertion = sign_assertion(&key, None, good_claims(), Algorithm::ES256);

        let verified = verify_client_assertion(&assertion, &client, &audiences()).unwrap();
        assert_eq!(verified.jti, "jti-1");
    }

    #[test]
    fn accepts_the_issuer_as_audience() {
        let key = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&key])));
        let mut claims = good_claims();
        claims["aud"] = Value::String("https://auth.example.com".to_string());
        let assertion = sign_assertion(&key, None, claims, Algorithm::ES256);

        assert!(verify_client_assertion(&assertion, &client, &audiences()).is_ok());
    }

    #[test]
    fn rejects_an_assertion_signed_by_an_unregistered_key() {
        let registered = generate_test_key(None);
        let attacker = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&registered])));
        let assertion = sign_assertion(&attacker, None, good_claims(), Algorithm::ES256);

        assert!(matches!(
            verify_client_assertion(&assertion, &client, &audiences()),
            Err(OpError::InvalidClientAssertion)
        ));
    }

    /// The algorithm-confusion attack: an attacker who knows the client's
    /// public key (it is public) HMACs the assertion with those very bytes
    /// and offers `alg: HS256`.
    #[test]
    fn rejects_a_symmetric_algorithm() {
        let key = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&key])));

        let public_key_bytes = serde_json::to_vec(&key.public_jwk).unwrap();
        let forged = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &good_claims(),
            &EncodingKey::from_secret(&public_key_bytes),
        )
        .unwrap();

        assert!(
            matches!(
                verify_client_assertion(&forged, &client, &audiences()),
                Err(OpError::BadAlg(_))
            ),
            "an HS* assertion must never be verified against a public key"
        );
    }

    #[test]
    fn rejects_alg_none() {
        let key = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&key])));
        // Hand-built: no encoder will emit `alg: none` for us.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&good_claims()).unwrap());
        let unsigned = format!("{header}.{payload}.");

        assert!(matches!(
            verify_client_assertion(&unsigned, &client, &audiences()),
            Err(OpError::BadAlg(_))
        ));
    }

    #[test]
    fn rejects_a_wrong_audience() {
        let key = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&key])));
        let mut claims = good_claims();
        claims["aud"] = Value::String("https://someone-else.example.com/token".to_string());
        let assertion = sign_assertion(&key, None, claims, Algorithm::ES256);

        assert!(
            matches!(
                verify_client_assertion(&assertion, &client, &audiences()),
                Err(OpError::InvalidClientAssertion)
            ),
            "an assertion minted for another OP must not authenticate here"
        );
    }

    #[test]
    fn rejects_a_missing_audience() {
        let key = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&key])));
        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove("aud");
        let assertion = sign_assertion(&key, None, claims, Algorithm::ES256);

        assert!(matches!(
            verify_client_assertion(&assertion, &client, &audiences()),
            Err(OpError::InvalidClientAssertion)
        ));
    }

    #[test]
    fn rejects_an_expired_assertion() {
        let key = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&key])));
        let mut claims = good_claims();
        // Beyond jsonwebtoken's 60s default leeway.
        claims["exp"] = Value::from((Utc::now() - chrono::Duration::seconds(600)).timestamp());
        let assertion = sign_assertion(&key, None, claims, Algorithm::ES256);

        assert!(matches!(
            verify_client_assertion(&assertion, &client, &audiences()),
            Err(OpError::InvalidClientAssertion)
        ));
    }

    #[test]
    fn rejects_a_missing_exp() {
        let key = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&key])));
        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove("exp");
        let assertion = sign_assertion(&key, None, claims, Algorithm::ES256);

        assert!(matches!(
            verify_client_assertion(&assertion, &client, &audiences()),
            Err(OpError::InvalidClientAssertion)
        ));
    }

    #[test]
    fn rejects_an_assertion_that_never_meaningfully_expires() {
        let key = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&key])));
        let mut claims = good_claims();
        claims["exp"] = Value::from((Utc::now() + chrono::Duration::days(3650)).timestamp());
        let assertion = sign_assertion(&key, None, claims, Algorithm::ES256);

        assert!(
            matches!(
                verify_client_assertion(&assertion, &client, &audiences()),
                Err(OpError::InvalidClientAssertion)
            ),
            "a decade-long assertion is a permanent bearer credential and an unbounded \
             write into the replay store"
        );
    }

    #[test]
    fn rejects_a_missing_jti() {
        let key = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&key])));
        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove("jti");
        let assertion = sign_assertion(&key, None, claims, Algorithm::ES256);

        assert!(
            matches!(
                verify_client_assertion(&assertion, &client, &audiences()),
                Err(OpError::InvalidClientAssertion)
            ),
            "without a jti there is nothing to spend, so replay protection would be a no-op"
        );
    }

    #[test]
    fn rejects_an_assertion_issued_for_another_client() {
        let key = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&key])));
        let mut claims = good_claims();
        claims["sub"] = Value::String("some-other-client".to_string());
        let assertion = sign_assertion(&key, None, claims, Algorithm::ES256);

        assert!(matches!(
            verify_client_assertion(&assertion, &client, &audiences()),
            Err(OpError::InvalidClientAssertion)
        ));
    }

    #[test]
    fn rejects_iss_and_sub_disagreeing() {
        let key = generate_test_key(None);
        let client = test_client(Some(jwks_of(&[&key])));
        let mut claims = good_claims();
        claims["iss"] = Value::String("some-other-client".to_string());
        let assertion = sign_assertion(&key, None, claims, Algorithm::ES256);

        assert!(matches!(
            verify_client_assertion(&assertion, &client, &audiences()),
            Err(OpError::InvalidClientAssertion)
        ));
    }

    #[test]
    fn rejects_a_client_with_no_registered_jwks() {
        let key = generate_test_key(None);
        let client = test_client(None);
        let assertion = sign_assertion(&key, None, good_claims(), Algorithm::ES256);

        assert!(matches!(
            verify_client_assertion(&assertion, &client, &audiences()),
            Err(OpError::InvalidClientAssertion)
        ));
    }

    #[test]
    fn rejects_a_jwks_carrying_a_private_component() {
        let key = generate_test_key(None);
        let mut leaked = key.public_jwk.clone();
        leaked["d"] = Value::String("smuggled-private-scalar".to_string());
        let client = test_client(Some(serde_json::json!({ "keys": [leaked] })));
        let assertion = sign_assertion(&key, None, good_claims(), Algorithm::ES256);

        assert!(matches!(
            verify_client_assertion(&assertion, &client, &audiences()),
            Err(OpError::BadJwk(_))
        ));
    }

    #[test]
    fn selects_the_named_key_when_several_are_registered() {
        let key_a = generate_test_key(Some("a"));
        let key_b = generate_test_key(Some("b"));
        let client = test_client(Some(jwks_of(&[&key_a, &key_b])));

        let assertion = sign_assertion(&key_b, Some("b"), good_claims(), Algorithm::ES256);
        assert!(verify_client_assertion(&assertion, &client, &audiences()).is_ok());

        // Signed by A but claiming to be B: the named key must be the one
        // used, with no fallback that tries the others.
        let mismatched = sign_assertion(&key_a, Some("b"), good_claims(), Algorithm::ES256);
        assert!(matches!(
            verify_client_assertion(&mismatched, &client, &audiences()),
            Err(OpError::InvalidClientAssertion)
        ));
    }

    #[test]
    fn refuses_to_guess_between_several_keys_without_a_kid() {
        let key_a = generate_test_key(Some("a"));
        let key_b = generate_test_key(Some("b"));
        let client = test_client(Some(jwks_of(&[&key_a, &key_b])));
        let assertion = sign_assertion(&key_a, None, good_claims(), Algorithm::ES256);

        assert!(matches!(
            verify_client_assertion(&assertion, &client, &audiences()),
            Err(OpError::InvalidClientAssertion)
        ));
    }

    #[tokio::test]
    async fn memory_store_spends_a_jti_exactly_once() {
        let store = MemoryClientAssertionStore::new();
        let exp = Utc::now() + chrono::Duration::seconds(60);

        assert!(store.record_jti("jti-1", exp).await.unwrap());
        assert!(!store.record_jti("jti-1", exp).await.unwrap());
        assert!(store.record_jti("jti-2", exp).await.unwrap());
    }

    #[tokio::test]
    async fn no_store_refuses_rather_than_permitting_replay() {
        let store = NoClientAssertionStore;
        let exp = Utc::now() + chrono::Duration::seconds(60);
        assert!(matches!(
            store.record_jti("jti-1", exp).await,
            Err(OpError::ReplayProtectionUnavailable)
        ));
    }

    #[test]
    fn peeks_the_subject_without_verifying() {
        let key = generate_test_key(None);
        let assertion = sign_assertion(&key, None, good_claims(), Algorithm::ES256);
        assert_eq!(
            peek_client_assertion_subject(&assertion).as_deref(),
            Some("svc-1")
        );
        assert_eq!(peek_client_assertion_subject("not-a-jwt"), None);
    }
}
