//! Integration tests for `authkestra_resource::jwt`, covering:
//! - multi-value audience support on `ValidationConfig` / `ValidationConfigBuilder`
//! - backward compatibility of the single-value `.audience(...)` builder method
//! - opt-in strict `kid` enforcement on `JwksCache`
//! - per-issuer JWKS resolution for a multi-issuer resource server (issue #243)
//! - the documented default values produced by `ValidationConfigBuilder`
//!
//! JWKS is served via a local `wiremock` server and tokens are signed with
//! freshly generated RSA keys so the full offline-validation path (JWKS fetch,
//! key lookup, signature + claim validation) is exercised end to end.

use authkestra_engine::strategy::AuthenticationStrategy;
use authkestra_engine::token::cert_binding::{x5t_s256_thumbprint, ClientCertificateDer};
use authkestra_engine::token::jwk::Jwk;
use authkestra_resource::jwt::{
    validate_jwt_generic, validate_jwt_with_resolver, IssuerTrustMap, JwksCache, JwtStrategy,
    ValidationConfig, ValidationError,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::{header::AUTHORIZATION, Request};
use jsonwebtoken::{encode, errors::ErrorKind, Algorithm, EncodingKey, Header, Validation};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    sub: String,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
}

#[derive(Serialize)]
struct JwksBody {
    keys: Vec<Jwk>,
}

struct TestKey {
    encoding_key: EncodingKey,
    jwk: Jwk,
}

/// Generates a fresh RSA key pair and wraps it as both a signing key and the
/// public `Jwk` representation that would be published on a JWKS endpoint.
fn generate_rsa_key(kid: Option<&str>) -> TestKey {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key");
    let pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("failed to encode PKCS8 PEM");
    let encoding_key =
        EncodingKey::from_rsa_pem(pem.as_bytes()).expect("failed to build encoding key");

    let n = URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be());

    let jwk = Jwk {
        kid: kid.map(|s| s.to_string()),
        kty: "RSA".to_string(),
        alg: Some("RS256".to_string()),
        n: Some(n),
        e: Some(e),
        crv: None,
        x: None,
    };

    TestKey { encoding_key, jwk }
}

fn sign_token<T: Serialize>(key: &EncodingKey, kid: Option<&str>, claims: &T) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(|s| s.to_string());
    encode(&header, claims, key).expect("failed to sign token")
}

fn future_exp() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        + 3600
}

async fn start_jwks_server(keys: Vec<Jwk>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&JwksBody { keys }))
        .mount(&server)
        .await;
    server
}

fn jwks_url(server: &MockServer) -> String {
    format!("{}/.well-known/jwks.json", server.uri())
}

#[tokio::test]
async fn multi_audience_accepts_token_matching_any_configured_audience() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .audiences(["a", "b", "c"])
        .build();
    assert_eq!(
        config.audience,
        vec!["a".to_string(), "b".to_string(), "c".to_string()]
    );

    let cache = JwksCache::new(config.jwks_url.clone(), config.refresh_interval);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&config.audience);

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: Some("b".to_string()),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);

    let result: TestClaims = validate_jwt_generic(&token, &cache, &validation)
        .await
        .expect("token whose aud is in the configured audience set should validate");
    assert_eq!(result.sub, "user-1");
}

#[tokio::test]
async fn multi_audience_rejects_token_not_matching_any_configured_audience() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .audiences(["a", "c"])
        .build();

    let cache = JwksCache::new(config.jwks_url.clone(), config.refresh_interval);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&config.audience);

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: Some("b".to_string()),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);

    let err = validate_jwt_generic::<TestClaims>(&token, &cache, &validation)
        .await
        .expect_err("token whose aud is absent from the configured set must be rejected");
    assert!(matches!(err, ValidationError::Jwt(_)));
}

#[test]
fn single_audience_builder_call_is_backward_compatible() {
    let config = ValidationConfig::builder()
        .jwks_url("https://example.invalid/jwks.json")
        .audience("x")
        .build();

    assert_eq!(config.audience, vec!["x".to_string()]);
}

#[tokio::test]
async fn single_audience_builder_validates_like_before() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .audience("x")
        .build();

    let cache = JwksCache::new(config.jwks_url.clone(), config.refresh_interval);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&config.audience);

    let matching = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: Some("x".to_string()),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &matching);
    validate_jwt_generic::<TestClaims>(&token, &cache, &validation)
        .await
        .expect("token with matching single audience should validate");

    let mismatched = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: Some("y".to_string()),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &mismatched);
    let err = validate_jwt_generic::<TestClaims>(&token, &cache, &validation)
        .await
        .expect_err("token with mismatched single audience must be rejected");
    assert!(matches!(err, ValidationError::Jwt(_)));
}

#[tokio::test]
async fn missing_kid_falls_back_to_first_key_by_default() {
    let key1 = generate_rsa_key(Some("k1"));
    let key2 = generate_rsa_key(Some("k2"));
    let server = start_jwks_server(vec![key1.jwk.clone(), key2.jwk.clone()]).await;

    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600));
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    // Signed by the FIRST key in the JWKS, with no `kid` header on the token.
    let token = sign_token(&key1.encoding_key, None, &claims);

    let result: TestClaims = validate_jwt_generic(&token, &cache, &validation)
        .await
        .expect("kid-less token should fall back to the first JWKS key by default");
    assert_eq!(result.sub, "user-1");
}

#[tokio::test]
async fn missing_kid_is_rejected_when_require_kid_is_enabled() {
    let key1 = generate_rsa_key(Some("k1"));
    let key2 = generate_rsa_key(Some("k2"));
    let server = start_jwks_server(vec![key1.jwk.clone(), key2.jwk.clone()]).await;

    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600)).require_kid(true);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    let token = sign_token(&key1.encoding_key, None, &claims);

    let err = validate_jwt_generic::<TestClaims>(&token, &cache, &validation)
        .await
        .expect_err("kid-less token must be rejected when require_kid is enabled");
    assert!(matches!(err, ValidationError::MissingKid));
}

#[tokio::test]
async fn require_kid_still_allows_tokens_that_present_a_kid() {
    let key1 = generate_rsa_key(Some("k1"));
    let key2 = generate_rsa_key(Some("k2"));
    let server = start_jwks_server(vec![key1.jwk.clone(), key2.jwk.clone()]).await;

    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600)).require_kid(true);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;

    let claims = TestClaims {
        sub: "user-2".to_string(),
        exp: future_exp(),
        aud: None,
    };
    // Signed by the SECOND key and explicitly identifies it via `kid`.
    let token = sign_token(&key2.encoding_key, Some("k2"), &claims);

    let result: TestClaims = validate_jwt_generic(&token, &cache, &validation)
        .await
        .expect("token presenting a kid should validate normally under require_kid");
    assert_eq!(result.sub, "user-2");
}

#[tokio::test]
async fn strategy_surfaces_strict_kid_rejection_as_an_error_not_a_silent_none() {
    let key1 = generate_rsa_key(Some("k1"));
    let server = start_jwks_server(vec![key1.jwk.clone()]).await;

    let validation_config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_kid(true)
        .build();

    let strategy: JwtStrategy<TestClaims> = JwtStrategy::new(validation_config);

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    let token = sign_token(&key1.encoding_key, None, &claims);

    let request = Request::builder()
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(())
        .unwrap();
    let (parts, _) = request.into_parts();

    let result = strategy.authenticate(&parts).await;
    assert!(
        result.is_err(),
        "a strict-kid rejection must surface as Err(AuthError), not be swallowed as Ok(None)"
    );
}

// --- RFC 8705 certificate-bound (`cnf.x5t#S256`) access token tests -------
//
// Covers issue #224: a `client_credentials` token stamped with
// `cnf.x5t#S256` (see `authkestra-op`'s `handle_client_credentials` tests
// for the OP-side stamping half) must be rejected by
// `JwtStrategy::require_cert_binding` unless the *same* certificate — by
// SHA-256 thumbprint — is presented on the connection used to redeem it.

/// Claims shape carrying an optional RFC 8705 `cnf` confirmation claim,
/// separate from `TestClaims` above so the existing tests in this file stay
/// untouched.
#[derive(Debug, Serialize, Deserialize)]
struct CertBoundClaims {
    sub: String,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<serde_json::Value>,
}

/// Builds an `http::request::Parts` carrying a `Bearer` token and,
/// optionally, a `ClientCertificateDer` request extension — standing in for
/// whatever a host application's mTLS-terminating layer would have inserted
/// (see `ClientCertificateDer`'s doc comment).
fn bearer_request_parts(token: &str, cert_der: Option<&[u8]>) -> http::request::Parts {
    let mut request = Request::builder()
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(())
        .unwrap();
    if let Some(cert_der) = cert_der {
        request
            .extensions_mut()
            .insert(ClientCertificateDer(cert_der.to_vec()));
    }
    let (parts, _) = request.into_parts();
    parts
}

#[tokio::test]
async fn cert_binding_accepts_token_when_presented_certificate_matches() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let cert_der = b"a fake DER-encoded client certificate for testing";
    let thumbprint = x5t_s256_thumbprint(cert_der);

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_cert_binding(true)
        .build();
    let strategy: JwtStrategy<CertBoundClaims> = JwtStrategy::new(config);

    let claims = CertBoundClaims {
        sub: "service-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "x5t#S256": thumbprint })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let parts = bearer_request_parts(&token, Some(cert_der));

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    let identity = result.expect(
        "a certificate-bound token, redeemed with the same certificate it was bound to, must be accepted",
    );
    assert_eq!(identity.sub, "service-a");
}

#[tokio::test]
async fn cert_binding_rejects_token_when_presented_certificate_is_mismatched() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let bound_cert_der = b"the certificate the token was actually bound to";
    let presented_cert_der = b"a different, attacker-controlled certificate";
    let thumbprint = x5t_s256_thumbprint(bound_cert_der);

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_cert_binding(true)
        .build();
    let strategy: JwtStrategy<CertBoundClaims> = JwtStrategy::new(config);

    let claims = CertBoundClaims {
        sub: "service-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "x5t#S256": thumbprint })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let parts = bearer_request_parts(&token, Some(presented_cert_der));

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    assert!(
        result.is_none(),
        "a certificate-bound token presented with the WRONG certificate must be rejected"
    );
}

#[tokio::test]
async fn cert_binding_rejects_token_when_no_certificate_is_presented() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let bound_cert_der = b"the certificate the token was actually bound to";
    let thumbprint = x5t_s256_thumbprint(bound_cert_der);

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_cert_binding(true)
        .build();
    let strategy: JwtStrategy<CertBoundClaims> = JwtStrategy::new(config);

    let claims = CertBoundClaims {
        sub: "service-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "x5t#S256": thumbprint })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    // No `ClientCertificateDer` extension at all — e.g. a stolen bearer
    // token replayed from a peer with no client certificate, or one that
    // is mTLS-authenticated but under a different certificate than the
    // token was bound to.
    let parts = bearer_request_parts(&token, None);

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    assert!(
        result.is_none(),
        "a certificate-bound token presented with NO certificate at all must be rejected, \
         exactly like a mismatched one — mTLS alone does not restore proof-of-possession"
    );
}

#[tokio::test]
async fn cert_binding_is_not_enforced_when_require_cert_binding_is_false() {
    // Backward compatibility: a certificate-bound token is still accepted
    // as a plain bearer token when the resource server has not opted into
    // `require_cert_binding`.
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let bound_cert_der = b"the certificate the token was actually bound to";
    let thumbprint = x5t_s256_thumbprint(bound_cert_der);

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .build();
    assert!(!config.require_cert_binding);
    let strategy: JwtStrategy<CertBoundClaims> = JwtStrategy::new(config);

    let claims = CertBoundClaims {
        sub: "service-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "x5t#S256": thumbprint })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let parts = bearer_request_parts(&token, None);

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error")
        .expect(
            "without require_cert_binding, a certificate-bound token is still a valid bearer token",
        );
    assert_eq!(result.sub, "service-a");
}

// --- Multi-issuer JWKS resolution (issue #243) ---------------------------
//
// A single resource verifier trusting several issuers at once. The security
// property under test is that the token's `iss` selects *which* JWKS verifies
// it, with no default arm: an `iss` outside the trust map is rejected rather
// than falling through to some other issuer's keys.

const ISS_A: &str = "https://issuer-a.example";
const ISS_B: &str = "https://issuer-b.example";
const ISS_UNTRUSTED: &str = "https://issuer-c.example";

/// Claims carrying an `iss`, kept separate from `TestClaims` so the
/// single-issuer tests above stay exactly as they were.
#[derive(Debug, Serialize, Deserialize)]
struct IssuedClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    sub: String,
    exp: usize,
}

fn issued_claims(iss: Option<&str>, sub: &str) -> IssuedClaims {
    IssuedClaims {
        iss: iss.map(|s| s.to_string()),
        sub: sub.to_string(),
        exp: future_exp(),
    }
}

fn cache_for(server: &MockServer) -> Arc<JwksCache> {
    Arc::new(JwksCache::new(jwks_url(server), Duration::from_secs(3600)))
}

/// A `Validation` matching what `JwtStrategy` derives for a trust map, for the
/// tests that exercise `validate_jwt_with_resolver` directly.
fn multi_issuer_validation(accepted: &[&str]) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(accepted);
    validation.required_spec_claims.insert("iss".to_string());
    validation.validate_aud = false;
    validation
}

#[tokio::test]
async fn multi_issuer_verifies_each_token_against_its_own_issuers_jwks() {
    let key_a = generate_rsa_key(Some("a-key"));
    let key_b = generate_rsa_key(Some("b-key"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;
    let server_b = start_jwks_server(vec![key_b.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .trusted_issuer(ISS_A, jwks_url(&server_a))
        .trusted_issuer(ISS_B, jwks_url(&server_b))
        .build();
    assert_eq!(config.trusted_issuers.len(), 2);
    let strategy: JwtStrategy<IssuedClaims> = JwtStrategy::new(config);

    for (iss, key, kid) in [
        (ISS_A, &key_a, "a-key"),
        // The point of the test: issuer B's token is verified with keys fetched
        // from B's endpoint, which A's JWKS does not contain.
        (ISS_B, &key_b, "b-key"),
    ] {
        let token = sign_token(
            &key.encoding_key,
            Some(kid),
            &issued_claims(Some(iss), "user-1"),
        );
        let identity = strategy
            .authenticate(&bearer_request_parts(&token, None))
            .await
            .unwrap_or_else(|e| panic!("authenticate should not error for {iss}: {e}"))
            .unwrap_or_else(|| panic!("a valid token from trusted issuer {iss} must be accepted"));
        assert_eq!(identity.iss.as_deref(), Some(iss));
    }
}

#[tokio::test]
async fn multi_issuer_rejects_a_token_whose_issuer_is_not_in_the_trust_map() {
    let key_a = generate_rsa_key(Some("a-key"));
    let key_b = generate_rsa_key(Some("b-key"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;
    let server_b = start_jwks_server(vec![key_b.jwk.clone()]).await;

    // Signed by a key that IS published on a trusted endpoint, so the only
    // reason to reject is the issuer name itself.
    let token = sign_token(
        &key_a.encoding_key,
        Some("a-key"),
        &issued_claims(Some(ISS_UNTRUSTED), "user-1"),
    );

    let trust_map = IssuerTrustMap::new()
        .with_issuer(ISS_A, cache_for(&server_a))
        .with_issuer(ISS_B, cache_for(&server_b));

    // Rejected *for being untrusted*, not incidentally by signature or audience.
    let err = validate_jwt_with_resolver::<IssuedClaims>(
        &token,
        &trust_map,
        &multi_issuer_validation(&[ISS_A, ISS_B]),
    )
    .await
    .expect_err("a token from an issuer outside the trust map must be rejected");
    assert!(
        matches!(&err, ValidationError::UntrustedIssuer(iss) if iss == ISS_UNTRUSTED),
        "expected UntrustedIssuer({ISS_UNTRUSTED}), got {err:?}"
    );

    // And the same through the strategy, which must not silently accept it.
    let config = ValidationConfig::builder()
        .trusted_issuer(ISS_A, jwks_url(&server_a))
        .trusted_issuer(ISS_B, jwks_url(&server_b))
        .build();
    let strategy: JwtStrategy<IssuedClaims> = JwtStrategy::new(config);
    let res = strategy
        .authenticate(&bearer_request_parts(&token, None))
        .await
        .expect("authenticate must not fail on untrusted issuer");
    assert!(
        res.is_none(),
        "an untrusted issuer must be rejected gracefully as Ok(None) to allow fallback"
    );
}

#[tokio::test]
async fn multi_issuer_never_falls_back_to_the_single_issuer_jwks_url() {
    // `jwks_url` is set but no `issuer` names it, so it cannot be folded into
    // the trust map. It must NOT become a default arm for unknown issuers.
    let key_a = generate_rsa_key(Some("a-key"));
    let key_b = generate_rsa_key(Some("b-key"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;
    let server_b = start_jwks_server(vec![key_b.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server_a))
        .trusted_issuer(ISS_B, jwks_url(&server_b))
        .build();
    let strategy: JwtStrategy<IssuedClaims> = JwtStrategy::new(config);

    // Signed by the key published at the dangling `jwks_url`, claiming an
    // issuer nobody trusts. If `jwks_url` were used as a fallback this would
    // verify — that is precisely the issuer-confusion vulnerability.
    let token = sign_token(
        &key_a.encoding_key,
        Some("a-key"),
        &issued_claims(Some(ISS_UNTRUSTED), "user-1"),
    );
    let res = strategy
        .authenticate(&bearer_request_parts(&token, None))
        .await
        .expect("authenticate must not fail on unnamed jwks_url");
    assert!(
        res.is_none(),
        "an unnamed jwks_url must never verify a token from an untrusted issuer"
    );

    // The trust map itself still works.
    let token = sign_token(
        &key_b.encoding_key,
        Some("b-key"),
        &issued_claims(Some(ISS_B), "user-1"),
    );
    assert!(strategy
        .authenticate(&bearer_request_parts(&token, None))
        .await
        .expect("authenticate should not error")
        .is_some());
}

#[tokio::test]
async fn multi_issuer_rejects_a_token_claiming_issuer_a_but_signed_with_issuer_bs_key() {
    // Both issuers publish a key under the SAME `kid`, so `kid` lookup cannot be
    // what saves us: the resolver has to pick A's JWKS from `iss`, and the
    // signature then has to fail against A's key.
    let key_a = generate_rsa_key(Some("shared-kid"));
    let key_b = generate_rsa_key(Some("shared-kid"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;
    let server_b = start_jwks_server(vec![key_b.jwk.clone()]).await;

    let token = sign_token(
        &key_b.encoding_key,
        Some("shared-kid"),
        &issued_claims(Some(ISS_A), "attacker"),
    );

    let trust_map = IssuerTrustMap::new()
        .with_issuer(ISS_A, cache_for(&server_a))
        .with_issuer(ISS_B, cache_for(&server_b));

    let err = validate_jwt_with_resolver::<IssuedClaims>(
        &token,
        &trust_map,
        &multi_issuer_validation(&[ISS_A, ISS_B]),
    )
    .await
    .expect_err("a token claiming issuer A but signed with B's key must be rejected");
    match err {
        ValidationError::Jwt(e) => assert!(
            matches!(e.kind(), ErrorKind::InvalidSignature),
            "expected an invalid-signature rejection, got {:?}",
            e.kind()
        ),
        other => panic!("expected a signature failure against issuer A's key, got {other:?}"),
    }

    // Same token, same trust map, through the strategy: no identity.
    let config = ValidationConfig::builder()
        .trusted_issuer(ISS_A, jwks_url(&server_a))
        .trusted_issuer(ISS_B, jwks_url(&server_b))
        .build();
    let strategy: JwtStrategy<IssuedClaims> = JwtStrategy::new(config);
    assert!(
        strategy
            .authenticate(&bearer_request_parts(&token, None))
            .await
            .expect("authenticate should not error")
            .is_none(),
        "cross-issuer key confusion must never yield an identity"
    );
}

#[tokio::test]
async fn multi_issuer_rejects_a_token_with_no_issuer_claim() {
    let key_a = generate_rsa_key(Some("a-key"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;

    // No `iss` at all: nothing names a key, and there is no default.
    let token = sign_token(
        &key_a.encoding_key,
        Some("a-key"),
        &issued_claims(None, "user-1"),
    );

    let trust_map = IssuerTrustMap::new().with_issuer(ISS_A, cache_for(&server_a));
    let err = validate_jwt_with_resolver::<IssuedClaims>(
        &token,
        &trust_map,
        &multi_issuer_validation(&[ISS_A]),
    )
    .await
    .expect_err("a token with no iss must be rejected in multi-issuer mode");
    assert!(
        matches!(err, ValidationError::MissingIssuer),
        "expected MissingIssuer, got {err:?}"
    );
}

#[tokio::test]
async fn the_single_issuer_pair_is_folded_into_the_trust_map_as_one_more_entry() {
    let key_a = generate_rsa_key(Some("a-key"));
    let key_b = generate_rsa_key(Some("b-key"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;
    let server_b = start_jwks_server(vec![key_b.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .issuer(ISS_A)
        .jwks_url(jwks_url(&server_a))
        .trusted_issuer(ISS_B, jwks_url(&server_b))
        .build();
    let strategy: JwtStrategy<IssuedClaims> = JwtStrategy::new(config);

    for (iss, key, kid) in [(ISS_A, &key_a, "a-key"), (ISS_B, &key_b, "b-key")] {
        let token = sign_token(
            &key.encoding_key,
            Some(kid),
            &issued_claims(Some(iss), "user-1"),
        );
        assert!(
            strategy
                .authenticate(&bearer_request_parts(&token, None))
                .await
                .unwrap_or_else(|e| panic!("authenticate should not error for {iss}: {e}"))
                .is_some(),
            "the issuer/jwks_url pair must keep working alongside a trust map"
        );
    }
}

#[tokio::test]
async fn single_issuer_configuration_is_unchanged_by_multi_issuer_support() {
    // Regression guard: with no trust map this is exactly the pre-#243
    // verifier — one JWKS, one accepted issuer.
    let key_a = generate_rsa_key(Some("a-key"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .issuer(ISS_A)
        .jwks_url(jwks_url(&server_a))
        .build();
    assert!(
        config.trusted_issuers.is_empty(),
        "no trust map may be configured unless the caller asked for one"
    );
    let strategy: JwtStrategy<IssuedClaims> = JwtStrategy::new(config);

    let token = sign_token(
        &key_a.encoding_key,
        Some("a-key"),
        &issued_claims(Some(ISS_A), "user-1"),
    );
    let identity = strategy
        .authenticate(&bearer_request_parts(&token, None))
        .await
        .expect("authenticate should not error")
        .expect("a token from the configured issuer must still be accepted");
    assert_eq!(identity.sub, "user-1");

    // A different `iss`, signed by the very key this config trusts, is still
    // rejected by `Validation` — and still as `Ok(None)`, not an error, exactly
    // as before.
    let token = sign_token(
        &key_a.encoding_key,
        Some("a-key"),
        &issued_claims(Some(ISS_UNTRUSTED), "user-1"),
    );
    assert!(
        strategy
            .authenticate(&bearer_request_parts(&token, None))
            .await
            .expect("authenticate should not error")
            .is_none(),
        "a mismatched iss must still be rejected in single-issuer mode"
    );

    // Pre-existing `jsonwebtoken` semantics, unchanged here and pinned so that
    // changing it later is a deliberate act: `iss` is only checked when the
    // claim is present, so a token omitting it entirely is still accepted in
    // single-issuer mode. Multi-issuer mode does NOT inherit this (see
    // `multi_issuer_rejects_a_token_with_no_issuer_claim`), because there `iss`
    // is added to `required_spec_claims`.
    let token = sign_token(
        &key_a.encoding_key,
        Some("a-key"),
        &issued_claims(None, "user-1"),
    );
    let res = strategy
        .authenticate(&bearer_request_parts(&token, None))
        .await
        .expect("authenticate must not error on missing issuer");
    assert!(
        res.is_none(),
        "single-issuer mode now strictly requires the iss claim, failing as Ok(None)"
    );
}

/// A `with_resolver` strategy must still reject a token with no `iss`, even
/// when no static trust map is configured.
///
/// Raised in review of #254. `build_validation` inferred "multi-issuer" from
/// `trusted_issuers` being non-empty, but a `with_resolver` caller resolves
/// issuers dynamically and so configures no map at all — leaving that path with
/// neither `set_issuer` nor `iss` in `required_spec_claims`. Both backstops were
/// off precisely where the docs said they applied, so a resolver lax about
/// `None` would authenticate an issuer-less token.
///
/// The resolver here is deliberately maximally lax: it hands back the same
/// cache whatever the issuer, including `None`. The rejection must therefore
/// come from `Validation`, not from the resolver.
#[tokio::test]
async fn with_resolver_rejects_an_issuerless_token_even_with_no_trust_map() {
    struct AlwaysSame(Arc<JwksCache>);

    #[async_trait::async_trait]
    impl authkestra_resource::jwt::JwksResolver for AlwaysSame {
        async fn resolve(&self, _issuer: Option<&str>) -> Result<Arc<JwksCache>, ValidationError> {
            Ok(self.0.clone())
        }
    }

    let key = generate_rsa_key(Some("a-key"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    // No `iss` at all, signed by a key the resolver will happily hand over.
    let token = sign_token(&key.encoding_key, Some("a-key"), &issued_claims(None, "u"));

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .build();
    let strategy: JwtStrategy<IssuedClaims> =
        JwtStrategy::with_resolver(config, Box::new(AlwaysSame(cache_for(&server))));

    let result = strategy
        .authenticate(&bearer_request_parts(&token, None))
        .await;
    assert!(
        result.is_err() || result.as_ref().is_ok_and(|id| id.is_none()),
        "an iss-less token must not authenticate through a custom resolver, got: {result:?}"
    );
}

/// Pins every documented default of a minimally-configured `ValidationConfig`.
///
/// The security-relevant assertions are `require_cert_binding` and
/// `require_kid`: both are documented as off by default, and flipping either
/// on would silently start *rejecting* tokens that a deployed resource server
/// accepts today — a change that no existing test would otherwise catch,
/// because every other test in this file opts in explicitly. See issue #247.
#[test]
fn builder_defaults_match_documented_behaviour() {
    let config = ValidationConfig::builder()
        .jwks_url("https://issuer.example.com/.well-known/jwks.json")
        .build();

    assert_eq!(
        config.jwks_url,
        "https://issuer.example.com/.well-known/jwks.json"
    );
    assert_eq!(config.refresh_interval, Duration::from_secs(3600));
    assert_eq!(config.issuer, None);
    assert!(config.audience.is_empty());
    assert_eq!(config.algorithms, vec![Algorithm::RS256]);
    assert!(
        !config.require_kid,
        "require_kid must stay off by default: turning it on would reject every token whose \
         header omits `kid`, which validated fine before"
    );
    assert!(
        !config.require_cert_binding,
        "require_cert_binding must stay off by default: turning it on would reject every \
         certificate-bound token not presented over a matching mTLS connection"
    );
    assert!(
        !config.require_dpop,
        "require_dpop must stay off by default: turning it on would reject every DPoP-bound \
         token not presented over the DPoP auth-scheme with a matching proof"
    );
}

// --- RFC 9449 DPoP key-bound (`cnf.jkt`) access token tests — authkestra#274
// Phase C -------------------------------------------------------------------
//
// Covers the same shape of gap #224/cert-binding closed for RFC 8705: a
// token stamped with `cnf.jkt` (see `authkestra-op`'s DPoP `/token` wiring)
// must be rejected by `JwtStrategy::require_dpop` unless the request
// presents a fresh, valid DPoP proof for that same key, bound to this
// specific access token — and, per RFC 9449 §7.1, presented via the `DPoP`
// auth-scheme, never `Bearer`.

/// Claims shape carrying an optional `cnf` confirmation claim, separate from
/// `CertBoundClaims` so a claims payload can be reused verbatim across both
/// binding checks if a future test wants both at once.
#[derive(Debug, Serialize, Deserialize)]
struct DpopBoundClaims {
    sub: String,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<serde_json::Value>,
}

fn dpop_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn dpop_b64_json(v: &serde_json::Value) -> String {
    dpop_b64(serde_json::to_vec(v).unwrap().as_slice())
}

/// Builds a real, genuinely Ed25519-signed DPoP proof. Mirrors the
/// (private, so unreachable from this integration-test binary)
/// `DpopProofBuilder` in `authkestra_resource::jwt`'s own unit tests, and
/// `authkestra_engine::token::dpop`'s before that.
struct DpopProofBuilder {
    signing_key: ed25519_dalek::SigningKey,
    htm: String,
    jti: String,
    ath: Option<String>,
}

impl DpopProofBuilder {
    fn with_key_seed(seed: u8, htm: &str, jti: &str) -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            htm: htm.to_string(),
            jti: jti.to_string(),
            ath: None,
        }
    }

    fn with_ath(mut self, ath: &str) -> Self {
        self.ath = Some(ath.to_string());
        self
    }

    fn jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": dpop_b64(self.signing_key.verifying_key().as_bytes()),
        })
    }

    fn expected_jkt(&self) -> String {
        authkestra_engine::token::dpop::compute_jwk_thumbprint(
            &serde_json::from_value(self.jwk()).unwrap(),
        )
        .unwrap()
    }

    fn build(&self) -> String {
        use ed25519_dalek::Signer;
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": self.jwk(),
        });
        let mut payload = serde_json::json!({
            "htm": self.htm,
            "htu": "https://resource.example.com/protected",
            "iat": chrono::Utc::now().timestamp(),
            "jti": self.jti,
        });
        if let Some(ath) = &self.ath {
            payload["ath"] = serde_json::Value::String(ath.clone());
        }
        let signing_input = format!("{}.{}", dpop_b64_json(&header), dpop_b64_json(&payload));
        let signature = self.signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", dpop_b64(&signature.to_bytes()))
    }
}

/// Builds `http::request::Parts` presenting `token` via the given
/// auth-scheme, with `dpop_proof`, if any, as the `DPoP` header.
fn scheme_request_parts(
    scheme: &str,
    token: &str,
    dpop_proof: Option<&str>,
) -> http::request::Parts {
    let mut builder = Request::builder().header(AUTHORIZATION, format!("{scheme} {token}"));
    if let Some(proof) = dpop_proof {
        builder = builder.header("DPoP", proof);
    }
    let request = builder.body(()).unwrap();
    let (parts, _) = request.into_parts();
    parts
}

#[tokio::test]
async fn dpop_accepts_a_valid_proof_presented_via_the_dpop_scheme() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_dpop(true)
        .build();
    let strategy: JwtStrategy<DpopBoundClaims> = JwtStrategy::new(config).with_dpop_replay_store(
        Arc::new(authkestra_engine::store::memory::MemoryStore::<
            authkestra_resource::dpop::DpopJtiRecord,
        >::new()),
    );

    let proof_builder = DpopProofBuilder::with_key_seed(11, "GET", "jti-e2e-1");
    let claims = DpopBoundClaims {
        sub: "user-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "jkt": proof_builder.expected_jkt() })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let proof = proof_builder
        .with_ath(&x5t_s256_thumbprint(token.as_bytes()))
        .build();
    let parts = scheme_request_parts("DPoP", &token, Some(&proof));

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    let identity = result.expect(
        "a DPoP-bound token, presented via the DPoP scheme with a valid matching proof, must be accepted",
    );
    assert_eq!(identity.sub, "user-a");
}

/// The regression test for the exact gap this whole test module is about:
/// RFC 9449 §7.1 requires a DPoP-bound token be presented via the `DPoP`
/// scheme, never `Bearer` — and before this fix, `authenticate` only ever
/// looked for `Bearer`, so no request shaped the way a spec-compliant DPoP
/// client actually sends one could ever reach the DPoP check at all.
#[tokio::test]
async fn dpop_rejects_a_bound_token_presented_via_the_bearer_scheme() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_dpop(true)
        .build();
    let strategy: JwtStrategy<DpopBoundClaims> = JwtStrategy::new(config).with_dpop_replay_store(
        Arc::new(authkestra_engine::store::memory::MemoryStore::<
            authkestra_resource::dpop::DpopJtiRecord,
        >::new()),
    );

    let proof_builder = DpopProofBuilder::with_key_seed(11, "GET", "jti-e2e-2");
    let claims = DpopBoundClaims {
        sub: "user-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "jkt": proof_builder.expected_jkt() })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    // A genuinely valid proof is attached too — the point of this test is
    // that the *scheme* alone must be enough to refuse it, independent of
    // whether a valid proof also happens to be present.
    let proof = proof_builder
        .with_ath(&x5t_s256_thumbprint(token.as_bytes()))
        .build();
    let parts = scheme_request_parts("Bearer", &token, Some(&proof));

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    assert!(
        result.is_none(),
        "a DPoP-bound token presented via the Bearer scheme must be rejected, even with a \
         genuinely valid DPoP proof attached"
    );
}

#[tokio::test]
async fn dpop_is_not_enforced_when_require_dpop_is_false() {
    // Backward compatibility: a DPoP-bound token is still accepted as a
    // plain bearer token when the resource server has not opted into
    // `require_dpop` — mirrors `cert_binding_is_not_enforced_when_require_
    // cert_binding_is_false` above.
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .build();
    assert!(!config.require_dpop);
    let strategy: JwtStrategy<DpopBoundClaims> = JwtStrategy::new(config);

    let proof_builder = DpopProofBuilder::with_key_seed(11, "GET", "jti-e2e-3");
    let claims = DpopBoundClaims {
        sub: "user-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "jkt": proof_builder.expected_jkt() })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let parts = scheme_request_parts("Bearer", &token, None);

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error")
        .expect("without require_dpop, a DPoP-bound token is still a valid bearer token");
    assert_eq!(result.sub, "user-a");
}

/// The other regression this test module is about: a replay-store outage
/// (or, as here, the fail-closed `NoDpopReplayStore` default) must surface
/// as `Err(AuthError)`, never `Ok(None)`. `Ok(None)` means "this strategy
/// declined, try the next one" under `AuthPolicy::FirstSuccess` — treating
/// an infrastructure failure that way would let a `Guard` chain silently
/// authenticate the request via some other strategy with the DPoP check
/// skipped entirely, rather than surfacing the outage.
#[tokio::test]
async fn dpop_replay_store_outage_surfaces_as_err_not_ok_none() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_dpop(true)
        .build();
    // Deliberately not wiring `with_dpop_replay_store` — this strategy's
    // replay store is the fail-closed `NoDpopReplayStore` default.
    let strategy: JwtStrategy<DpopBoundClaims> = JwtStrategy::new(config);

    let proof_builder = DpopProofBuilder::with_key_seed(11, "GET", "jti-e2e-4");
    let claims = DpopBoundClaims {
        sub: "user-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "jkt": proof_builder.expected_jkt() })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let proof = proof_builder
        .with_ath(&x5t_s256_thumbprint(token.as_bytes()))
        .build();
    let parts = scheme_request_parts("DPoP", &token, Some(&proof));

    let result = strategy.authenticate(&parts).await;
    assert!(
        result.is_err(),
        "no replay store is configured; this must surface as Err(AuthError), not be swallowed \
         as Ok(None)"
    );
}
