//! Integration tests for `authkestra_resource::jwt`, covering:
//! - multi-value audience support on `ValidationConfig` / `ValidationConfigBuilder`
//! - backward compatibility of the single-value `.audience(...)` builder method
//! - opt-in strict `kid` enforcement on `JwksCache`
//! - the documented default values produced by `ValidationConfigBuilder`
//!
//! JWKS is served via a local `wiremock` server and tokens are signed with
//! freshly generated RSA keys so the full offline-validation path (JWKS fetch,
//! key lookup, signature + claim validation) is exercised end to end.

use authkestra_engine::strategy::AuthenticationStrategy;
use authkestra_engine::token::cert_binding::{x5t_s256_thumbprint, ClientCertificateDer};
use authkestra_engine::token::jwk::Jwk;
use authkestra_resource::jwt::{
    validate_jwt_generic, JwksCache, JwtStrategy, ValidationConfig, ValidationError,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::{header::AUTHORIZATION, Request};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header, Validation};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
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
}
