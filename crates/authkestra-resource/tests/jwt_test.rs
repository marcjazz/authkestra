//! Integration tests for `authkestra_resource::jwt`, covering:
//! - multi-value audience support on `ValidationConfig` / `ValidationConfigBuilder`
//! - backward compatibility of the single-value `.audience(...)` builder method
//! - opt-in strict `kid` enforcement on `JwksCache`
//!
//! JWKS is served via a local `wiremock` server and tokens are signed with
//! freshly generated RSA keys so the full offline-validation path (JWKS fetch,
//! key lookup, signature + claim validation) is exercised end to end.

use authkestra_engine::strategy::AuthenticationStrategy;
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

fn sign_token(key: &EncodingKey, kid: Option<&str>, claims: &TestClaims) -> String {
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
