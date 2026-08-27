use authkestra_engine::token::jwk::Jwk;
use authkestra_engine::OAuthProvider;
use authkestra_oidc::provider::{Claims, OidcProvider};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_oidc_discover_and_auth_url() {
    let mock_server = MockServer::start().await;

    // Mock OIDC Discovery Endpoint
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": mock_server.uri(),
            "authorization_endpoint": format!("{}/authorize", mock_server.uri()),
            "token_endpoint": format!("{}/token", mock_server.uri()),
            "jwks_uri": format!("{}/jwks.json", mock_server.uri()),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        })))
        .mount(&mock_server)
        .await;

    let provider = OidcProvider::discover(
        "test_client".to_string(),
        "test_secret".to_string(),
        "http://localhost/callback".to_string(),
        &mock_server.uri(),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();

    let url = provider.get_authorization_url("state_123", &["profile"], None, Some("nonce_123"));

    assert!(url.contains(&format!("{}/authorize", mock_server.uri())));
    assert!(url.contains("client_id=test_client"));
    assert!(url.contains("response_type=code"));
    assert!(url.contains("state=state_123"));
    assert!(url.contains("nonce=nonce_123"));
    assert!(url.contains("scope=profile%20openid") || url.contains("scope=openid%20profile"));
}

#[tokio::test]
async fn test_oidc_exchange_code() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": mock_server.uri(),
            "authorization_endpoint": format!("{}/authorize", mock_server.uri()),
            "token_endpoint": format!("{}/token", mock_server.uri()),
            "jwks_uri": format!("{}/jwks.json", mock_server.uri()),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [] // For this simple test, we mock a failure or empty JWKS if signature validation is strict, but let's see.
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "acc_tok",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": "id_tok_invalid_sig" // Will fail validation because of empty JWKS, but hits the code path!
        })))
        .mount(&mock_server)
        .await;

    let provider = OidcProvider::discover(
        "test_client".to_string(),
        "test_secret".to_string(),
        "http://localhost/callback".to_string(),
        &mock_server.uri(),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();

    let res = provider
        .exchange_code_for_identity("code123", None, None)
        .await;
    // It should fail to decode the JWT because the signature is invalid/missing,
    // but it exercises the exchange_code_for_identity fn!
    assert!(res.is_err());
}

// --- Regression tests for #225: `Validation::default()` is HS256-only and
// checks neither `iss` nor `aud`, so a real RS256 IdP's ID token was rejected
// on algorithm mismatch before any claim check ran, and a token with a wrong
// `iss`/`aud` would have passed unnoticed (except that HS256-only made the
// aud=None/validate_aud=true combination reject unconditionally). These
// tests sign real RS256 tokens and drive `exchange_code_for_identity`
// through discovery + JWKS + token-endpoint mocks end to end. ---

struct TestKey {
    encoding_key: EncodingKey,
    jwk: Jwk,
}

/// Generates a fresh RSA key pair and wraps it as both a signing key and the
/// public `Jwk` representation that would be published on a JWKS endpoint.
fn generate_rsa_key(kid: &str) -> TestKey {
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
        kid: Some(kid.to_string()),
        kty: "RSA".to_string(),
        alg: Some("RS256".to_string()),
        n: Some(n),
        e: Some(e),
        crv: None,
        x: None,
    };

    TestKey { encoding_key, jwk }
}

fn sign_claims(key: &EncodingKey, kid: &str, claims: &Claims) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(&header, claims, key).expect("failed to sign RS256 ID token")
}

/// Signs an arbitrary JSON payload as an RS256 ID token.
///
/// The `aud`-shape tests below deliberately bypass [`Claims`]: the whole
/// point of #244 is what happens when an IdP puts a JSON *array* on the
/// wire, and building the payload by hand asserts against those bytes
/// rather than against however this crate's own type chooses to serialize.
fn sign_json(key: &EncodingKey, kid: &str, payload: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(&header, payload, key).expect("failed to sign RS256 ID token")
}

fn future_exp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600
}

/// Mounts discovery, JWKS and token-endpoint mocks for `mock_server` and
/// returns a discovered `OidcProvider` plus the RSA key used to sign
/// whatever `id_token` the caller mounts on the `/token` response.
async fn setup_provider(mock_server: &MockServer, client_id: &str) -> (OidcProvider, TestKey) {
    setup_provider_advertising(mock_server, client_id, Some(json!(["RS256"]))).await
}

/// As [`setup_provider`], but lets the caller control what the discovery
/// document advertises in `id_token_signing_alg_values_supported`. `None`
/// omits the field entirely, exercising the RS256 fallback.
async fn setup_provider_advertising(
    mock_server: &MockServer,
    client_id: &str,
    algs: Option<serde_json::Value>,
) -> (OidcProvider, TestKey) {
    let mut discovery = json!({
        "issuer": mock_server.uri(),
        "authorization_endpoint": format!("{}/authorize", mock_server.uri()),
        "token_endpoint": format!("{}/token", mock_server.uri()),
        "jwks_uri": format!("{}/jwks.json", mock_server.uri()),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
    });
    if let Some(algs) = algs {
        discovery["id_token_signing_alg_values_supported"] = algs;
    }

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
        .mount(mock_server)
        .await;

    let key = generate_rsa_key("kid-1");

    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [key.jwk]
        })))
        .mount(mock_server)
        .await;

    let provider = OidcProvider::discover(
        client_id.to_string(),
        "test_secret".to_string(),
        "http://localhost/callback".to_string(),
        &mock_server.uri(),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();

    (provider, key)
}

async fn mount_token_response(mock_server: &MockServer, id_token: &str) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "acc_tok",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token
        })))
        .mount(mock_server)
        .await;
}

#[tokio::test]
async fn rs256_id_token_with_correct_iss_and_aud_verifies() {
    let mock_server = MockServer::start().await;
    let (provider, key) = setup_provider(&mock_server, "test_client").await;

    let claims = Claims {
        sub: "user-123".to_string(),
        iss: mock_server.uri(),    // matches the discovered issuer
        aud: "test_client".into(), // matches client_id
        exp: future_exp(),
        azp: None,
        email: Some("user@example.com".to_string()),
        name: Some("Test User".to_string()),
        picture: None,
        nonce: Some("nonce-123".to_string()),
    };
    let id_token = sign_claims(&key.encoding_key, "kid-1", &claims);
    mount_token_response(&mock_server, &id_token).await;

    let (identity, _token) = provider
        .exchange_code_for_identity("code123", None, Some("nonce-123"))
        .await
        .expect("a correctly-signed RS256 ID token with matching iss/aud must verify");

    assert_eq!(identity.external_id, "user-123");
    assert_eq!(identity.email.as_deref(), Some("user@example.com"));
    // Regression coverage for #225 Defect 5: the verified nonce claim must be
    // surfaced in `attributes["nonce"]` so `OAuth2Flow::finalize_login`'s
    // second nonce check (which reads it back from there) has real data.
    assert_eq!(
        identity.attributes.get("nonce").map(String::as_str),
        Some("nonce-123")
    );
}

#[tokio::test]
async fn rs256_id_token_with_wrong_issuer_is_rejected() {
    let mock_server = MockServer::start().await;
    let (provider, key) = setup_provider(&mock_server, "test_client").await;

    let claims = Claims {
        sub: "user-123".to_string(),
        iss: "https://attacker.example".to_string(), // does NOT match discovered issuer
        aud: "test_client".into(),
        exp: future_exp(),
        azp: None,
        email: None,
        name: None,
        picture: None,
        nonce: None,
    };
    let id_token = sign_claims(&key.encoding_key, "kid-1", &claims);
    mount_token_response(&mock_server, &id_token).await;

    let err = provider
        .exchange_code_for_identity("code123", None, None)
        .await
        .expect_err("an ID token whose iss does not match the discovered issuer must be rejected");
    assert!(matches!(err, authkestra_engine::error::AuthError::Token(_)));
    // Pin down *why* it was rejected: the signature and algorithm are both
    // valid here, so this must be the issuer check, not incidental
    // algorithm-mismatch noise from #225 Defect 2 masking Defect 3.
    assert!(
        err.to_string().contains("InvalidIssuer"),
        "expected an InvalidIssuer rejection, got: {err}"
    );
}

#[tokio::test]
async fn rs256_id_token_with_wrong_audience_is_rejected() {
    let mock_server = MockServer::start().await;
    let (provider, key) = setup_provider(&mock_server, "test_client").await;

    let claims = Claims {
        sub: "user-123".to_string(),
        iss: mock_server.uri(),
        aud: "some_other_client".into(), // does NOT match client_id
        exp: future_exp(),
        azp: None,
        email: None,
        name: None,
        picture: None,
        nonce: None,
    };
    let id_token = sign_claims(&key.encoding_key, "kid-1", &claims);
    mount_token_response(&mock_server, &id_token).await;

    let err = provider
        .exchange_code_for_identity("code123", None, None)
        .await
        .expect_err("an ID token whose aud does not match client_id must be rejected");
    assert!(matches!(err, authkestra_engine::error::AuthError::Token(_)));
    // Pin down *why* it was rejected: the signature and algorithm are both
    // valid here, so this must be the audience check, not incidental
    // algorithm-mismatch noise from #225 Defect 2 masking Defect 4.
    assert!(
        err.to_string().contains("InvalidAudience"),
        "expected an InvalidAudience rejection, got: {err}"
    );
}

/// The algorithm set must come from the discovery document, not from the
/// RS256 fallback. Without this test, deleting the whole
/// `id_token_signing_alg_values_supported` parsing and hardcoding RS256
/// would still pass every other test in this file, because they all
/// advertise RS256 — the same value as the fallback.
///
/// Here discovery advertises ES256 *only*, while the token is signed with
/// RS256. If the advertised list were ignored, this token would verify;
/// it must instead be rejected on algorithm mismatch.
#[tokio::test]
async fn algorithms_come_from_discovery_not_the_rs256_fallback() {
    let mock_server = MockServer::start().await;
    let (provider, key) =
        setup_provider_advertising(&mock_server, "test_client", Some(json!(["ES256"]))).await;

    let claims = Claims {
        sub: "user-123".to_string(),
        iss: mock_server.uri(),
        aud: "test_client".into(),
        exp: future_exp(),
        azp: None,
        email: None,
        name: None,
        picture: None,
        nonce: None,
    };
    let id_token = sign_claims(&key.encoding_key, "kid-1", &claims);
    mount_token_response(&mock_server, &id_token).await;

    let err = provider
        .exchange_code_for_identity("code123", None, None)
        .await
        .expect_err("an RS256 token must be rejected when discovery advertises only ES256");
    assert!(
        err.to_string().contains("InvalidAlgorithm"),
        "expected an InvalidAlgorithm rejection, got: {err}"
    );
}

/// A discovery document that omits `id_token_signing_alg_values_supported`
/// entirely must fall back to RS256 rather than ending up with an empty
/// algorithm list (which would reject everything, or panic on
/// `algorithms[0]`).
#[tokio::test]
async fn omitted_signing_algs_fall_back_to_rs256() {
    let mock_server = MockServer::start().await;
    let (provider, key) = setup_provider_advertising(&mock_server, "test_client", None).await;

    let claims = Claims {
        sub: "user-123".to_string(),
        iss: mock_server.uri(),
        aud: "test_client".into(),
        exp: future_exp(),
        azp: None,
        email: None,
        name: None,
        picture: None,
        nonce: None,
    };
    let id_token = sign_claims(&key.encoding_key, "kid-1", &claims);
    mount_token_response(&mock_server, &id_token).await;

    let (identity, _token) = provider
        .exchange_code_for_identity("code123", None, None)
        .await
        .expect("RS256 must be accepted when discovery omits the algorithm list");
    assert_eq!(identity.external_id, "user-123");
}

/// `with_validation` must actually replace the derived policy. Discovery
/// advertises ES256 only (so the derived default would reject an RS256
/// token, per `algorithms_come_from_discovery_not_the_rs256_fallback`);
/// the override re-permits RS256 and supplies the matching `iss`/`aud`,
/// so the same token now verifies. If the override were ignored, this
/// would fail.
#[tokio::test]
async fn with_validation_overrides_the_derived_policy() {
    let mock_server = MockServer::start().await;
    let (provider, key) =
        setup_provider_advertising(&mock_server, "test_client", Some(json!(["ES256"]))).await;

    let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
    validation.set_issuer(&[mock_server.uri()]);
    validation.set_audience(&["test_client"]);
    let provider = provider.with_validation(validation);

    let claims = Claims {
        sub: "user-123".to_string(),
        iss: mock_server.uri(),
        aud: "test_client".into(),
        exp: future_exp(),
        azp: None,
        email: None,
        name: None,
        picture: None,
        nonce: None,
    };
    let id_token = sign_claims(&key.encoding_key, "kid-1", &claims);
    mount_token_response(&mock_server, &id_token).await;

    let (identity, _token) = provider
        .exchange_code_for_identity("code123", None, None)
        .await
        .expect("with_validation must replace the ES256-only derived policy");
    assert_eq!(identity.external_id, "user-123");
}

// --- Tests for #244: `Claims::aud` was a `String`, so an ID token with an
// array-valued `aud` — the shape Keycloak and Auth0 routinely issue — failed
// inside `jsonwebtoken::decode`'s typed deserialization, which runs *before*
// `validate()` (jsonwebtoken 11.0.0 `decoding.rs:288-289`). The rejection was
// fail-closed, so this was a compatibility gap rather than a vulnerability,
// but it meant #225's "RS256 IdPs like Keycloak can't complete login" still
// held for those deployments. Widening `aud` in turn makes OIDC Core
// §3.1.3.7's `azp` rule reachable, so it is enforced and tested here too. ---

/// The load-bearing test for the `aud` type change: an otherwise perfect
/// RS256 ID token whose `aud` is `["test_client"]` rather than
/// `"test_client"` must verify.
///
/// A single-element array is used on purpose, so this test isolates the
/// deserialization shape and is not entangled with the `azp` rules (which
/// only apply to multiple audiences).
#[tokio::test]
async fn rs256_id_token_with_array_aud_containing_client_id_verifies() {
    let mock_server = MockServer::start().await;
    let (provider, key) = setup_provider(&mock_server, "test_client").await;

    let id_token = sign_json(
        &key.encoding_key,
        "kid-1",
        &json!({
            "sub": "user-123",
            "iss": mock_server.uri(),
            "aud": ["test_client"],
            "exp": future_exp(),
            "email": "user@example.com",
        }),
    );
    mount_token_response(&mock_server, &id_token).await;

    let (identity, _token) = provider
        .exchange_code_for_identity("code123", None, None)
        .await
        .expect("an ID token with an array-valued aud containing client_id must verify");

    assert_eq!(identity.external_id, "user-123");
    assert_eq!(identity.email.as_deref(), Some("user@example.com"));
}

/// The full Keycloak shape: several audiences plus an `azp` naming this
/// client. Must verify.
#[tokio::test]
async fn multi_value_aud_with_matching_azp_verifies() {
    let mock_server = MockServer::start().await;
    let (provider, key) = setup_provider(&mock_server, "test_client").await;

    let id_token = sign_json(
        &key.encoding_key,
        "kid-1",
        &json!({
            "sub": "user-123",
            "iss": mock_server.uri(),
            "aud": ["account", "test_client"],
            "azp": "test_client",
            "exp": future_exp(),
        }),
    );
    mount_token_response(&mock_server, &id_token).await;

    let (identity, _token) = provider
        .exchange_code_for_identity("code123", None, None)
        .await
        .expect("a multi-audience ID token whose azp matches client_id must verify");

    assert_eq!(identity.external_id, "user-123");
}

/// Widening `aud` must not weaken the audience check #225 added: an array
/// that does not list this client is still rejected, by `jsonwebtoken`'s
/// own `InvalidAudience`.
#[tokio::test]
async fn array_aud_not_containing_client_id_is_rejected() {
    let mock_server = MockServer::start().await;
    let (provider, key) = setup_provider(&mock_server, "test_client").await;

    let id_token = sign_json(
        &key.encoding_key,
        "kid-1",
        &json!({
            "sub": "user-123",
            "iss": mock_server.uri(),
            "aud": ["account", "some_other_client"],
            "azp": "some_other_client",
            "exp": future_exp(),
        }),
    );
    mount_token_response(&mock_server, &id_token).await;

    let err = provider
        .exchange_code_for_identity("code123", None, None)
        .await
        .expect_err("an array aud that does not contain client_id must be rejected");
    assert!(matches!(err, authkestra_engine::error::AuthError::Token(_)));
    // Must be the audience check, not the new azp check incidentally
    // catching it — otherwise a regression in `aud` handling could hide
    // behind an `azp` rejection.
    assert!(
        err.to_string().contains("InvalidAudience"),
        "expected an InvalidAudience rejection, got: {err}"
    );
}

/// OIDC Core §3.1.3.7 step 4: with multiple audiences, `azp` must be present.
#[tokio::test]
async fn multi_value_aud_without_azp_is_rejected() {
    let mock_server = MockServer::start().await;
    let (provider, key) = setup_provider(&mock_server, "test_client").await;

    let id_token = sign_json(
        &key.encoding_key,
        "kid-1",
        &json!({
            "sub": "user-123",
            "iss": mock_server.uri(),
            "aud": ["account", "test_client"],
            "exp": future_exp(),
        }),
    );
    mount_token_response(&mock_server, &id_token).await;

    let err = provider
        .exchange_code_for_identity("code123", None, None)
        .await
        .expect_err("a multi-audience ID token without azp must be rejected");
    assert!(
        err.to_string().contains("no azp claim"),
        "expected a missing-azp rejection, got: {err}"
    );
}

/// OIDC Core §3.1.3.7 step 5: with multiple audiences, `azp` must be this
/// client. Here `aud` does contain `test_client`, so `jsonwebtoken`'s
/// audience check passes and only the new `azp` check can reject.
#[tokio::test]
async fn multi_value_aud_with_mismatched_azp_is_rejected() {
    let mock_server = MockServer::start().await;
    let (provider, key) = setup_provider(&mock_server, "test_client").await;

    let id_token = sign_json(
        &key.encoding_key,
        "kid-1",
        &json!({
            "sub": "user-123",
            "iss": mock_server.uri(),
            "aud": ["test_client", "another_client"],
            "azp": "another_client",
            "exp": future_exp(),
        }),
    );
    mount_token_response(&mock_server, &id_token).await;

    let err = provider
        .exchange_code_for_identity("code123", None, None)
        .await
        .expect_err("a multi-audience ID token whose azp is another client must be rejected");
    assert!(
        err.to_string()
            .contains("azp claim does not match client_id"),
        "expected an azp-mismatch rejection, got: {err}"
    );
}

/// Pins the deliberate deviation documented on `verify_authorized_party`:
/// §3.1.3.7 step 5 is a SHOULD, and providers such as Google legitimately
/// issue single-audience tokens whose `azp` names a different (front-end)
/// client. Those must still be accepted — rejecting them would recreate the
/// fail-closed gap #244 exists to close.
#[tokio::test]
async fn single_valued_aud_with_foreign_azp_is_accepted() {
    let mock_server = MockServer::start().await;
    let (provider, key) = setup_provider(&mock_server, "test_client").await;

    let id_token = sign_json(
        &key.encoding_key,
        "kid-1",
        &json!({
            "sub": "user-123",
            "iss": mock_server.uri(),
            "aud": "test_client",
            "azp": "some_frontend_client",
            "exp": future_exp(),
        }),
    );
    mount_token_response(&mock_server, &id_token).await;

    let (identity, _token) = provider
        .exchange_code_for_identity("code123", None, None)
        .await
        .expect("a single-audience token with a foreign azp must still be accepted");
    assert_eq!(identity.external_id, "user-123");
}

/// Regression guard for the serialization side of the `aud` widening: a
/// `Claims` carrying one audience must still go on the wire as a bare JSON
/// string, exactly as it did when the field was a `String`. If
/// `Audience::Single` ever serialized as a one-element array, every token
/// this type has ever produced would change shape.
#[test]
fn single_audience_claims_still_serialize_aud_as_a_bare_string() {
    let claims = Claims {
        sub: "user-123".to_string(),
        iss: "https://issuer.example".to_string(),
        aud: "test_client".into(),
        exp: future_exp(),
        azp: None,
        email: None,
        name: None,
        picture: None,
        nonce: None,
    };

    let value = serde_json::to_value(&claims).expect("Claims must serialize");
    assert_eq!(value["aud"], json!("test_client"));
}
