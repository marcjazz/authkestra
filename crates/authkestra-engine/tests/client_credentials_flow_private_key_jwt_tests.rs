//! Client-side `private_key_jwt` (RFC 7523 §2.2) coverage for
//! `ClientCredentialsFlow`, issue #222.
//!
//! Unit coverage of the assertion's claim shape lives alongside
//! `mint_client_assertion` in `authkestra_engine::client_assertion`; these
//! tests instead exercise `ClientCredentialsFlow::get_token` end-to-end
//! against a mock token endpoint, proving the assertion is actually sent on
//! the wire the way RFC 7523 §2.2 requires.

use authkestra_engine::flow::ClientCredentialsFlow;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{Algorithm, EncodingKey};
use serde_json::Value;
use std::collections::HashMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Throwaway Ed25519 private key (PKCS#8 PEM), test-only. Generated with
/// `openssl genpkey -algorithm ed25519`. Matches the OP's own accepted
/// algorithm derivation for an `OctetKeyPair` JWK
/// (`authkestra_op::client_assertion::assertion_algorithms`).
const TEST_ED25519_PRIVATE_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKIPR2jojpdobYr1M/pjIRuMONpZGYQ+y5yxSqKX9T9/
-----END PRIVATE KEY-----";

/// Parses `application/x-www-form-urlencoded` bytes into a map, so a test
/// can pull out individual form fields without depending on field order.
fn parse_form(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body)
        .into_owned()
        .collect::<HashMap<_, _>>()
}

fn decode_jwt_payload(jwt: &str) -> Value {
    let payload_b64 = jwt.split('.').nth(1).expect("jwt must have 3 segments");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap()
}

fn decode_jwt_header(jwt: &str) -> Value {
    let header_b64 = jwt.split('.').next().expect("jwt must have 3 segments");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap()
}

/// The core acceptance criterion: `get_token` must send
/// `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
/// plus a `client_assertion` JWT in place of `client_secret`, and that JWT
/// must have `iss == sub == client_id`, the token endpoint as `aud`, a
/// `jti`, a bounded `exp`, and the `EdDSA` `alg` the signing key requires.
///
/// Without the change this asserts against, `ClientCredentialsFlow` has no
/// `new_private_key_jwt` constructor at all, so this test fails to compile —
/// which is itself proof the capability did not previously exist.
#[tokio::test]
async fn sends_a_private_key_jwt_assertion_with_the_right_shape() {
    let mock_server = MockServer::start().await;
    let token_url = format!("{}/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-1",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .mount(&mock_server)
        .await;

    let signing_key = EncodingKey::from_ed_pem(TEST_ED25519_PRIVATE_KEY_PEM).unwrap();
    let flow = ClientCredentialsFlow::new_private_key_jwt(
        "svc-1".to_string(),
        signing_key,
        Algorithm::EdDSA,
        token_url.clone(),
    );

    let token = flow
        .get_token(None)
        .await
        .expect("token request must succeed against the mock server");
    assert_eq!(token.access_token, "at-1");

    let received = mock_server
        .received_requests()
        .await
        .expect("request recording must be enabled");
    assert_eq!(received.len(), 1);

    let form = parse_form(&received[0].body);

    // Sent as client_assertion_type + client_assertion, never client_secret.
    assert_eq!(
        form.get("client_assertion_type").map(String::as_str),
        Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    );
    assert!(
        !form.contains_key("client_secret"),
        "private_key_jwt must never also send a client_secret"
    );

    let assertion = form
        .get("client_assertion")
        .expect("client_assertion must be present on the wire");

    let header = decode_jwt_header(assertion);
    assert_eq!(header["alg"], "EdDSA");

    let payload = decode_jwt_payload(assertion);
    assert_eq!(payload["iss"], "svc-1");
    assert_eq!(payload["sub"], "svc-1");
    assert_eq!(payload["aud"], token_url);

    let jti = payload["jti"].as_str().expect("jti must be present");
    assert!(!jti.is_empty());

    let exp = payload["exp"].as_i64().expect("exp must be present");
    let iat = payload["iat"].as_i64().expect("iat must be present");
    assert!(
        exp > iat && exp - iat <= 300,
        "exp must be a bounded, short-lived window (<= 300s per RFC 7523 \
         §3 discipline this workspace's OP enforces), got {}s",
        exp - iat
    );
}

/// A fresh assertion — with a fresh `jti` — must be minted on every call to
/// `get_token`, not cached and replayed: a replay-tracking verifier (this
/// workspace's own `authkestra_op::client_assertion::ClientAssertionStore`)
/// would reject a `jti` it already spent.
#[tokio::test]
async fn mints_a_fresh_assertion_and_jti_on_every_call() {
    let mock_server = MockServer::start().await;
    let token_url = format!("{}/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-1",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .mount(&mock_server)
        .await;

    let signing_key = EncodingKey::from_ed_pem(TEST_ED25519_PRIVATE_KEY_PEM).unwrap();
    let flow = ClientCredentialsFlow::new_private_key_jwt(
        "svc-1".to_string(),
        signing_key,
        Algorithm::EdDSA,
        token_url,
    );

    flow.get_token(None).await.unwrap();
    flow.get_token(None).await.unwrap();

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2);

    let assertion_a = parse_form(&received[0].body)
        .get("client_assertion")
        .unwrap()
        .clone();
    let assertion_b = parse_form(&received[1].body)
        .get("client_assertion")
        .unwrap()
        .clone();

    let jti_a = decode_jwt_payload(&assertion_a)["jti"]
        .as_str()
        .unwrap()
        .to_string();
    let jti_b = decode_jwt_payload(&assertion_b)["jti"]
        .as_str()
        .unwrap()
        .to_string();

    assert_ne!(
        jti_a, jti_b,
        "each token request must mint its own assertion with its own jti"
    );
}

/// `with_kid` must stamp the header `kid` onto the minted assertion, so a
/// server with several registered keys for this client can select the right
/// one (`authkestra_op::client_assertion::select_key`).
#[tokio::test]
async fn with_kid_stamps_the_assertion_header() {
    let mock_server = MockServer::start().await;
    let token_url = format!("{}/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-1",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .mount(&mock_server)
        .await;

    let signing_key = EncodingKey::from_ed_pem(TEST_ED25519_PRIVATE_KEY_PEM).unwrap();
    let flow = ClientCredentialsFlow::new_private_key_jwt(
        "svc-1".to_string(),
        signing_key,
        Algorithm::EdDSA,
        token_url,
    )
    .with_kid("key-1");

    flow.get_token(None).await.unwrap();

    let received = mock_server.received_requests().await.unwrap();
    let assertion = parse_form(&received[0].body)
        .get("client_assertion")
        .unwrap()
        .clone();
    let header = decode_jwt_header(&assertion);
    assert_eq!(header["kid"], "key-1");
}

/// Regression guard: the pre-existing `client_secret` path must be
/// unaffected by the `private_key_jwt` addition — still sends
/// `client_secret`, never a `client_assertion`.
#[tokio::test]
async fn client_secret_flow_is_unaffected() {
    let mock_server = MockServer::start().await;
    let token_url = format!("{}/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-1",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .mount(&mock_server)
        .await;

    let flow = ClientCredentialsFlow::new("svc-1".to_string(), "shh-secret".to_string(), token_url);

    flow.get_token(None).await.unwrap();

    let received = mock_server.received_requests().await.unwrap();
    let form = parse_form(&received[0].body);
    assert_eq!(
        form.get("client_secret").map(String::as_str),
        Some("shh-secret")
    );
    assert!(!form.contains_key("client_assertion"));
    assert!(!form.contains_key("client_assertion_type"));
}
