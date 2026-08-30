//! End-to-end client-authentication tests for `/token`.
//!
//! `client_assertion.rs` covers assertion verification in isolation; what is
//! tested here is the part that only exists at the endpoint: that a
//! registration is bound to exactly one authentication method, and that a
//! `jti` is spent once across the whole request path.

use super::*;
use crate::client::{ClientRegistration, GrantType, TokenEndpointAuthMethod};
use crate::client_assertion::tests::{generate_test_key, good_claims, jwks_of, sign_assertion};
use crate::client_assertion::MemoryClientAssertionStore;
use crate::handlers::token::tests::{test_config, test_tokens};
use crate::store::CompositeOpStore;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::store::KvStore;
use jsonwebtoken::Algorithm;
use serde_json::Value;

const CLIENT_ID: &str = "svc-1";
const SECRET: &str = "correct-horse-battery-staple";

fn hash_secret(secret: &str) -> String {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    argon2::Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn registration(
    method: Option<TokenEndpointAuthMethod>,
    secret_hash: Option<String>,
    jwks: Option<Value>,
) -> ClientRegistration {
    ClientRegistration {
        client_id: CLIENT_ID.to_string(),
        client_secret_hash: secret_hash,
        redirect_uris: vec![],
        grant_types: vec![GrantType::ClientCredentials],
        scopes: vec!["api".to_string()],
        require_pkce: false,
        allowed_audiences: vec![],
        token_endpoint_auth_method: method,
        jwks,
    }
}

/// A `client_credentials` request with no credential attached — each test
/// then adds exactly the one it means to exercise.
fn bare_request() -> TokenRequest {
    TokenRequest {
        grant_type: "client_credentials".to_string(),
        code: None,
        device_code: None,
        redirect_uri: None,
        client_id: Some(CLIENT_ID.to_string()),
        client_secret: None,
        code_verifier: None,
        scope: None,
        refresh_token: None,
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        audience: None,
        client_assertion: None,
        client_assertion_type: None,
        dpop_jkt: None,
    }
}

fn with_assertion(mut req: TokenRequest, assertion: &str) -> TokenRequest {
    req.client_assertion = Some(assertion.to_string());
    req.client_assertion_type = Some(CLIENT_ASSERTION_TYPE_JWT_BEARER.to_string());
    req
}

fn basic_header(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// Builds a store holding `client`, with working replay tracking.
async fn store_with(
    client: ClientRegistration,
) -> CompositeOpStore<
    MemoryStore<ClientRegistration>,
    MemoryStore<crate::code::AuthorizationCode>,
    MemoryStore<crate::refresh::RefreshToken>,
    MemoryStore<crate::device::DeviceCodeSession>,
    MemoryClientAssertionStore,
> {
    let clients = MemoryStore::<ClientRegistration>::new();
    clients
        .set(CLIENT_ID, client, std::time::Duration::from_secs(3600))
        .await
        .unwrap();

    CompositeOpStore::new(
        clients,
        MemoryStore::<crate::code::AuthorizationCode>::new(),
        MemoryStore::<crate::refresh::RefreshToken>::new(),
        MemoryStore::<crate::device::DeviceCodeSession>::new(),
    )
    .with_client_assertion_store(MemoryClientAssertionStore::new())
}

/// The same store, but left with the fail-closed default replay slot.
async fn store_without_replay_protection(
    client: ClientRegistration,
) -> CompositeOpStore<
    MemoryStore<ClientRegistration>,
    MemoryStore<crate::code::AuthorizationCode>,
    MemoryStore<crate::refresh::RefreshToken>,
    MemoryStore<crate::device::DeviceCodeSession>,
> {
    let clients = MemoryStore::<ClientRegistration>::new();
    clients
        .set(CLIENT_ID, client, std::time::Duration::from_secs(3600))
        .await
        .unwrap();

    CompositeOpStore::new(
        clients,
        MemoryStore::<crate::code::AuthorizationCode>::new(),
        MemoryStore::<crate::refresh::RefreshToken>::new(),
        MemoryStore::<crate::device::DeviceCodeSession>::new(),
    )
}

#[tokio::test]
async fn private_key_jwt_client_gets_a_token() {
    let key = generate_test_key(None);
    let store = store_with(registration(
        Some(TokenEndpointAuthMethod::PrivateKeyJwt),
        None,
        Some(jwks_of(&[&key])),
    ))
    .await;

    let assertion = sign_assertion(&key, None, good_claims(), Algorithm::ES256);
    let res = handle_token(
        with_assertion(bare_request(), &assertion),
        None,
        &test_config(false),
        &store,
        &test_tokens(),
    )
    .await;

    assert!(res.is_ok(), "expected a token, got {:?}", res.err());
}

/// The headline property, in the direction that matters most: a client
/// registered for `private_key_jwt` that *also* has a secret hash on file
/// must not be authenticable with that secret. Otherwise the leaked secret of
/// a client that has long since moved to keys is still a way in.
#[tokio::test]
async fn private_key_jwt_client_is_refused_a_valid_client_secret() {
    let key = generate_test_key(None);
    let store = store_with(registration(
        Some(TokenEndpointAuthMethod::PrivateKeyJwt),
        Some(hash_secret(SECRET)),
        Some(jwks_of(&[&key])),
    ))
    .await;

    let mut req = bare_request();
    req.client_secret = Some(SECRET.to_string());

    let err = handle_token(req, None, &test_config(false), &store, &test_tokens())
        .await
        .expect_err("a private_key_jwt client must not be authenticable with its secret");
    assert_eq!(err.error, "invalid_client");

    // ...and the same secret over the Basic transport is no better.
    let err = handle_token(
        bare_request(),
        Some(&basic_header(CLIENT_ID, SECRET)),
        &test_config(false),
        &store,
        &test_tokens(),
    )
    .await
    .expect_err("Basic transport must not be a way around the binding either");
    assert_eq!(err.error, "invalid_client");
}

/// The same property in the other direction: a secret-authenticated client
/// that happens to have a key registered must not be authenticable by signing
/// with it.
#[tokio::test]
async fn client_secret_client_is_refused_a_valid_assertion() {
    let key = generate_test_key(None);
    let store = store_with(registration(
        Some(TokenEndpointAuthMethod::ClientSecretBasic),
        Some(hash_secret(SECRET)),
        Some(jwks_of(&[&key])),
    ))
    .await;

    let assertion = sign_assertion(&key, None, good_claims(), Algorithm::ES256);
    let err = handle_token(
        with_assertion(bare_request(), &assertion),
        None,
        &test_config(false),
        &store,
        &test_tokens(),
    )
    .await
    .expect_err("a client_secret_basic client must not be authenticable by assertion");
    assert_eq!(err.error, "invalid_client");

    // The credential it *is* registered for still works, so the rejection
    // above is about the method and not a broken registration.
    assert!(handle_token(
        bare_request(),
        Some(&basic_header(CLIENT_ID, SECRET)),
        &test_config(false),
        &store,
        &test_tokens(),
    )
    .await
    .is_ok());
}

/// Registrations written before `token_endpoint_auth_method` existed must not
/// silently gain asymmetric authentication just because someone later filled
/// in a `jwks`.
#[tokio::test]
async fn a_registration_without_an_auth_method_is_never_accepted_by_assertion() {
    let key = generate_test_key(None);
    let store = store_with(registration(None, None, Some(jwks_of(&[&key])))).await;

    let assertion = sign_assertion(&key, None, good_claims(), Algorithm::ES256);
    let err = handle_token(
        with_assertion(bare_request(), &assertion),
        None,
        &test_config(false),
        &store,
        &test_tokens(),
    )
    .await
    .expect_err("private_key_jwt must be opted into, never inferred");
    assert_eq!(err.error, "invalid_client");
}

/// Registered for `client_secret_basic`, presenting the right secret over the
/// `client_secret_post` transport. OIDC Core §9 makes those two distinct
/// methods, and the registration named one of them.
#[tokio::test]
async fn the_secret_transport_is_bound_too() {
    let store = store_with(registration(
        Some(TokenEndpointAuthMethod::ClientSecretBasic),
        Some(hash_secret(SECRET)),
        None,
    ))
    .await;

    let mut req = bare_request();
    req.client_secret = Some(SECRET.to_string());

    let err = handle_token(req, None, &test_config(false), &store, &test_tokens())
        .await
        .expect_err("client_secret_post is not client_secret_basic");
    assert_eq!(err.error, "invalid_client");
}

#[tokio::test]
async fn a_replayed_assertion_is_refused() {
    let key = generate_test_key(None);
    let store = store_with(registration(
        Some(TokenEndpointAuthMethod::PrivateKeyJwt),
        None,
        Some(jwks_of(&[&key])),
    ))
    .await;

    let assertion = sign_assertion(&key, None, good_claims(), Algorithm::ES256);

    assert!(handle_token(
        with_assertion(bare_request(), &assertion),
        None,
        &test_config(false),
        &store,
        &test_tokens(),
    )
    .await
    .is_ok());

    let err = handle_token(
        with_assertion(bare_request(), &assertion),
        None,
        &test_config(false),
        &store,
        &test_tokens(),
    )
    .await
    .expect_err("the second presentation of the same assertion is a replay");
    assert_eq!(err.error, "invalid_client");

    // A fresh assertion from the same client still works, so the rejection is
    // about the spent `jti` and not about the client being locked out.
    let mut claims = good_claims();
    claims["jti"] = Value::String("jti-2".to_string());
    let fresh = sign_assertion(&key, None, claims, Algorithm::ES256);
    assert!(handle_token(
        with_assertion(bare_request(), &fresh),
        None,
        &test_config(false),
        &store,
        &test_tokens(),
    )
    .await
    .is_ok());
}

/// Without replay tracking the method cannot be honoured safely, so it is
/// refused outright rather than served with a silently missing guarantee.
#[tokio::test]
async fn assertions_are_refused_when_no_replay_store_is_wired() {
    let key = generate_test_key(None);
    let store = store_without_replay_protection(registration(
        Some(TokenEndpointAuthMethod::PrivateKeyJwt),
        None,
        Some(jwks_of(&[&key])),
    ))
    .await;

    let assertion = sign_assertion(&key, None, good_claims(), Algorithm::ES256);
    let err = handle_token(
        with_assertion(bare_request(), &assertion),
        None,
        &test_config(false),
        &store,
        &test_tokens(),
    )
    .await
    .expect_err("fail closed, do not accept a replayable assertion");
    assert_eq!(err.error, "invalid_client");
}

/// RFC 6749 §2.3: one authentication method per request. A request carrying
/// both must not be resolved by precedence, because precedence is what an
/// attacker with the weaker credential would exploit.
#[tokio::test]
async fn two_credentials_in_one_request_are_refused() {
    let key = generate_test_key(None);
    let store = store_with(registration(
        Some(TokenEndpointAuthMethod::PrivateKeyJwt),
        Some(hash_secret(SECRET)),
        Some(jwks_of(&[&key])),
    ))
    .await;

    let assertion = sign_assertion(&key, None, good_claims(), Algorithm::ES256);
    let mut req = with_assertion(bare_request(), &assertion);
    req.client_secret = Some(SECRET.to_string());

    let err = handle_token(req, None, &test_config(false), &store, &test_tokens())
        .await
        .expect_err("two credentials in one request is a malformed request");
    assert_eq!(err.error, "invalid_request");
}

#[tokio::test]
async fn an_unsupported_client_assertion_type_is_refused() {
    let key = generate_test_key(None);
    let store = store_with(registration(
        Some(TokenEndpointAuthMethod::PrivateKeyJwt),
        None,
        Some(jwks_of(&[&key])),
    ))
    .await;

    let assertion = sign_assertion(&key, None, good_claims(), Algorithm::ES256);
    let mut req = bare_request();
    req.client_assertion = Some(assertion);
    req.client_assertion_type = Some("urn:example:not-a-real-assertion-type".to_string());

    let err = handle_token(req, None, &test_config(false), &store, &test_tokens())
        .await
        .expect_err("only the RFC 7523 jwt-bearer assertion type is accepted");
    assert_eq!(err.error, "invalid_request");
}

/// RFC 7521 §4.2 makes `client_id` optional alongside an assertion; the OP
/// resolves it from the assertion's own `sub`.
#[tokio::test]
async fn client_id_may_be_omitted_alongside_an_assertion() {
    let key = generate_test_key(None);
    let store = store_with(registration(
        Some(TokenEndpointAuthMethod::PrivateKeyJwt),
        None,
        Some(jwks_of(&[&key])),
    ))
    .await;

    let assertion = sign_assertion(&key, None, good_claims(), Algorithm::ES256);
    let mut req = with_assertion(bare_request(), &assertion);
    req.client_id = None;

    assert!(
        handle_token(req, None, &test_config(false), &store, &test_tokens())
            .await
            .is_ok()
    );
}

/// Naming another client in `client_id` selects that client's registration —
/// which the forged assertion then fails against, rather than being verified
/// against the key of the client it claims to be.
#[tokio::test]
async fn an_assertion_cannot_be_pointed_at_another_clients_registration() {
    let victim_key = generate_test_key(None);
    let attacker_key = generate_test_key(None);
    let store = store_with(registration(
        Some(TokenEndpointAuthMethod::PrivateKeyJwt),
        None,
        Some(jwks_of(&[&victim_key])),
    ))
    .await;

    // Signed by a key the victim never registered, but claiming to be them.
    let assertion = sign_assertion(&attacker_key, None, good_claims(), Algorithm::ES256);
    let err = handle_token(
        with_assertion(bare_request(), &assertion),
        None,
        &test_config(false),
        &store,
        &test_tokens(),
    )
    .await
    .expect_err("an assertion must be signed by the named client's registered key");
    assert_eq!(err.error, "invalid_client");
}

/// Public clients, and secret-bearing registrations that present nothing,
/// must behave exactly as they did before this change.
#[tokio::test]
async fn existing_behaviour_is_unchanged_for_registrations_without_a_method() {
    let public = store_with(registration(None, None, None)).await;
    assert!(handle_token(
        bare_request(),
        None,
        &test_config(false),
        &public,
        &test_tokens(),
    )
    .await
    .is_ok());

    let confidential = store_with(registration(None, Some(hash_secret(SECRET)), None)).await;
    let err = handle_token(
        bare_request(),
        None,
        &test_config(false),
        &confidential,
        &test_tokens(),
    )
    .await
    .expect_err("a confidential client presenting nothing is not authenticated");
    assert_eq!(err.error, "invalid_client");

    // Either transport still carries the secret for these registrations,
    // because they never said which one they use.
    let mut post = bare_request();
    post.client_secret = Some(SECRET.to_string());
    assert!(handle_token(
        post,
        None,
        &test_config(false),
        &confidential,
        &test_tokens(),
    )
    .await
    .is_ok());
    assert!(handle_token(
        bare_request(),
        Some(&basic_header(CLIENT_ID, SECRET)),
        &test_config(false),
        &confidential,
        &test_tokens(),
    )
    .await
    .is_ok());
}
