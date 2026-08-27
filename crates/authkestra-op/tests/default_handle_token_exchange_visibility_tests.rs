//! Proves `authkestra_op::handlers::token::default_handle_token_exchange` is
//! reachable from *outside* the crate, and that a consumer can delegate to
//! it and post-process the result instead of reimplementing the RFC 8693
//! validation (subject-token validation, audience binding, scope
//! intersection, `subject_token_type`/`requested_token_type` checks) that
//! already lives inside it.
//!
//! Being an integration test (a separate compilation unit under `tests/`,
//! not `#[cfg(test)] mod tests` inside the crate), `pub(crate)` visibility on
//! the function is genuinely enforced here: this file would fail to
//! *compile* against the crate as published prior to this change, because
//! `default_handle_token_exchange` was not part of the crate's public API.

use std::collections::HashMap;

use authkestra_engine::auth::state::Identity;
use authkestra_engine::token::TokenManager;
use authkestra_op::client::{ClientRegistration, GrantType};
use authkestra_op::config::OpConfig;
use authkestra_op::handlers::token::TokenRequest;

fn test_tokens() -> TokenManager {
    TokenManager::new(b"super_secret_key_that_is_long_enough_for_hmac", None)
}

fn test_identity() -> Identity {
    Identity {
        provider_id: "test".to_string(),
        external_id: "user123".to_string(),
        username: Some("user123".to_string()),
        email: None,
        attributes: HashMap::new(),
    }
}

fn test_config() -> OpConfig {
    OpConfig {
        issuer: "https://issuer.example.com".to_string(),
        scopes_supported: vec!["profile".to_string()],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["urn:ietf:params:oauth:grant-type:token-exchange".to_string()],
        id_token_signing_alg: "RS256".to_string(),
        authorization_code_ttl_secs: 60,
        access_token_ttl_secs: 3600,
        device_code_ttl_secs: 1800,
        token_exchange_enabled: true,
    }
}

fn test_client() -> ClientRegistration {
    ClientRegistration {
        client_id: "client1".to_string(),
        client_secret_hash: None,
        redirect_uris: vec![],
        grant_types: vec![GrantType::TokenExchange],
        scopes: vec!["profile".to_string()],
        require_pkce: false,
        allowed_audiences: vec![],
        token_endpoint_auth_method: None,
        jwks: None,
    }
}

fn exchange_request(subject_token: &str) -> TokenRequest {
    serde_json::from_value(serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": "client1",
        "subject_token": subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token"
    }))
    .unwrap()
}

#[tokio::test]
async fn op_store_override_can_delegate_to_default_and_post_process() {
    let tokens = test_tokens();
    let identity = test_identity();
    let subject_token = tokens
        .issue_user_token(
            identity.clone(),
            3600,
            Some("profile".to_string()),
            Some("client1".to_string()),
        )
        .unwrap();

    let config = test_config();
    let client = test_client();
    let req = exchange_request(&subject_token);

    // This is the seam #204/#208 added: an `OpStore::handle_token_exchange`
    // override delegating to the built-in default and post-processing the
    // result, instead of hand-reimplementing every RFC 8693 check the
    // default already performs. Success here proves the default ran the
    // real validation (subject-token signature, audience binding, scope
    // intersection) against a request only a passing exchange satisfies.
    let default_resp = authkestra_op::handlers::token::default_handle_token_exchange(
        req,
        "client1".to_string(),
        client,
        &config,
        &tokens,
    )
    .await
    .expect("a valid exchange request should be accepted by the built-in default");

    assert_eq!(default_resp.scope.as_deref(), Some("profile"));

    // Post-process: stamp an extra claim the default alone never adds (the
    // downstream motivation cited in the issue — `issue_user_token_with_extra`
    // exists precisely for this, but the default has no way to reach it).
    let mut extra = HashMap::new();
    extra.insert("post_processed".to_string(), serde_json::Value::Bool(true));
    let post_processed_token = tokens
        .issue_user_token_with_extra(
            identity,
            3600,
            default_resp.scope.clone(),
            Some(config.issuer.clone()),
            extra,
        )
        .unwrap();

    assert_ne!(post_processed_token, default_resp.access_token);
}
