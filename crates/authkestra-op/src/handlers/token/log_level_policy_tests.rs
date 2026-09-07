//! Holds the #353 log-level policy in place.
//!
//! The policy this crate now follows:
//!
//! - `warn!` — the context is insufficient to determine whether something is
//!   actually wrong.
//! - `error!` — determined, and a registration or deployment must change.
//! - `debug!` — determined, and nothing here needs to change: an ordinary
//!   malformed or unsupported request, which is a 400 for the client's author.
//!
//! Without a test, that policy is a comment. `authkestra-op` carried eighty
//! `warn!` call sites against ten `info!`, so a misbehaving client could fill
//! the warn stream with its own protocol mistakes; nothing stops the levels
//! drifting back the next time a call site is added.

use super::*;
use crate::client::{ClientRegistration, GrantType};
use crate::handlers::token::tests::{test_config, test_tokens};
use crate::store::CompositeOpStore;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::store::KvStore;
use std::cell::RefCell;
use std::io;
use std::sync::{Arc, Mutex, Once};

thread_local! {
    static SINK: RefCell<Option<Arc<Mutex<Vec<u8>>>>> = const { RefCell::new(None) };
}

/// Routes each thread's output to that thread's own buffer.
///
/// A global subscriber with a per-thread sink, for the reason recorded in
/// `authkestra-engine`'s `test_support`: `tracing` caches callsite interest
/// globally, so a thread-local subscriber sees nothing at a callsite any
/// earlier test reached while none was installed.
#[derive(Clone, Copy, Default)]
struct ThreadSink;

impl io::Write for ThreadSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        SINK.with(|sink| {
            if let Some(target) = sink.borrow().as_ref() {
                target.lock().unwrap().extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ThreadSink {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        *self
    }
}

static INSTALL: Once = Once::new();

fn install_subscriber() {
    INSTALL.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_writer(ThreadSink)
            .with_max_level(tracing::Level::TRACE)
            .without_time()
            .try_init();
    });
}

/// A public client permitted exactly `grants`, so a request can get past
/// client resolution and authentication and reach a later branch — or be
/// refused at the grant-authorization check, depending on what is asked for.
async fn client_allowing(grants: Vec<GrantType>) -> MemoryStore<ClientRegistration> {
    let clients = MemoryStore::<ClientRegistration>::new();
    #[allow(deprecated)] // `require_pkce` (authkestra#273) — not exercised here
    clients
        .set(
            "client1",
            ClientRegistration {
                client_id: "client1".to_string(),
                client_secret_hash: None,
                redirect_uris: vec![],
                grant_types: grants,
                scopes: vec![],
                require_pkce: false,
                allowed_audiences: vec![],
                token_endpoint_auth_method: None,
                jwks: None,
            },
            std::time::Duration::from_secs(3600),
        )
        .await
        .unwrap();
    clients
}

async fn registered_client() -> MemoryStore<ClientRegistration> {
    client_allowing(vec![GrantType::RefreshToken]).await
}

/// As [`capture_token_request`], but with the client's permitted grants and
/// the resulting error under the caller's control.
async fn capture_with_client(
    req: TokenRequest,
    grants: Vec<GrantType>,
) -> (Option<String>, String) {
    install_subscriber();

    let buffer = Arc::new(Mutex::new(Vec::new()));
    SINK.with(|sink| *sink.borrow_mut() = Some(Arc::clone(&buffer)));

    let mut store = CompositeOpStore::new(
        client_allowing(grants).await,
        MemoryStore::<crate::code::AuthorizationCode>::new(),
        MemoryStore::<crate::refresh::RefreshToken>::new(),
        MemoryStore::<crate::device::DeviceCodeSession>::new(),
    );
    let outcome = handle_token(req, None, &test_config(true), &mut store, &test_tokens()).await;

    SINK.with(|sink| *sink.borrow_mut() = None);
    let bytes = buffer.lock().unwrap().clone();
    (
        outcome.err().map(|e| e.error),
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

async fn capture_token_request(req: TokenRequest) -> String {
    install_subscriber();

    let buffer = Arc::new(Mutex::new(Vec::new()));
    SINK.with(|sink| *sink.borrow_mut() = Some(Arc::clone(&buffer)));

    let mut store = CompositeOpStore::new(
        registered_client().await,
        MemoryStore::<crate::code::AuthorizationCode>::new(),
        MemoryStore::<crate::refresh::RefreshToken>::new(),
        MemoryStore::<crate::device::DeviceCodeSession>::new(),
    );
    let _ = handle_token(req, None, &test_config(false), &mut store, &test_tokens()).await;

    SINK.with(|sink| *sink.borrow_mut() = None);

    let bytes = buffer.lock().unwrap().clone();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// A request carrying nothing but a grant type — no `client_id`, no
/// credential. `TokenRequest` has no `Default`, so the fields are spelled out
/// as the sibling test modules do.
fn bare_request(grant_type: &str) -> TokenRequest {
    TokenRequest {
        grant_type: grant_type.to_string(),
        code: None,
        device_code: None,
        redirect_uri: None,
        client_id: None,
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

/// A request missing `client_id` is the client's own bug, determined and
/// requiring nothing of this deployment. It must not reach the warn stream:
/// a misbehaving client should not be able to fill it.
#[tokio::test]
async fn a_malformed_request_does_not_warn() {
    let logs = capture_token_request(bare_request("authorization_code")).await;

    assert!(
        logs.contains("Missing client_id in token request"),
        "the refusal should still be visible at debug; got:\n{logs}"
    );
    assert!(
        !logs.contains("WARN"),
        "a client's own malformed request must not raise a warning:\n{logs}"
    );
    assert!(
        !logs.contains("ERROR"),
        "nor an error, since nothing in this deployment needs changing:\n{logs}"
    );
}

/// A second debug case, and one that has to travel: a request naming the
/// refresh-token grant with no `refresh_token` in it. This gets past client
/// resolution and authentication and reaches the refresh handler, so unlike
/// the case above it exercises a branch deep in the flow.
///
/// The first version of this test used an unsupported grant type instead, and
/// was worthless twice over. It carried no `client_id`, so it was rejected as
/// `invalid_client` before grant dispatch and re-tested the case above — and
/// had it reached the dispatch it would have *failed*, because an
/// unregistered custom grant logs "Client not authorized for custom grant",
/// which this same change classifies as `error!`. The premise was wrong, not
/// just the fixture: an unsupported grant type is a determined authorization
/// refusal, not a client's malformed request.
#[tokio::test]
async fn a_missing_grant_parameter_does_not_warn() {
    let mut req = bare_request("refresh_token");
    req.client_id = Some("client1".to_string());

    let logs = capture_token_request(req).await;

    assert!(
        logs.contains("Missing refresh_token in request"),
        "the request must actually reach the refresh handler, not be refused \
         earlier — otherwise this asserts nothing; got:\n{logs}"
    );
    assert!(
        !logs.contains("WARN") && !logs.contains("ERROR"),
        "an incomplete request is the client's own bug:\n{logs}"
    );
}

// --- Grant authorization refusals ---
//
// `codecov/patch` flagged these lines when the levels changed, and every one
// sat on a branch with no test: the OP's check that a client may only use the
// grants it is registered for. For an authorization server that is a security
// property, so these assert the refusal itself and not merely the level.

/// Each grant a client can be refused, with the parameter-complete request
/// that reaches the check.
fn request_for(grant: &str) -> TokenRequest {
    let mut req = bare_request(grant);
    req.client_id = Some("client1".to_string());
    match grant {
        "urn:ietf:params:oauth:grant-type:device_code" => req.device_code = Some("dc".to_string()),
        "refresh_token" => req.refresh_token = Some("rt".to_string()),
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            req.subject_token = Some("st".to_string());
            req.subject_token_type =
                Some("urn:ietf:params:oauth:token-type:access_token".to_string());
        }
        _ => {}
    }
    req
}

/// A client registered for no grant at all is refused every one of them, and
/// the refusal is an `error!` — the registration is what has to change.
#[tokio::test]
async fn a_client_is_refused_every_grant_it_is_not_registered_for() {
    for grant in [
        "authorization_code",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:token-exchange",
    ] {
        let (error, logs) = capture_with_client(request_for(grant), vec![]).await;

        assert_eq!(
            error.as_deref(),
            Some("unauthorized_client"),
            "grant {grant} must be refused for a client not registered for it"
        );
        assert!(
            logs.contains("ERROR"),
            "the refusal is a registration fault and belongs at error; grant \
             {grant} gave:\n{logs}"
        );
        // Not merely "not authorized": the custom-grant arm says that too, so
        // an unrecognised grant string would satisfy a looser assertion while
        // never reaching the branch under test.
        assert!(
            !logs.contains("custom grant"),
            "grant {grant} fell through to the custom-grant arm, so this \
             asserts nothing about its own check:\n{logs}"
        );
    }
}

/// The same requests succeed past the authorization check once the client is
/// registered for the grant — so the assertions above are attributable to the
/// registration and not to the fixture being malformed.
#[tokio::test]
async fn the_same_requests_pass_the_authorization_check_when_registered() {
    for (grant, ty) in [
        (
            "urn:ietf:params:oauth:grant-type:device_code",
            GrantType::DeviceCode,
        ),
        ("refresh_token", GrantType::RefreshToken),
        (
            "urn:ietf:params:oauth:grant-type:token-exchange",
            GrantType::TokenExchange,
        ),
    ] {
        let (error, logs) = capture_with_client(request_for(grant), vec![ty]).await;

        assert_ne!(
            error.as_deref(),
            Some("unauthorized_client"),
            "grant {grant} is registered, so it must not be refused as \
             unauthorized; got:\n{logs}"
        );
        assert!(
            !logs.contains("not authorized"),
            "grant {grant} is registered; nothing should report it otherwise:\n{logs}"
        );
    }
}

/// The missing-parameter branches on the far side of the authorization check.
/// Each is the client's own incomplete request, so each is `debug!`.
///
/// Built by taking the *complete* request and clearing one field, rather than
/// starting from an empty one: token exchange validates `subject_token_type`
/// before `subject_token`, so an empty request never reaches the branch under
/// test — it stops at the earlier check instead.
#[tokio::test]
async fn missing_grant_parameters_are_reported_at_debug() {
    type Clear = fn(&mut TokenRequest);

    let cases: [(&str, GrantType, &str, Clear); 3] = [
        (
            "urn:ietf:params:oauth:grant-type:device_code",
            GrantType::DeviceCode,
            "Missing device_code in request",
            |r| r.device_code = None,
        ),
        (
            "refresh_token",
            GrantType::RefreshToken,
            "Missing refresh_token in request",
            |r| r.refresh_token = None,
        ),
        (
            "urn:ietf:params:oauth:grant-type:token-exchange",
            GrantType::TokenExchange,
            "Missing subject_token in request",
            |r| r.subject_token = None,
        ),
    ];

    for (grant, ty, expected, clear) in cases {
        let mut req = request_for(grant);
        clear(&mut req);

        let (_error, logs) = capture_with_client(req, vec![ty]).await;

        assert!(
            logs.contains(expected),
            "the request must reach the {grant} handler and report {expected:?}; got:\n{logs}"
        );
        assert!(
            !logs.contains("WARN") && !logs.contains("ERROR"),
            "an incomplete request is the client's own bug; {grant} gave:\n{logs}"
        );
    }
}

/// The token endpoint's own client lookup. Distinct from the earlier
/// "no `client_id` at all" case: here one is supplied and is simply not
/// registered, which is determined and means a registration must change.
///
/// Its log line used to read "Unknown client ID during token exchange" while
/// firing for every grant type — a mislabel nothing caught, because the
/// branch had no test.
#[tokio::test]
async fn an_unregistered_client_id_is_refused_at_the_token_endpoint() {
    let mut req = bare_request("client_credentials");
    req.client_id = Some("no-such-client".to_string());

    let (error, logs) = capture_with_client(req, vec![GrantType::ClientCredentials]).await;

    assert_eq!(error.as_deref(), Some("invalid_client"));
    assert!(
        logs.contains("Unknown client ID at the token endpoint"),
        "the refusal should name the endpoint it happened at, not a grant it \
         has nothing to do with; got:\n{logs}"
    );
    assert!(
        !logs.contains("token exchange"),
        "this fires for every grant type and must not claim otherwise:\n{logs}"
    );
}

/// PKCE: a stored code carrying a `code_challenge` cannot be redeemed without
/// a verifier. Left at `debug!` because the request is simply incomplete —
/// the mismatch case, which is a determined tampering signal, is separate and
/// stays at its own level.
#[tokio::test]
async fn redeeming_a_pkce_code_without_a_verifier_is_refused() {
    install_subscriber();

    let clients = client_allowing(vec![GrantType::AuthorizationCode]).await;
    let codes = MemoryStore::<crate::code::AuthorizationCode>::new();

    let mut code = crate::code::AuthorizationCode::new(
        "the-code".to_string(),
        "client1".to_string(),
        "https://app.example.com/cb".to_string(),
        "openid".to_string(),
        authkestra_engine::auth::Identity {
            provider_id: "local".to_string(),
            external_id: "user-123".to_string(),
            email: None,
            username: None,
            attributes: std::collections::HashMap::new(),
        },
        chrono::Utc::now() + chrono::Duration::minutes(10),
        false,
    );
    // Issued under PKCE, so redemption must present the verifier.
    code.code_challenge = Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string());
    code.code_challenge_method = Some("S256".to_string());
    codes
        .set("the-code", code, std::time::Duration::from_secs(600))
        .await
        .unwrap();

    let mut req = bare_request("authorization_code");
    req.client_id = Some("client1".to_string());
    req.code = Some("the-code".to_string());
    req.redirect_uri = Some("https://app.example.com/cb".to_string());
    // `code_verifier` deliberately omitted.

    let buffer = Arc::new(Mutex::new(Vec::new()));
    SINK.with(|sink| *sink.borrow_mut() = Some(Arc::clone(&buffer)));
    let mut store = CompositeOpStore::new(
        clients,
        codes,
        MemoryStore::<crate::refresh::RefreshToken>::new(),
        MemoryStore::<crate::device::DeviceCodeSession>::new(),
    );
    let outcome = handle_token(req, None, &test_config(true), &mut store, &test_tokens()).await;
    SINK.with(|sink| *sink.borrow_mut() = None);
    let logs = String::from_utf8_lossy(&buffer.lock().unwrap().clone()).into_owned();

    assert!(outcome.is_err(), "a PKCE code needs its verifier");
    assert!(
        logs.contains("Missing code_verifier for PKCE-secured code"),
        "the request must reach the PKCE check, not stop earlier; got:\n{logs}"
    );
    assert!(
        !logs.contains("WARN") && !logs.contains("ERROR"),
        "an omitted parameter is the client's own bug:\n{logs}"
    );
}
