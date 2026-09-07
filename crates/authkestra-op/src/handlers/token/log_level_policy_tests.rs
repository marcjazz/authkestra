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
use crate::handlers::token::tests::{test_config, test_tokens};
use crate::store::CompositeOpStore;
use authkestra_engine::store::memory::MemoryStore;
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

async fn capture_token_request(req: TokenRequest) -> String {
    INSTALL.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_writer(ThreadSink)
            .with_max_level(tracing::Level::TRACE)
            .without_time()
            .try_init();
    });

    let buffer = Arc::new(Mutex::new(Vec::new()));
    SINK.with(|sink| *sink.borrow_mut() = Some(Arc::clone(&buffer)));

    let mut store = CompositeOpStore::new(
        MemoryStore::<authkestra_engine::oauth2::client::ClientRegistration>::new(),
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

/// And an unsupported grant type, the other shape of the same thing.
#[tokio::test]
async fn an_unsupported_grant_type_does_not_warn() {
    let logs = capture_token_request(bare_request("urn:example:no-such-grant")).await;

    assert!(
        !logs.contains("WARN"),
        "an unsupported grant type is a client mistake, not an operator's:\n{logs}"
    );
}
