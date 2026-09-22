//! Every rejection must name the check that failed, in the logs.
//!
//! A caller sees one flattened `VerifyError`, and the adapters map the whole
//! family onto a single 401 — so over the wire the nineteen ways this can
//! reject are indistinguishable. The log line is the only place the reason
//! exists, which makes it worth asserting rather than assuming (#353).
//!
//! These tests would all have passed before the instrumentation went in, save
//! for the assertions on the log text. That is deliberate: the behaviour did
//! not change, the visibility did.

mod support;

use std::cell::RefCell;
use std::io;
use std::sync::{Arc, Mutex, Once};

use authkestra_devsig::{InMemoryReplayStore, SignedRequest};
use support::{KeyPair, TestSetup};

// Capture, modelled on `authkestra-engine`'s `test_support` — including the
// reason it installs one *global* subscriber rather than a thread-local one:
// `tracing` caches callsite interest globally, so a callsite first reached
// while no subscriber is installed caches as "never" and a later capture at
// that callsite sees nothing however correctly it was set up.
thread_local! {
    static SINK: RefCell<Option<Arc<Mutex<Vec<u8>>>>> = const { RefCell::new(None) };
}

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

fn install() {
    INSTALL.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_writer(ThreadSink)
            .with_max_level(tracing::Level::TRACE)
            // Without this the fields arrive wrapped in escape codes and a
            // plain `contains` on `reason="..."` silently never matches.
            .with_ansi(false)
            .without_time()
            .try_init();
    });
}

/// Captures this thread's tracing output while `body` runs.
async fn capture<F, Fut, T>(body: F) -> (T, String)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    install();
    let buffer = Arc::new(Mutex::new(Vec::new()));
    SINK.with(|sink| *sink.borrow_mut() = Some(Arc::clone(&buffer)));
    let value = body().await;
    SINK.with(|sink| *sink.borrow_mut() = None);
    let captured = String::from_utf8_lossy(&buffer.lock().unwrap()).into_owned();
    (value, captured)
}

fn request<'a>(signature: Option<&'a str>, attestation: Option<&'a str>) -> SignedRequest<'a> {
    SignedRequest {
        signature,
        attestation,
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    }
}

/// A request-binding rejection names itself.
///
/// This is the case the change exists for. Every rejection in `signature.rs`
/// from the request-signature check onward — this one included — emitted
/// nothing before, so the reason existed nowhere: the caller gets a flattened
/// `VerifyError` and the adapters turn the whole family into one 401.
///
/// The signature is minted by the *bound* device key, so the binding check
/// passes and the request fails on the method alone.
#[tokio::test]
async fn a_request_binding_rejection_names_the_check_that_failed() {
    let setup = TestSetup::new().await;
    let signature =
        setup.valid_signature(&setup.device, "GET", "/v1/payments/transfer", None, None);

    let store = InMemoryReplayStore::new();
    let (result, logs) = capture(|| async {
        authkestra_devsig::verify(
            &request(Some(&signature), Some(&setup.valid_attestation())),
            &setup.config,
            &setup.jwks,
            &store,
        )
        .await
    })
    .await;

    assert!(
        result.is_err(),
        "a signature minted for GET must not authorise a POST"
    );
    assert!(
        logs.contains("reason=\"method_mismatch\""),
        "the rejection must name the check that failed; got:\n{logs}"
    );
    assert!(
        logs.contains("device-signature request rejected"),
        "got:\n{logs}"
    );
}

/// Two different rejections must be distinguishable from the logs alone,
/// which is the property that makes them worth emitting. Over HTTP both are
/// the same 401.
#[tokio::test]
async fn different_rejections_are_told_apart() {
    let setup = TestSetup::new().await;
    let store = InMemoryReplayStore::new();

    let (_, missing) = capture(|| async {
        authkestra_devsig::verify(&request(None, None), &setup.config, &setup.jwks, &store).await
    })
    .await;

    let (_, untrusted) = capture(|| async {
        let att = setup.attestation_with_issuer("https://not-the-issuer.example");
        let key = KeyPair::generate_ed25519();
        let sig = setup.valid_signature(&key, "POST", "/v1/payments/transfer", None, None);
        authkestra_devsig::verify(
            &request(Some(&sig), Some(&att)),
            &setup.config,
            &setup.jwks,
            &store,
        )
        .await
    })
    .await;

    assert!(missing.contains("missing_credential"), "got:\n{missing}");
    assert!(
        !missing.contains("untrusted_issuer"),
        "the two must not blur together; got:\n{missing}"
    );
    assert!(untrusted.contains("untrusted_issuer"), "got:\n{untrusted}");
}

/// The credentials are credentials. A rejection log that echoed either would
/// put a live signature — or a reusable attestation — into whatever collects
/// the logs.
#[tokio::test]
async fn a_rejection_never_logs_the_credentials() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let attacker = KeyPair::generate_ed25519();
    let signature = setup.valid_signature(&attacker, "POST", "/v1/payments/transfer", None, None);

    let store = InMemoryReplayStore::new();
    let (_, logs) = capture(|| async {
        authkestra_devsig::verify(
            &request(Some(&signature), Some(&attestation)),
            &setup.config,
            &setup.jwks,
            &store,
        )
        .await
    })
    .await;

    assert!(
        !logs.contains(&signature),
        "the request signature reached the logs"
    );
    assert!(
        !logs.contains(&attestation),
        "the attestation reached the logs"
    );
}
