//! Test-only helpers shared across this crate's test modules.

use std::io;
use std::sync::{Arc, Mutex};

/// A `MakeWriter` that accumulates everything written to it, so a test can
/// assert on the `tracing` output actually emitted.
///
/// Two reasons this exists rather than each test module rolling its own.
///
/// The first is the property it makes assertable: instrumentation on an
/// authentication path is handed credentials, and "the password never reaches
/// a log line" cannot be checked without capturing what was emitted.
///
/// The second is subtler. `tracing` macros do not evaluate their field
/// expressions when no subscriber is installed, so a field like
/// `ath_bound = expected_ath.is_some()` is never executed under a plain
/// `cargo test` and shows as uncovered however well the surrounding function
/// is exercised. Installing a subscriber makes the instrumentation genuinely
/// run, which is both more honest about coverage and the only way to assert
/// that a log line says what it claims to.
#[derive(Clone, Default)]
pub(crate) struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedLogs {
    /// Everything emitted so far.
    pub(crate) fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Runs `body` with every `tracing` event captured, returning the output.
///
/// The subscriber is installed for the current thread only, so this composes
/// with `#[tokio::test]`'s default current-thread runtime.
pub(crate) fn capture<T>(body: impl FnOnce() -> T) -> (T, String) {
    let captured = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_max_level(tracing::Level::TRACE)
        .without_time()
        .finish();
    let value = tracing::subscriber::with_default(subscriber, body);
    (value, captured.contents())
}
