//! Test-only helpers shared across this crate's test modules.

use std::cell::RefCell;
use std::io;
use std::sync::{Arc, Mutex, Once};

thread_local! {
    /// Where this thread's captured output goes, when it is capturing.
    static SINK: RefCell<Option<Arc<Mutex<Vec<u8>>>>> = const { RefCell::new(None) };
}

/// Routes each thread's `tracing` output to that thread's own buffer, and
/// discards it on threads that are not capturing.
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

/// Installs one process-wide subscriber, once.
///
/// A **global** subscriber rather than a thread-local one, which is the whole
/// point. `tracing` caches callsite interest globally and a thread-local
/// subscriber does not invalidate that cache, so any test that reaches a
/// callsite while no subscriber is installed gets its interest cached as
/// "never" — and a later thread-local capture at that callsite sees nothing,
/// however correctly it installed its subscriber.
///
/// Rebuilding the cache is not enough either: the tests that are not
/// capturing run concurrently and re-cache "never" immediately afterwards.
/// Both were tried, and both produced a capture that passed alone and failed
/// in a parallel run.
///
/// Installed once at `TRACE`, interest is stable for the life of the process,
/// and the per-thread sink decides what is kept.
fn install() {
    INSTALL.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_writer(ThreadSink)
            .with_max_level(tracing::Level::TRACE)
            .without_time()
            .try_init();
    });
}

/// Runs `body` with this thread's `tracing` output captured.
///
/// Capture is per-thread, so this needs no lock and composes with `cargo
/// test`'s parallelism. It does assume `body` emits on the calling thread,
/// which holds for `#[tokio::test]`'s default current-thread runtime.
pub(crate) fn capture<T>(body: impl FnOnce() -> T) -> (T, String) {
    install();

    let buffer = Arc::new(Mutex::new(Vec::new()));
    SINK.with(|sink| *sink.borrow_mut() = Some(Arc::clone(&buffer)));
    let value = body();
    SINK.with(|sink| *sink.borrow_mut() = None);

    let captured = String::from_utf8_lossy(&buffer.lock().unwrap()).into_owned();
    (value, captured)
}
