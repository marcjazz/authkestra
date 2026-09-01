//! Shared helper for SQL-backed `OpStore` examples that support SQLite.
//!
//! Not a conformance test like the other modules in this crate — a small
//! utility both `authkestra-example-diesel` and `authkestra-example-seaorm`
//! need for the exact same reason, factored out here (rather than
//! duplicated in each example) so a future refinement of the URL
//! classification only has to land once.

/// True if `database_url` names a private, per-connection SQLite database —
/// one where a multi-connection pool would scatter a store's rows across
/// several unrelated databases instead of one shared one.
///
/// Covers the bare `:memory:` filename, the URI forms `file::memory:` and
/// `file:name?mode=memory` (SQLite's *named* in-memory database — distinct
/// per name, but still private to the connection that opened it unless
/// shared), and `""` (a private temporary on-disk database — same
/// per-connection isolation). `cache=shared` is the one exception: it puts
/// an in-memory database in SQLite's shared cache instead, which every
/// connection in the process can see, so it does not need — and should not
/// get — the single-connection restriction the other forms do.
pub fn is_private_memory_url(database_url: &str) -> bool {
    let url = database_url.trim();
    if url.is_empty() {
        return true;
    }
    let lower = url.to_ascii_lowercase();
    (lower.contains(":memory:") || lower.contains("mode=memory")) && !lower.contains("cache=shared")
}

#[cfg(test)]
mod tests {
    use super::is_private_memory_url;

    #[test]
    fn bare_memory_filename_is_private() {
        assert!(is_private_memory_url(":memory:"));
    }

    #[test]
    fn empty_url_is_a_private_temporary_database() {
        assert!(is_private_memory_url(""));
        assert!(is_private_memory_url("   "));
    }

    #[test]
    fn file_uri_memory_form_is_private() {
        assert!(is_private_memory_url("file::memory:"));
        assert!(is_private_memory_url("file::memory:?cache=private"));
    }

    #[test]
    fn named_mode_memory_uri_is_private() {
        assert!(is_private_memory_url("file:mydb?mode=memory"));
    }

    #[test]
    fn shared_cache_memory_uri_is_not_private() {
        assert!(!is_private_memory_url("file::memory:?cache=shared"));
        assert!(!is_private_memory_url("file:mydb?mode=memory&cache=shared"));
    }

    #[test]
    fn a_real_file_path_is_not_private() {
        assert!(!is_private_memory_url("/tmp/authkestra-example.sqlite"));
        assert!(!is_private_memory_url("sqlite://data.db"));
    }
}
