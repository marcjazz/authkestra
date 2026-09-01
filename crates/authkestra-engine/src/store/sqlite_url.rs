//! Classifying SQLite connection strings — not a SQLite store implementation
//! itself (see `store::sql` for that, feature-gated behind `sql-*`), just
//! URL parsing with no `sqlx`/`diesel`/`sea_orm` dependency, so this module
//! is named `sqlite_url` rather than `sqlite` to avoid reading as one.
//!
//! Every SQL-backed `OpStore` example in this workspace
//! (`authkestra-example-diesel`, `authkestra-example-seaorm`) needs the
//! same answer to "is this URL a private, per-connection in-memory
//! database", so it lives here once rather than duplicated in each.
//!
//! Deliberately ungated (unlike `store::sql`) and `pub`: it costs nothing —
//! no new dependency, no feature flag — to expose from an
//! already-mandatory-dependency crate, versus the alternative of
//! duplicating it in each example. The trade-off is that
//! `is_private_memory_url` is now permanent public API of a published
//! crate (`authkestra-engine`) whose only consumers today are two
//! `publish = false` examples — it can't be removed later without a
//! breaking release, so don't casually add more surface here.

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
