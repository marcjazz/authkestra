//! Resolving the crate path a derive's output hangs off.

use syn::{Attribute, Path};

/// The path the expansion routes every emitted item through.
///
/// Macro output must not depend on what the caller happens to have in scope.
/// Emitting bare `authkestra_engine::` / `axum::` paths meant the derive only
/// compiled for someone with those exact crates as direct dependencies, so a
/// caller depending on the `authkestra` facade — the documented advice — got
/// an error naming a crate they never wrote down (#332).
///
/// The default anchor is the adapter crate the derive was re-exported from,
/// which the caller demonstrably can name. A caller reaching that crate under
/// a different name says so on the struct:
///
/// ```ignore
/// #[derive(Clone, AxumState)]
/// #[authkestra(crate = ::authkestra::axum)]
/// struct AppState { /* ... */ }
/// ```
///
/// Unrecognised keys are left alone: field-level `engine`/`store` share this
/// attribute, and a container may carry keys this function does not own.
pub(crate) fn resolve(attrs: &[Attribute], default: &str) -> syn::Result<Path> {
    let mut anchor = None;

    for attr in attrs {
        if !attr.path().is_ident("authkestra") {
            continue;
        }

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("crate") {
                anchor = Some(meta.value()?.parse::<Path>()?);
            }
            Ok(())
        })?;
    }

    match anchor {
        Some(path) => Ok(path),
        None => syn::parse_str(default),
    }
}
