//! Carrying actix request extensions into the `http::request::Parts` handed to
//! [`AuthenticationStrategy::authenticate`].
//!
//! # Why this module exists at all
//!
//! `authkestra-engine`'s [`AuthenticationStrategy`] is defined over
//! [`http::request::Parts`] (`http` 1.x). axum hands its extractors that exact
//! type, so `authkestra-axum` passes the framework's own `Parts` straight
//! through and nothing is ever lost. actix-web has no such type: its request is
//! an `actix_http::RequestHead` plus a separate `RefCell<Extensions>` map, and
//! actix-http 3.x is still built on `http` **0.2**. So the actix adapter has to
//! *synthesise* an `http` 1.x `Parts` from method + URI + headers, and that
//! synthetic value starts with an empty extension map (issue #246).
//!
//! # Why the whole map cannot simply be copied
//!
//! A fully generic "move/clone every extension across" is not expressible on the
//! pinned versions (`actix-http` 3.13, `http` 1.5). Three independent blockers,
//! any one of which is fatal:
//!
//! 1. **No enumeration.** `actix_http::Extensions` wraps a private
//!    `HashMap<TypeId, Box<dyn Any>>` and exposes only *typed* accessors
//!    (`get::<T>`, `remove::<T>`, `extend(Extensions)`). There is no `iter()`,
//!    no `drain()`, no `IntoIterator`. Nothing outside actix-http can discover
//!    which types a request is carrying.
//! 2. **No `Send`/`Sync`/`Clone` on the values.** Even given enumeration, actix
//!    stores `Box<dyn Any>`, while `http::Extensions` stores
//!    `Box<dyn AnyClone + Send + Sync>` and its only insertion API is
//!    `insert<T: Clone + Send + Sync + 'static>(val: T)`. A type-erased
//!    `Box<dyn Any>` cannot be re-boxed into that; the bounds are unrecoverable
//!    once the concrete type is gone.
//! 3. **Two different `http` crates.** `http` 0.2's `Extensions` and `http`
//!    1.x's `Extensions` are unrelated types from separately-compiled crates,
//!    so even `extend` has nothing to bridge.
//!
//! Storing a handle to actix's map inside the `Parts` instead is equally
//! blocked: `HttpRequest`/`Extensions` are `!Send + !Sync`, and
//! `http::Extensions::insert` requires `Send + Sync`.
//!
//! # What this module does instead
//!
//! Option 2 from issue #246: an explicit, host-registered list of extension
//! *types* to carry. Registration is generic over `T` and monomorphises a
//! transfer function per type, so the adapter never names a concrete extension
//! type — the host decides. See [`CarriedExtensions`].
//!
//! [`AuthenticationStrategy`]: authkestra_engine::auth::AuthenticationStrategy
//! [`AuthenticationStrategy::authenticate`]: authkestra_engine::auth::AuthenticationStrategy::authenticate

use actix_web::dev::Extensions as ActixExtensions;

/// A monomorphised "copy extension of type `T`" step.
///
/// Deliberately a plain `fn` pointer rather than a boxed closure: the transfer
/// is fully determined by `T`, so there is no state to capture, and `fn`
/// pointers keep [`CarriedExtensions`] `Clone + Send + Sync` for free.
///
/// Note `App::app_data` and `HttpRequest::app_data` themselves require only
/// `'static`, not `Send + Sync`; those bounds arrive transitively from
/// `HttpServer::new`'s factory, which must be `Send + Clone` to be moved into
/// each worker. The `fn`-pointer choice is still right — it just isn't
/// `app_data` that forces it.
type Carrier = fn(&ActixExtensions, &mut http::Extensions);

/// The body of a [`Carrier`], monomorphised once per registered type.
///
/// `pub(crate)` rather than private: the [`Auth`](crate::Auth) extractor calls
/// it directly to carry `ClientCertificateDer` unconditionally, without going
/// through the host-visible registry.
pub(crate) fn carry_one<T>(src: &ActixExtensions, dst: &mut http::Extensions)
where
    T: Clone + Send + Sync + 'static,
{
    if let Some(value) = src.get::<T>() {
        dst.insert(value.clone());
    }
}

/// The set of actix request-extension types that must survive into the
/// `http::request::Parts` seen by an [`AuthenticationStrategy`].
///
/// Register it in `app_data` and the [`Auth`](crate::Auth) extractor will copy
/// each listed type out of actix's per-request extension map before calling
/// `Guard::authenticate`. Types not listed are **not** carried — see the module
/// docs for why an automatic carry-everything is impossible here.
///
/// `ClientCertificateDer` is always carried and does not need registering
/// (RFC 8705 certificate-bound tokens depend on it).
///
/// # Example
///
/// ```no_run
/// use actix_web::{web, App, HttpMessage};
/// use authkestra_actix::CarriedExtensions;
///
/// #[derive(Clone)]
/// struct TenantId(String);
///
/// let app = App::new()
///     .wrap_fn(|req, srv| {
///         use actix_web::dev::Service as _;
///         req.extensions_mut().insert(TenantId("acme".to_string()));
///         srv.call(req)
///     })
///     .app_data(web::Data::new(
///         CarriedExtensions::new().carry::<TenantId>(),
///     ));
/// ```
///
/// A strategy can then read `parts.extensions.get::<TenantId>()`.
///
/// # Registration forms and their precedence
///
/// Both `.app_data(web::Data::new(registry))` and the bare
/// `.app_data(registry)` are accepted, because matching only one would turn
/// the other into a silent no-op — the failure mode #246 is about.
///
/// If **both** are present, the `web::Data` form always wins, *even when the
/// bare form is registered on a more specific scope*. `HttpRequest::app_data`
/// scans the whole App → Scope → Resource chain for one type before the
/// fallback is consulted, so an app-level `web::Data` registration takes
/// precedence over a resource-level bare one. Register one form, not both.
///
/// # Feature gate
///
/// This type is only available with the `resource` feature, which is what
/// gates the [`Auth`](crate::Auth) extractor it feeds.
///
/// [`AuthenticationStrategy`]: authkestra_engine::auth::AuthenticationStrategy
#[derive(Clone, Default)]
pub struct CarriedExtensions {
    carriers: Vec<Carrier>,
}

impl CarriedExtensions {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `T` to be carried into `Parts`.
    ///
    /// The `Clone + Send + Sync` bounds are not a design choice — they are
    /// exactly what `http::Extensions::insert` demands. A type that cannot meet
    /// them cannot be put into an `http` 1.x extension map at all, by anyone.
    #[must_use]
    pub fn carry<T>(mut self) -> Self
    where
        T: Clone + Send + Sync + 'static,
    {
        self.carriers.push(carry_one::<T>);
        self
    }

    /// Number of registered types.
    pub fn len(&self) -> usize {
        self.carriers.len()
    }

    /// Whether no type is registered.
    pub fn is_empty(&self) -> bool {
        self.carriers.is_empty()
    }

    /// Run every registered carrier.
    ///
    /// Returns how much the destination map grew, which the caller logs: a
    /// registry with entries but a growth of zero is the signature of a
    /// middleware-ordering mistake, which is otherwise completely silent. It is
    /// a growth count rather than a hit count because a type already present in
    /// `dst` (e.g. `ClientCertificateDer`, carried unconditionally beforehand)
    /// is overwritten rather than added.
    pub(crate) fn apply(&self, src: &ActixExtensions, dst: &mut http::Extensions) -> usize {
        let before = dst.len();
        for carrier in &self.carriers {
            carrier(src, dst);
        }
        dst.len().saturating_sub(before)
    }
}

impl std::fmt::Debug for CarriedExtensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The registered types are erased into `fn` pointers, so there is
        // nothing more informative to print than the count.
        f.debug_struct("CarriedExtensions")
            .field("registered", &self.carriers.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    struct Alpha(&'static str);

    #[derive(Clone, Debug, PartialEq)]
    struct Beta(u8);

    #[test]
    fn carries_only_registered_types() {
        let mut src = ActixExtensions::new();
        src.insert(Alpha("a"));
        src.insert(Beta(7));

        let mut dst = http::Extensions::new();
        let carried = CarriedExtensions::new()
            .carry::<Alpha>()
            .apply(&src, &mut dst);

        assert_eq!(carried, 1);
        assert_eq!(dst.get::<Alpha>(), Some(&Alpha("a")));
        assert_eq!(dst.get::<Beta>(), None);
    }

    #[test]
    fn registered_but_absent_type_is_a_no_op() {
        let src = ActixExtensions::new();
        let mut dst = http::Extensions::new();

        let carried = CarriedExtensions::new()
            .carry::<Alpha>()
            .carry::<Beta>()
            .apply(&src, &mut dst);

        assert_eq!(carried, 0);
        assert!(dst.is_empty());
    }

    #[test]
    fn empty_registry_carries_nothing() {
        let mut src = ActixExtensions::new();
        src.insert(Alpha("a"));
        let mut dst = http::Extensions::new();

        assert!(CarriedExtensions::new().is_empty());
        assert_eq!(CarriedExtensions::new().apply(&src, &mut dst), 0);
        assert!(dst.is_empty());
    }
}
