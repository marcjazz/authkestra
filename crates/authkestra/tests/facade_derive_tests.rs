//! Issue #332: the state derives must be usable by someone who depends only on
//! the `authkestra` facade.
//!
//! The derives expand to code naming `authkestra_engine`, `axum`/`actix_web`
//! and the adapter crate itself. Emitted as bare paths, those only resolved
//! for a caller with every one of those crates as a direct dependency under
//! exactly those names — so the documented facade-only setup failed with an
//! error naming crates the integrator never wrote down.
//!
//! Every path now hangs off an anchor, and `#[authkestra(crate = ...)]` points
//! that anchor at whatever name the caller reaches the adapter by. These tests
//! are compile-time assertions: if the anchored paths do not resolve through
//! the facade's re-export, the file does not build.
//!
//! What they cannot prove is the absence of the *original* fault, because this
//! crate's own dev-dependencies include the adapters directly, so bare paths
//! would resolve here too. The expansion itself is pinned by the unit tests in
//! `authkestra-macros`, which assert no emitted path escapes the anchor.

#[cfg(feature = "axum")]
mod axum_facade {
    use authkestra::axum::AxumState;

    #[derive(Clone, AxumState)]
    #[authkestra(crate = ::authkestra::axum)]
    struct AppState {
        #[authkestra(engine)]
        auth: authkestra::core::AkWebAppEngine,
    }

    #[test]
    fn the_axum_derive_resolves_through_the_facade() {
        // Reaching the generated `FromRef` impl is what proves the anchored
        // paths resolved; constructing state would need a live session store.
        fn assert_from_ref<T: ::axum::extract::FromRef<AppState>>() {}
        assert_from_ref::<authkestra::core::SessionConfig>();
    }
}

#[cfg(feature = "actix")]
mod actix_facade {
    use authkestra::actix::ActixState;

    #[derive(Clone, ActixState)]
    #[authkestra(crate = ::authkestra::actix)]
    struct AppState {
        #[authkestra(engine)]
        auth: authkestra::core::AkWebAppEngine,
    }

    #[test]
    fn the_actix_derive_resolves_through_the_facade() {
        // `configure_authkestra` is what the derive generates; naming it is
        // enough to prove the anchored paths inside it resolved.
        let _configure: fn(&AppState, &mut ::actix_web::web::ServiceConfig) =
            AppState::configure_authkestra;
    }
}
