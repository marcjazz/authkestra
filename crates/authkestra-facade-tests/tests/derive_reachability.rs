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
//! These moved here from `crates/authkestra/tests/`, where they could not
//! prove the absence of the original fault: that crate's dev-dependencies name
//! the adapters directly, so the bare paths the bug emitted would have
//! resolved there too. This crate depends on `authkestra` and nothing else
//! from the workspace, so an unanchored path in the expansion fails to
//! resolve here exactly as it did for the reporter. See this crate's
//! `Cargo.toml` for why that distinction is load-bearing.
//!
//! The expansion is separately pinned by unit tests in `authkestra-macros`,
//! which assert no emitted path escapes the anchor at all.

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
