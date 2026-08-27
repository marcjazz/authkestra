//! Regression tests for issue #246: actix request extensions must be able to
//! reach a custom `AuthenticationStrategy` through the `Auth<I>` extractor.
//!
//! The load-bearing test here deliberately uses `TenantId`, a test-only marker
//! type, **not** `ClientCertificateDer`: before this change the adapter carried
//! exactly one hardcoded type across, so a test written against that type would
//! have passed on the buggy code and proved nothing.
//!
//! Driven through a real `actix_web::App` + `test::call_service`, matching the
//! other integration tests in this crate.

use actix_web::{
    dev::Service as _,
    http::StatusCode,
    test::{self, TestRequest},
    web, App, HttpMessage, HttpResponse, Responder,
};
use async_trait::async_trait;
use authkestra_actix::{Auth, CarriedExtensions};
use authkestra_engine::auth::strategy::AuthenticationStrategy;
use authkestra_engine::auth::AuthError;
use authkestra_engine::token::cert_binding::ClientCertificateDer;
use authkestra_resource::Guard;
use http::request::Parts;
use std::sync::Arc;

/// A test-only extension type standing in for whatever a host application puts
/// in actix's request extensions (tenant id, session context, device identity).
/// Nothing in this repo consumes it, which is the point.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TenantId(String);

/// A second test-only type, registered but never inserted, to check that a
/// missing extension is a quiet no-op rather than an error.
#[derive(Clone, Debug)]
struct NeverInserted;

/// A third test-only type, carried alongside [`TenantId`] so that registering
/// two types that are *both* present is covered — one type succeeding could
/// otherwise mask a registry that only ever applies its first carrier.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestScope(String);

#[derive(Clone, Debug, PartialEq, Eq)]
struct TestIdentity(String);

/// A custom strategy of exactly the kind issue #246 says is broken: it reads a
/// request extension and nothing else.
struct TenantStrategy;

#[async_trait]
impl AuthenticationStrategy<TestIdentity> for TenantStrategy {
    async fn authenticate(&self, parts: &Parts) -> Result<Option<TestIdentity>, AuthError> {
        assert!(
            parts.extensions.get::<NeverInserted>().is_none(),
            "a registered-but-absent type must not be fabricated"
        );
        Ok(parts
            .extensions
            .get::<TenantId>()
            .map(|t| TestIdentity(t.0.clone())))
    }
}

/// Reads `ClientCertificateDer`, which the adapter carries unconditionally so
/// the RFC 8705 resource-side check (#224) keeps working without registration.
struct CertStrategy;

#[async_trait]
impl AuthenticationStrategy<TestIdentity> for CertStrategy {
    async fn authenticate(&self, parts: &Parts) -> Result<Option<TestIdentity>, AuthError> {
        Ok(parts
            .extensions
            .get::<ClientCertificateDer>()
            .map(|c| TestIdentity(format!("cert:{}", c.0.len()))))
    }
}

/// Reads **two** registered types and fails unless both arrived, so a registry
/// that applied only its first carrier would be caught.
struct BothStrategy;

#[async_trait]
impl AuthenticationStrategy<TestIdentity> for BothStrategy {
    async fn authenticate(&self, parts: &Parts) -> Result<Option<TestIdentity>, AuthError> {
        let tenant = parts.extensions.get::<TenantId>();
        let scope = parts.extensions.get::<RequestScope>();
        Ok(match (tenant, scope) {
            (Some(t), Some(s)) => Some(TestIdentity(format!("{}/{}", t.0, s.0))),
            _ => None,
        })
    }
}

async fn whoami(Auth(identity): Auth<TestIdentity>) -> impl Responder {
    HttpResponse::Ok().body(identity.0)
}

fn tenant_guard() -> Arc<Guard<TestIdentity>> {
    Arc::new(Guard::builder().strategy(TenantStrategy).build())
}

fn cert_guard() -> Arc<Guard<TestIdentity>> {
    Arc::new(Guard::builder().strategy(CertStrategy).build())
}

fn both_guard() -> Arc<Guard<TestIdentity>> {
    Arc::new(Guard::builder().strategy(BothStrategy).build())
}

/// Two registered types, both present on the request, must *both* be carried.
///
/// Every other positive test registers types of which only one is ever
/// actually inserted, so a registry that stopped after applying its first
/// carrier would still pass them. This pins that `apply` runs every carrier.
#[actix_web::test]
async fn two_registered_types_are_both_carried() {
    let app = test::init_service(
        App::new()
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(TenantId("acme".to_string()));
                req.extensions_mut()
                    .insert(RequestScope("admin".to_string()));
                srv.call(req)
            })
            .app_data(web::Data::new(both_guard()))
            .app_data(web::Data::new(
                CarriedExtensions::new()
                    .carry::<TenantId>()
                    .carry::<RequestScope>(),
            ))
            .route("/whoami", web::get().to(whoami)),
    )
    .await;

    let resp = test::call_service(&app, TestRequest::get().uri("/whoami").to_request()).await;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "both registered extension types must reach the strategy"
    );
    assert_eq!(test::read_body(resp).await, "acme/admin");
}

/// The regression test for #246. A middleware inserts `TenantId` into actix's
/// request extensions; the host registers that type; the custom strategy must
/// observe it. On unmodified `main` the extension is dropped when `Parts` are
/// hand-built, the strategy sees `None`, and this returns 401.
#[actix_web::test]
async fn custom_extension_type_reaches_a_custom_strategy() {
    let app = test::init_service(
        App::new()
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(TenantId("acme".to_string()));
                srv.call(req)
            })
            .app_data(web::Data::new(tenant_guard()))
            .app_data(web::Data::new(
                CarriedExtensions::new()
                    .carry::<TenantId>()
                    .carry::<NeverInserted>(),
            ))
            .route("/whoami", web::get().to(whoami)),
    )
    .await;

    let resp = test::call_service(&app, TestRequest::get().uri("/whoami").to_request()).await;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "TenantId inserted by middleware did not reach the strategy"
    );
    assert_eq!(test::read_body(resp).await, "acme");
}

/// Same as above but registered via the bare `.app_data(registry)` form rather
/// than `web::Data`, since silently ignoring one of the two would reintroduce
/// exactly the "extension is quietly missing" failure this issue is about.
#[actix_web::test]
async fn registry_also_works_without_web_data_wrapper() {
    let app = test::init_service(
        App::new()
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(TenantId("beta".to_string()));
                srv.call(req)
            })
            .app_data(web::Data::new(tenant_guard()))
            .app_data(CarriedExtensions::new().carry::<TenantId>())
            .route("/whoami", web::get().to(whoami)),
    )
    .await;

    let resp = test::call_service(&app, TestRequest::get().uri("/whoami").to_request()).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await, "beta");
}

/// Carrying is opt-in by type: an extension present on the request but not
/// registered stays behind. Pins the documented contract so it cannot drift
/// into "carries everything" by accident.
#[actix_web::test]
async fn unregistered_extension_type_is_not_carried() {
    let app = test::init_service(
        App::new()
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(TenantId("acme".to_string()));
                srv.call(req)
            })
            .app_data(web::Data::new(tenant_guard()))
            .app_data(web::Data::new(CarriedExtensions::new()))
            .route("/whoami", web::get().to(whoami)),
    )
    .await;

    let resp = test::call_service(&app, TestRequest::get().uri("/whoami").to_request()).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// No registry configured at all must not break: the strategy simply sees no
/// extension.
#[actix_web::test]
async fn missing_registry_is_not_an_error() {
    let app = test::init_service(
        App::new()
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(TenantId("acme".to_string()));
                srv.call(req)
            })
            .app_data(web::Data::new(tenant_guard()))
            .route("/whoami", web::get().to(whoami)),
    )
    .await;

    let resp = test::call_service(&app, TestRequest::get().uri("/whoami").to_request()).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// `ClientCertificateDer` must keep flowing with no registration whatsoever —
/// the RFC 8705 resource-side check (#224) depends on it.
#[actix_web::test]
async fn client_certificate_der_is_still_carried_without_registration() {
    let app = test::init_service(
        App::new()
            .wrap_fn(|req, srv| {
                req.extensions_mut()
                    .insert(ClientCertificateDer(vec![1, 2, 3, 4, 5]));
                srv.call(req)
            })
            .app_data(web::Data::new(cert_guard()))
            .route("/whoami", web::get().to(whoami)),
    )
    .await;

    let resp = test::call_service(&app, TestRequest::get().uri("/whoami").to_request()).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await, "cert:5");
}
