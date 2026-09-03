//! Downstream-consumer view of [`DeviceIdentity`]: these tests live outside the crate on
//! purpose, because that is exactly what authkestra#282 reported as impossible — the type is
//! `#[non_exhaustive]`, so no external crate could build one to unit-test its own principal
//! mapping without minting a real attestation and a real signature first.
//!
//! Nothing here verifies anything cryptographically; `DeviceIdentity::new` performs no checks.
//! The real algorithm is covered by `conformance.rs`.

use authkestra_devsig::DeviceIdentity;
use serde_json::{json, Value};

#[test]
fn new_exposes_every_field_to_an_external_crate() {
    let identity = DeviceIdentity::new(
        "usr_1".to_owned(),
        "vk_1".to_owned(),
        "jkt-1".to_owned(),
        json!({ "role": "admin", "kycStatus": "verified" }),
    );

    assert_eq!(identity.subject, "usr_1");
    assert_eq!(identity.device, "vk_1");
    assert_eq!(identity.key_thumbprint, "jkt-1");
    assert_eq!(identity.attributes["role"], "admin");
    assert_eq!(identity.attributes["kycStatus"], "verified");
}

/// A consumer's principal, and the mapping from a verified identity onto it — the shape
/// authkestra#282 described (`vaam-store`'s `ClaimsPrincipalResolver`), reduced to the one rule
/// with real weight.
#[derive(Debug, PartialEq, Eq)]
struct Principal {
    subject: String,
    role: String,
}

fn principal_from(identity: &DeviceIdentity) -> Principal {
    Principal {
        subject: identity.subject.clone(),
        // A missing `role` attribute must fall back to the least-privileged value. Inverting
        // this default is a privilege escalation, which is why it is worth a test.
        role: identity
            .attributes
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("user")
            .to_owned(),
    }
}

#[test]
fn principal_mapping_defaults_a_missing_role_to_user() {
    let identity = DeviceIdentity::new(
        "usr_1".to_owned(),
        "vk_1".to_owned(),
        "jkt-1".to_owned(),
        json!({}),
    );

    assert_eq!(
        principal_from(&identity),
        Principal {
            subject: "usr_1".to_owned(),
            role: "user".to_owned(),
        }
    );
}

#[test]
fn principal_mapping_reads_a_present_role() {
    let identity = DeviceIdentity::new(
        "usr_2".to_owned(),
        "vk_2".to_owned(),
        "jkt-2".to_owned(),
        json!({ "role": "admin" }),
    );

    assert_eq!(principal_from(&identity).role, "admin");
}

/// A non-string `role` is not a string, so the fallback applies: still `"user"`, never anything
/// more privileged.
#[test]
fn principal_mapping_defaults_a_non_string_role_to_user() {
    let identity = DeviceIdentity::new(
        "usr_3".to_owned(),
        "vk_3".to_owned(),
        "jkt-3".to_owned(),
        json!({ "role": 7 }),
    );

    assert_eq!(principal_from(&identity).role, "user");
}
