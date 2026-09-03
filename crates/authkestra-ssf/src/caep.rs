//! Typed [OpenID Continuous Access Evaluation Profile (CAEP) 1.0](https://openid.net/specs/openid-caep-specification-1_0.html)
//! events, decoded out of a SET's `events` claim.
//!
//! CAEP is the application of the Shared Signals Framework to access security: a transmitter
//! signals that something about a subject changed — the session was revoked, a credential was
//! rotated, the device fell out of compliance — and the receiver decides what to do about it.
//! This module is the "what was signalled" half only; acting on it (session revocation,
//! middleware enforcement) is deliberately out of scope here, see the crate-level docs.
//!
//! Field names and their required/optional status come from CAEP 1.0 §2 (claims common to every
//! event) and §3.1–§3.5 (the event-specific claims).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::subject::SubjectIdentifier;

/// The base URI every CAEP 1.0 event type is built from (CAEP 1.0 §3).
pub const CAEP_EVENT_TYPE_PREFIX: &str = "https://schemas.openid.net/secevent/caep/event-type/";

/// Event Type URI for Session Revoked (CAEP 1.0 §3.1).
pub const EVENT_TYPE_SESSION_REVOKED: &str =
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
/// Event Type URI for Token Claims Change (CAEP 1.0 §3.2).
pub const EVENT_TYPE_TOKEN_CLAIMS_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change";
/// Event Type URI for Credential Change (CAEP 1.0 §3.3).
pub const EVENT_TYPE_CREDENTIAL_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/credential-change";
/// Event Type URI for Assurance Level Change (CAEP 1.0 §3.4).
pub const EVENT_TYPE_ASSURANCE_LEVEL_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";
/// Event Type URI for Device Compliance Change (CAEP 1.0 §3.5).
pub const EVENT_TYPE_DEVICE_COMPLIANCE_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change";

/// An event payload named a CAEP event type but did not conform to that type's definition.
///
/// Kept distinct from "unknown event type": an unknown type is preserved as
/// [`CaepEvent::Unknown`], whereas a *known* type with a malformed payload is exactly what
/// RFC 8935 §2.4's `invalid_request` describes ("the Event Payload within the SET does not
/// conform to the event's definition") and must be reported, not silently downgraded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("event payload for {uri} does not conform to its CAEP 1.0 definition: {message}")]
pub struct EventDecodeError {
    uri: String,
    message: String,
}

impl EventDecodeError {
    /// Builds a decode error for `uri` with a human-readable `message`.
    pub fn new(uri: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            message: message.into(),
        }
    }

    /// The event type URI whose payload failed to decode.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The underlying reason, as reported by the JSON decoder.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Generates a CAEP string-valued enum with an `Other(String)` escape hatch.
///
/// CAEP 1.0 spells most of these as "MUST be one of the following strings", but a receiver that
/// hard-errors on an unrecognised value would reject a whole SET — including the events it *does*
/// understand — because a transmitter added a value in a later profile revision. Preserving the
/// raw string keeps the decision about what to do with it where it belongs: with the handler.
macro_rules! caep_string_enum {
    (
        $(#[$meta:meta])*
        $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $wire:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
            /// A value CAEP 1.0 does not define, preserved verbatim.
            Other(String),
        }

        impl $name {
            /// The on-the-wire string for this value.
            pub fn as_str(&self) -> &str {
                match self {
                    $( $name::$variant => $wire, )+
                    $name::Other(raw) => raw.as_str(),
                }
            }
        }

        impl From<&str> for $name {
            fn from(raw: &str) -> Self {
                match raw {
                    $( $wire => $name::$variant, )+
                    other => $name::Other(other.to_string()),
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Ok($name::from(raw.as_str()))
            }
        }
    };
}

caep_string_enum! {
    /// The entity that invoked an event (CAEP 1.0 §2, `initiating_entity`).
    InitiatingEntity {
        /// An administrative action triggered the event.
        Admin => "admin",
        /// An end-user action triggered the event.
        User => "user",
        /// A policy evaluation triggered the event.
        Policy => "policy",
        /// A system or platform assertion triggered the event.
        System => "system",
    }
}

caep_string_enum! {
    /// The kind of credential a Credential Change event is about (CAEP 1.0 §3.3.1,
    /// `credential_type`). The spec explicitly allows "any other credential type supported
    /// mutually by the Transmitter and the Receiver", so `Other` is not merely defensive here.
    CredentialType {
        /// A password.
        Password => "password",
        /// A PIN.
        Pin => "pin",
        /// An X.509 certificate.
        X509 => "x509",
        /// A platform FIDO2 authenticator.
        Fido2Platform => "fido2-platform",
        /// A roaming FIDO2 authenticator.
        Fido2Roaming => "fido2-roaming",
        /// A FIDO U2F authenticator.
        FidoU2f => "fido-u2f",
        /// A verifiable credential.
        VerifiableCredential => "verifiable-credential",
        /// Voice call to a phone number.
        PhoneVoice => "phone-voice",
        /// SMS to a phone number.
        PhoneSms => "phone-sms",
        /// An authenticator application.
        App => "app",
    }
}

caep_string_enum! {
    /// What happened to the credential (CAEP 1.0 §3.3.1, `change_type`).
    ChangeType {
        /// The credential was created.
        Create => "create",
        /// The credential was revoked.
        Revoke => "revoke",
        /// The credential was updated.
        Update => "update",
        /// The credential was deleted.
        Delete => "delete",
    }
}

caep_string_enum! {
    /// A NIST SP 800-63R3 Authenticator Assurance Level (CAEP 1.0 §3.4.1).
    AssuranceLevel {
        /// NIST AAL1.
        Aal1 => "nist-aal1",
        /// NIST AAL2.
        Aal2 => "nist-aal2",
        /// NIST AAL3.
        Aal3 => "nist-aal3",
    }
}

caep_string_enum! {
    /// Whether an assurance level went up or down (CAEP 1.0 §3.4.1, `change_direction`).
    ChangeDirection {
        /// The assurance level increased.
        Increase => "increase",
        /// The assurance level decreased.
        Decrease => "decrease",
    }
}

caep_string_enum! {
    /// A device compliance status (CAEP 1.0 §3.5.1).
    ComplianceStatus {
        /// The device is compliant with policy.
        Compliant => "compliant",
        /// The device is not compliant with policy.
        NotCompliant => "not-compliant",
    }
}

/// A localizable message: BCP 47 language tag to locale-specific text (CAEP 1.0 §2,
/// `reason_admin` / `reason_user`).
pub type LocalizedMessage = BTreeMap<String, String>;

/// The claims CAEP 1.0 §2 defines for every event type, all optional unless an event definition
/// says otherwise.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CaepMetadata {
    /// When the event described by this SET occurred, as seconds since the Unix epoch.
    ///
    /// Distinct from the SET's own `iat` (when the token was minted) and from `toe` (the SET's
    /// own time-of-event claim): each event in a multi-event SET carries its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_timestamp: Option<i64>,

    /// The entity that invoked the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiating_entity: Option<InitiatingEntity>,

    /// A localizable administrative message intended for logging and auditing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_admin: Option<LocalizedMessage>,

    /// A localizable user-friendly message for display to an end user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_user: Option<LocalizedMessage>,

    /// The event's own subject.
    ///
    /// Not in CAEP 1.0 §2's list, but every example in §3.1.2–§3.5.2 puts a `subject` member in
    /// the event payload, and RFC 8417 §2.2 explicitly allows a profile to "convey event subject
    /// information in the event payload". A receiver that only looked at the SET's `sub_id`
    /// would miss the subject of every real-world CAEP event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<SubjectIdentifier>,

    /// Any other member of the event payload, preserved so a handler can read members from a
    /// profile this crate does not model.
    #[serde(flatten)]
    pub additional: Map<String, Value>,
}

/// Session Revoked (CAEP 1.0 §3.1): the session identified by the subject has been revoked.
///
/// Has no event-specific claims — the subject *is* the payload. When `event_timestamp` is
/// present it is the time the revocation occurred.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionRevoked {
    /// Claims common to every CAEP event.
    #[serde(flatten)]
    pub metadata: CaepMetadata,
}

/// Token Claims Change (CAEP 1.0 §3.2): a claim in a token identified by the subject changed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TokenClaimsChange {
    /// REQUIRED: one or more claims with their new value(s).
    pub claims: Map<String, Value>,
    /// Claims common to every CAEP event.
    #[serde(flatten)]
    pub metadata: CaepMetadata,
}

/// Credential Change (CAEP 1.0 §3.3): a credential was created, changed, revoked or deleted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CredentialChange {
    /// REQUIRED: the kind of credential that changed.
    pub credential_type: CredentialType,
    /// REQUIRED: what happened to it.
    pub change_type: ChangeType,
    /// OPTIONAL: credential friendly name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    /// OPTIONAL: issuer of the X.509 certificate (RFC 5280).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_issuer: Option<String>,
    /// OPTIONAL: serial number of the X.509 certificate (RFC 5280).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_serial: Option<String>,
    /// OPTIONAL: FIDO2 Authenticator Attestation GUID (WebAuthn).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fido2_aaguid: Option<String>,
    /// Claims common to every CAEP event.
    #[serde(flatten)]
    pub metadata: CaepMetadata,
}

/// Assurance Level Change (CAEP 1.0 §3.4): the authentication method changed since login.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AssuranceLevelChange {
    /// REQUIRED: the current NIST AAL.
    pub current_level: AssuranceLevel,
    /// REQUIRED: the previous NIST AAL.
    pub previous_level: AssuranceLevel,
    /// REQUIRED: whether the level increased or decreased.
    pub change_direction: ChangeDirection,
    /// Claims common to every CAEP event.
    #[serde(flatten)]
    pub metadata: CaepMetadata,
}

/// Device Compliance Change (CAEP 1.0 §3.5): a device's compliance status changed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeviceComplianceChange {
    /// REQUIRED: the compliance status prior to the change.
    pub previous_status: ComplianceStatus,
    /// REQUIRED: the status that triggered the event.
    pub current_status: ComplianceStatus,
    /// Claims common to every CAEP event.
    #[serde(flatten)]
    pub metadata: CaepMetadata,
}

impl CaepMetadata {
    /// An empty set of common claims.
    ///
    /// **Exists so consumers can construct one in their own tests.** A `#[non_exhaustive]` claims
    /// bag with no constructor cannot be built downstream at all, which is the problem reported
    /// against `authkestra-devsig`'s `DeviceIdentity` in
    /// [authkestra#282](https://github.com/marcjazz/authkestra/issues/282). It performs **no
    /// validation**: these claims are all OPTIONAL per CAEP 1.0 §2, so an empty bag is
    /// a legal, if uninformative, value.
    pub fn empty() -> Self {
        Self::default()
    }
}

impl TokenClaimsChange {
    /// Builds a Token Claims Change event carrying `claims` (CAEP 1.0 §3.2.1: REQUIRED).
    ///
    /// **Exists so consumers can construct one in their own tests.** A `#[non_exhaustive]` event
    /// type with no constructor cannot be built downstream at all, which is the problem reported
    /// against `authkestra-devsig`'s `DeviceIdentity` in
    /// [authkestra#282](https://github.com/marcjazz/authkestra/issues/282). It performs **no
    /// validation**: an event a receiver should act on comes out of [`CaepEvent::decode`] behind
    /// [`crate::SetVerifier`], never out of this constructor.
    pub fn new(claims: Map<String, Value>) -> Self {
        Self {
            claims,
            metadata: CaepMetadata::default(),
        }
    }
}

impl CredentialChange {
    /// Builds a Credential Change event from the two claims CAEP 1.0 §3.3.1 makes REQUIRED.
    ///
    /// **Exists so consumers can construct one in their own tests.** A `#[non_exhaustive]` event
    /// type with no constructor cannot be built downstream at all, which is the problem reported
    /// against `authkestra-devsig`'s `DeviceIdentity` in
    /// [authkestra#282](https://github.com/marcjazz/authkestra/issues/282). It performs **no
    /// validation**: an event a receiver should act on comes out of [`CaepEvent::decode`] behind
    /// [`crate::SetVerifier`], never out of this constructor.
    pub fn new(credential_type: CredentialType, change_type: ChangeType) -> Self {
        Self {
            credential_type,
            change_type,
            friendly_name: None,
            x509_issuer: None,
            x509_serial: None,
            fido2_aaguid: None,
            metadata: CaepMetadata::default(),
        }
    }
}

impl AssuranceLevelChange {
    /// Builds an Assurance Level Change event from the three claims CAEP 1.0 §3.4.1 makes
    /// REQUIRED.
    ///
    /// **Exists so consumers can construct one in their own tests.** A `#[non_exhaustive]` event
    /// type with no constructor cannot be built downstream at all, which is the problem reported
    /// against `authkestra-devsig`'s `DeviceIdentity` in
    /// [authkestra#282](https://github.com/marcjazz/authkestra/issues/282). It performs **no
    /// validation**: an event a receiver should act on comes out of [`CaepEvent::decode`] behind
    /// [`crate::SetVerifier`], never out of this constructor.
    ///
    /// Note in particular that nothing here checks that `change_direction` agrees with the two
    /// levels: a transmitter that sends `increase` alongside a decrease is describing something
    /// self-contradictory, and it is the receiver's policy, not this type, that decides what to
    /// do about it.
    pub fn new(
        current_level: AssuranceLevel,
        previous_level: AssuranceLevel,
        change_direction: ChangeDirection,
    ) -> Self {
        Self {
            current_level,
            previous_level,
            change_direction,
            metadata: CaepMetadata::default(),
        }
    }
}

impl DeviceComplianceChange {
    /// Builds a Device Compliance Change event from the two claims CAEP 1.0 §3.5.1 makes
    /// REQUIRED.
    ///
    /// **Exists so consumers can construct one in their own tests.** A `#[non_exhaustive]` event
    /// type with no constructor cannot be built downstream at all, which is the problem reported
    /// against `authkestra-devsig`'s `DeviceIdentity` in
    /// [authkestra#282](https://github.com/marcjazz/authkestra/issues/282). It performs **no
    /// validation**: an event a receiver should act on comes out of [`CaepEvent::decode`] behind
    /// [`crate::SetVerifier`], never out of this constructor.
    pub fn new(previous_status: ComplianceStatus, current_status: ComplianceStatus) -> Self {
        Self {
            previous_status,
            current_status,
            metadata: CaepMetadata::default(),
        }
    }
}

/// One decoded entry of a SET's `events` claim.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CaepEvent {
    /// [`EVENT_TYPE_SESSION_REVOKED`].
    SessionRevoked(SessionRevoked),
    /// [`EVENT_TYPE_TOKEN_CLAIMS_CHANGE`].
    TokenClaimsChange(TokenClaimsChange),
    /// [`EVENT_TYPE_CREDENTIAL_CHANGE`].
    CredentialChange(CredentialChange),
    /// [`EVENT_TYPE_ASSURANCE_LEVEL_CHANGE`].
    AssuranceLevelChange(AssuranceLevelChange),
    /// [`EVENT_TYPE_DEVICE_COMPLIANCE_CHANGE`].
    DeviceComplianceChange(DeviceComplianceChange),
    /// An event type this crate does not model — another CAEP revision, a RISC event, a SCIM
    /// event, or a vendor extension.
    ///
    /// Preserved rather than dropped: RFC 8417 §2.2 lets any URI name an event, receivers are
    /// free to ignore events they do not care about (RFC 8935 §3), and a SET that mixes one
    /// known event with one unknown one must still deliver the known one. A handler that
    /// understands the URI can parse `payload` itself.
    Unknown {
        /// The event type URI, exactly as it appeared in the `events` claim.
        uri: String,
        /// The untouched event payload.
        payload: Value,
    },
}

impl CaepEvent {
    /// Decodes one `events` entry.
    ///
    /// Returns `Err` only when `uri` names an event type this crate models *and* the payload
    /// does not match its definition; an unrecognised `uri` yields [`CaepEvent::Unknown`].
    pub fn decode(uri: &str, payload: &Value) -> Result<Self, EventDecodeError> {
        fn parse<T: serde::de::DeserializeOwned>(
            uri: &str,
            payload: &Value,
        ) -> Result<T, EventDecodeError> {
            serde_json::from_value(payload.clone())
                .map_err(|err| EventDecodeError::new(uri, err.to_string()))
        }

        let event = match uri {
            EVENT_TYPE_SESSION_REVOKED => CaepEvent::SessionRevoked(parse(uri, payload)?),
            EVENT_TYPE_TOKEN_CLAIMS_CHANGE => CaepEvent::TokenClaimsChange(parse(uri, payload)?),
            EVENT_TYPE_CREDENTIAL_CHANGE => CaepEvent::CredentialChange(parse(uri, payload)?),
            EVENT_TYPE_ASSURANCE_LEVEL_CHANGE => {
                CaepEvent::AssuranceLevelChange(parse(uri, payload)?)
            }
            EVENT_TYPE_DEVICE_COMPLIANCE_CHANGE => {
                CaepEvent::DeviceComplianceChange(parse(uri, payload)?)
            }
            other => {
                tracing::debug!(
                    target: "authkestra_ssf",
                    event_type = %other,
                    "event type is not modelled by authkestra-ssf; preserving payload verbatim"
                );
                CaepEvent::Unknown {
                    uri: other.to_string(),
                    payload: payload.clone(),
                }
            }
        };
        Ok(event)
    }

    /// The event type URI this event was decoded from.
    pub fn event_type_uri(&self) -> &str {
        match self {
            CaepEvent::SessionRevoked(_) => EVENT_TYPE_SESSION_REVOKED,
            CaepEvent::TokenClaimsChange(_) => EVENT_TYPE_TOKEN_CLAIMS_CHANGE,
            CaepEvent::CredentialChange(_) => EVENT_TYPE_CREDENTIAL_CHANGE,
            CaepEvent::AssuranceLevelChange(_) => EVENT_TYPE_ASSURANCE_LEVEL_CHANGE,
            CaepEvent::DeviceComplianceChange(_) => EVENT_TYPE_DEVICE_COMPLIANCE_CHANGE,
            CaepEvent::Unknown { uri, .. } => uri,
        }
    }

    /// The CAEP 1.0 §2 common claims, or `None` for [`CaepEvent::Unknown`] — an unmodelled event
    /// type is not guaranteed to be a CAEP event at all, so its payload is not interpreted.
    pub fn metadata(&self) -> Option<&CaepMetadata> {
        match self {
            CaepEvent::SessionRevoked(event) => Some(&event.metadata),
            CaepEvent::TokenClaimsChange(event) => Some(&event.metadata),
            CaepEvent::CredentialChange(event) => Some(&event.metadata),
            CaepEvent::AssuranceLevelChange(event) => Some(&event.metadata),
            CaepEvent::DeviceComplianceChange(event) => Some(&event.metadata),
            CaepEvent::Unknown { .. } => None,
        }
    }

    /// The event's own subject, when it carries one (CAEP 1.0 §3 examples).
    pub fn subject(&self) -> Option<&SubjectIdentifier> {
        self.metadata().and_then(|m| m.subject.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decodes_session_revoked_with_common_claims() {
        let payload = json!({
            "subject": { "format": "opaque", "id": "dMTlD|1600802906" },
            "initiating_entity": "policy",
            "event_timestamp": 1615304991,
            "reason_admin": { "en": "Landspeed Policy Violation: C076E82F" },
            "reason_user": { "en": "Access attempt from multiple regions." }
        });
        let event = CaepEvent::decode(EVENT_TYPE_SESSION_REVOKED, &payload).unwrap();
        let CaepEvent::SessionRevoked(revoked) = &event else {
            panic!("expected SessionRevoked, got {event:?}");
        };
        assert_eq!(revoked.metadata.event_timestamp, Some(1615304991));
        assert_eq!(
            revoked.metadata.initiating_entity,
            Some(InitiatingEntity::Policy)
        );
        assert_eq!(
            revoked.metadata.reason_admin.as_ref().unwrap()["en"],
            "Landspeed Policy Violation: C076E82F"
        );
        assert_eq!(
            revoked.metadata.reason_user.as_ref().unwrap()["en"],
            "Access attempt from multiple regions."
        );
        assert_eq!(
            event.subject(),
            Some(&SubjectIdentifier::Opaque {
                id: "dMTlD|1600802906".into()
            })
        );
        assert_eq!(event.event_type_uri(), EVENT_TYPE_SESSION_REVOKED);
    }

    #[test]
    fn decodes_session_revoked_with_empty_payload() {
        let event = CaepEvent::decode(EVENT_TYPE_SESSION_REVOKED, &json!({})).unwrap();
        assert_eq!(event, CaepEvent::SessionRevoked(SessionRevoked::default()));
        assert_eq!(event.subject(), None);
        assert_eq!(event.metadata(), Some(&CaepMetadata::default()));
    }

    #[test]
    fn decodes_token_claims_change() {
        let payload = json!({
            "subject": { "format": "iss_sub", "iss": "https://idp.example.com/", "sub": "42" },
            "claims": { "role": "ro-admin" },
            "event_timestamp": 1615304991
        });
        let event = CaepEvent::decode(EVENT_TYPE_TOKEN_CLAIMS_CHANGE, &payload).unwrap();
        let CaepEvent::TokenClaimsChange(change) = &event else {
            panic!("expected TokenClaimsChange, got {event:?}");
        };
        assert_eq!(change.claims["role"], "ro-admin");
        assert_eq!(change.metadata.event_timestamp, Some(1615304991));
        assert_eq!(event.event_type_uri(), EVENT_TYPE_TOKEN_CLAIMS_CHANGE);
        assert!(event.metadata().is_some());
        assert!(event.subject().is_some());
    }

    #[test]
    fn token_claims_change_requires_claims() {
        let err = CaepEvent::decode(EVENT_TYPE_TOKEN_CLAIMS_CHANGE, &json!({})).unwrap_err();
        assert_eq!(err.uri(), EVENT_TYPE_TOKEN_CLAIMS_CHANGE);
        assert!(err.message().contains("claims"), "{err}");
        assert!(err.to_string().contains("does not conform"), "{err}");
    }

    #[test]
    fn decodes_credential_change() {
        let payload = json!({
            "credential_type": "fido2-roaming",
            "change_type": "create",
            "friendly_name": "Corp Issued YubiKey",
            "fido2_aaguid": "accced6c-f6ec-45dd-9c9c-19e5b2b6d9c1",
            "x509_issuer": "CN=Example CA",
            "x509_serial": "123456",
            "initiating_entity": "admin"
        });
        let event = CaepEvent::decode(EVENT_TYPE_CREDENTIAL_CHANGE, &payload).unwrap();
        let CaepEvent::CredentialChange(change) = &event else {
            panic!("expected CredentialChange, got {event:?}");
        };
        assert_eq!(change.credential_type, CredentialType::Fido2Roaming);
        assert_eq!(change.change_type, ChangeType::Create);
        assert_eq!(change.friendly_name.as_deref(), Some("Corp Issued YubiKey"));
        assert_eq!(change.x509_issuer.as_deref(), Some("CN=Example CA"));
        assert_eq!(change.x509_serial.as_deref(), Some("123456"));
        assert_eq!(
            change.fido2_aaguid.as_deref(),
            Some("accced6c-f6ec-45dd-9c9c-19e5b2b6d9c1")
        );
        assert_eq!(
            change.metadata.initiating_entity,
            Some(InitiatingEntity::Admin)
        );
        assert_eq!(event.event_type_uri(), EVENT_TYPE_CREDENTIAL_CHANGE);
        assert!(event.metadata().is_some());
    }

    #[test]
    fn credential_change_requires_type_and_change() {
        let err = CaepEvent::decode(
            EVENT_TYPE_CREDENTIAL_CHANGE,
            &json!({ "credential_type": "password" }),
        )
        .unwrap_err();
        assert!(err.message().contains("change_type"), "{err}");
    }

    #[test]
    fn decodes_assurance_level_change() {
        let payload = json!({
            "current_level": "nist-aal1",
            "previous_level": "nist-aal2",
            "change_direction": "decrease",
            "initiating_entity": "system"
        });
        let event = CaepEvent::decode(EVENT_TYPE_ASSURANCE_LEVEL_CHANGE, &payload).unwrap();
        let CaepEvent::AssuranceLevelChange(change) = &event else {
            panic!("expected AssuranceLevelChange, got {event:?}");
        };
        assert_eq!(change.current_level, AssuranceLevel::Aal1);
        assert_eq!(change.previous_level, AssuranceLevel::Aal2);
        assert_eq!(change.change_direction, ChangeDirection::Decrease);
        assert_eq!(event.event_type_uri(), EVENT_TYPE_ASSURANCE_LEVEL_CHANGE);
        assert!(event.metadata().is_some());
    }

    #[test]
    fn assurance_level_change_requires_all_three_claims() {
        let err = CaepEvent::decode(
            EVENT_TYPE_ASSURANCE_LEVEL_CHANGE,
            &json!({ "current_level": "nist-aal1", "previous_level": "nist-aal2" }),
        )
        .unwrap_err();
        assert!(err.message().contains("change_direction"), "{err}");
    }

    #[test]
    fn decodes_device_compliance_change() {
        let payload = json!({
            "previous_status": "compliant",
            "current_status": "not-compliant",
            "reason_admin": { "en": "Location outside of the corporate network" }
        });
        let event = CaepEvent::decode(EVENT_TYPE_DEVICE_COMPLIANCE_CHANGE, &payload).unwrap();
        let CaepEvent::DeviceComplianceChange(change) = &event else {
            panic!("expected DeviceComplianceChange, got {event:?}");
        };
        assert_eq!(change.previous_status, ComplianceStatus::Compliant);
        assert_eq!(change.current_status, ComplianceStatus::NotCompliant);
        assert_eq!(event.event_type_uri(), EVENT_TYPE_DEVICE_COMPLIANCE_CHANGE);
        assert!(event.metadata().is_some());
    }

    #[test]
    fn device_compliance_change_requires_both_statuses() {
        let err = CaepEvent::decode(
            EVENT_TYPE_DEVICE_COMPLIANCE_CHANGE,
            &json!({ "current_status": "compliant" }),
        )
        .unwrap_err();
        assert!(err.message().contains("previous_status"), "{err}");
    }

    #[test]
    fn preserves_unknown_event_type() {
        let uri = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
        let payload = json!({ "reason": "hijacking" });
        let event = CaepEvent::decode(uri, &payload).unwrap();
        assert_eq!(
            event,
            CaepEvent::Unknown {
                uri: uri.to_string(),
                payload: payload.clone(),
            }
        );
        assert_eq!(event.event_type_uri(), uri);
        assert_eq!(event.metadata(), None);
        assert_eq!(event.subject(), None);
    }

    #[test]
    fn preserves_unmodelled_members_of_a_known_event() {
        let payload = json!({ "vendor_extension": { "tenant": "acme" } });
        let event = CaepEvent::decode(EVENT_TYPE_SESSION_REVOKED, &payload).unwrap();
        let metadata = event.metadata().expect("session-revoked has metadata");
        assert_eq!(metadata.additional["vendor_extension"]["tenant"], "acme");
    }

    #[test]
    fn all_event_type_uris_share_the_documented_prefix() {
        for uri in [
            EVENT_TYPE_SESSION_REVOKED,
            EVENT_TYPE_TOKEN_CLAIMS_CHANGE,
            EVENT_TYPE_CREDENTIAL_CHANGE,
            EVENT_TYPE_ASSURANCE_LEVEL_CHANGE,
            EVENT_TYPE_DEVICE_COMPLIANCE_CHANGE,
        ] {
            assert!(
                uri.starts_with(CAEP_EVENT_TYPE_PREFIX),
                "{uri} does not start with {CAEP_EVENT_TYPE_PREFIX}"
            );
        }
    }

    #[test]
    fn string_enums_preserve_unknown_values() {
        assert_eq!(
            InitiatingEntity::from("robot"),
            InitiatingEntity::Other("robot".into())
        );
        assert_eq!(InitiatingEntity::Other("robot".into()).as_str(), "robot");
        assert_eq!(InitiatingEntity::User.to_string(), "user");

        let credential: CredentialType =
            serde_json::from_value(json!("smartcard-ng")).expect("unknown types are preserved");
        assert_eq!(credential, CredentialType::Other("smartcard-ng".into()));
        assert_eq!(
            serde_json::to_value(&credential).unwrap(),
            json!("smartcard-ng")
        );
    }

    #[test]
    fn string_enums_round_trip_every_defined_value() {
        let cases: Vec<(Value, String)> = vec![
            (json!("admin"), InitiatingEntity::Admin.as_str().into()),
            (json!("user"), InitiatingEntity::User.as_str().into()),
            (json!("policy"), InitiatingEntity::Policy.as_str().into()),
            (json!("system"), InitiatingEntity::System.as_str().into()),
        ];
        for (wire, expected) in cases {
            let parsed: InitiatingEntity = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(parsed.as_str(), expected);
            assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
        }

        for wire in [
            "password",
            "pin",
            "x509",
            "fido2-platform",
            "fido2-roaming",
            "fido-u2f",
            "verifiable-credential",
            "phone-voice",
            "phone-sms",
            "app",
        ] {
            let parsed = CredentialType::from(wire);
            assert!(!matches!(parsed, CredentialType::Other(_)), "{wire}");
            assert_eq!(parsed.as_str(), wire);
        }

        for wire in ["create", "revoke", "update", "delete"] {
            assert_eq!(ChangeType::from(wire).as_str(), wire);
            assert!(!matches!(ChangeType::from(wire), ChangeType::Other(_)));
        }
        for wire in ["nist-aal1", "nist-aal2", "nist-aal3"] {
            assert!(!matches!(
                AssuranceLevel::from(wire),
                AssuranceLevel::Other(_)
            ));
            assert_eq!(AssuranceLevel::from(wire).as_str(), wire);
        }
        for wire in ["increase", "decrease"] {
            assert!(!matches!(
                ChangeDirection::from(wire),
                ChangeDirection::Other(_)
            ));
            assert_eq!(ChangeDirection::from(wire).as_str(), wire);
        }
        for wire in ["compliant", "not-compliant"] {
            assert!(!matches!(
                ComplianceStatus::from(wire),
                ComplianceStatus::Other(_)
            ));
            assert_eq!(ComplianceStatus::from(wire).as_str(), wire);
        }
    }

    #[test]
    fn known_events_serialize_back_to_their_wire_shape() {
        let payload = json!({
            "credential_type": "password",
            "change_type": "update",
            "event_timestamp": 1615304991
        });
        let event = CaepEvent::decode(EVENT_TYPE_CREDENTIAL_CHANGE, &payload).unwrap();
        let CaepEvent::CredentialChange(change) = event else {
            panic!("expected CredentialChange");
        };
        assert_eq!(serde_json::to_value(&change).unwrap(), payload);
    }

    #[test]
    fn event_decode_error_accessors() {
        let err = EventDecodeError::new("uri", "message");
        assert_eq!(err.uri(), "uri");
        assert_eq!(err.message(), "message");
    }
}
