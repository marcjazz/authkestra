//! The Security Event Token model, per [RFC 8417](https://www.rfc-editor.org/rfc/rfc8417).
//!
//! A SET is a JWT whose payload describes something that *already happened* to a security
//! subject. That tense is what makes its claim profile unusual, and the unusual parts are
//! modelled explicitly here rather than left to a generic JWT struct — see [`SecurityEventToken`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::caep::{CaepEvent, EventDecodeError};
use crate::subject::SubjectIdentifier;

/// The media type registered for a SET by
/// [RFC 8417 §2.3](https://www.rfc-editor.org/rfc/rfc8417#section-2.3), and the value RFC 8935
/// §2.1 requires in the `Content-Type` of a push delivery request.
pub const SET_MEDIA_TYPE: &str = "application/secevent+jwt";

/// The value RFC 8417 §2.3 says SHOULD appear in the JWT's `typ` header: the media type with the
/// `application/` prefix omitted, as RFC 7515 §4.1.9 recommends.
pub const SET_TYP: &str = "secevent+jwt";

/// The `aud` claim, which RFC 7519 §4.1.3 allows to be either a single string or an array of
/// strings.
///
/// Both shapes are kept distinct rather than normalised to a `Vec` on parse, so that a SET can
/// be re-serialized in the shape it arrived in — a receiver that forwards or archives SETs must
/// not silently rewrite the transmitter's tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience value.
    Single(String),
    /// One or more audience values.
    Multiple(Vec<String>),
}

impl Audience {
    /// Whether `value` is one of the audiences.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Audience::Single(single) => single == value,
            Audience::Multiple(values) => values.iter().any(|v| v == value),
        }
    }

    /// Iterates over the audience values.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        // `Either` would need another dependency for two cases; a boxed iterator keeps the
        // signature simple and this is never on a hot path (one call per SET).
        let iter: Box<dyn Iterator<Item = &str>> = match self {
            Audience::Single(single) => Box::new(std::iter::once(single.as_str())),
            Audience::Multiple(values) => Box::new(values.iter().map(String::as_str)),
        };
        iter
    }

    /// Whether the claim carries no audience value at all (an empty JSON array).
    pub fn is_empty(&self) -> bool {
        match self {
            Audience::Single(_) => false,
            Audience::Multiple(values) => values.is_empty(),
        }
    }
}

/// A Security Event Token's claims (RFC 8417 §2.2).
///
/// Three things about this profile are not what a JWT reader expects, and each is modelled
/// deliberately:
///
/// - **`exp` is NOT RECOMMENDED** (§2.2), because a SET is historical — it does not stop being
///   true. So [`SecurityEventToken::exp`] is optional and its absence is never an error;
///   [`crate::SetVerifier`] still honours it when a transmitter chose to send one. §4.1 goes
///   further: a SET profile that could be confused with an ID Token MUST NOT carry `exp` at all.
/// - **`nbf` is not profiled by RFC 8417 at all** — the word does not appear in the document.
///   It is therefore parsed into [`SecurityEventToken::nbf`] and *deliberately not validated*:
///   rejecting on a claim the specification never gave meaning to would refuse valid SETs, while
///   dropping it would hide it from handlers that a profiling specification does give meaning to.
/// - **Freshness comes from `iat`, not `exp`** — see [`crate::SetVerifier`] for the leeway and
///   maximum-age checks that replace expiry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityEventToken {
    /// REQUIRED (§2.2). The service provider publishing the SET.
    ///
    /// Not necessarily the issuer associated with the security subject: §2.2 warns that
    /// implementers cannot assume the two are the same unless a profiling specification says so.
    pub iss: String,

    /// REQUIRED (§2.2). Unique identifier for this SET, unique within a particular event feed —
    /// which is why replay state is keyed by `(iss, jti)` and not by `jti` alone.
    pub jti: String,

    /// REQUIRED (§2.2). When the SET was issued, as a NumericDate.
    pub iat: i64,

    /// RECOMMENDED (§2.2). One or more audience identifiers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,

    /// OPTIONAL (§2.2). A `StringOrURI` naming the principal the SET is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// OPTIONAL. The RFC 9493 §4.1 `sub_id` claim: the subject as a structured Subject
    /// Identifier rather than a bare string.
    ///
    /// RFC 9493 §4.1 requires that `sub` and `sub_id`, when both present, identify the same
    /// subject, and that an implementation MUST NOT rely on both to determine it. This crate
    /// therefore only parses them; picking which one to resolve against is the consumer's call,
    /// because only the consumer knows which identifier formats its user store speaks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_id: Option<SubjectIdentifier>,

    /// OPTIONAL (§2.2). Correlates several related JWTs issued as one transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn: Option<String>,

    /// OPTIONAL (§2.2). Time of event: when the event occurred, as opposed to when the SET was
    /// issued. Its absence means the issuer chose not to share an event time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toe: Option<i64>,

    /// NOT RECOMMENDED (§2.2), honoured when present. See the type-level docs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Not profiled by RFC 8417; parsed, preserved, and deliberately not validated. See the
    /// type-level docs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// REQUIRED (§2.2). Event type URI to event payload.
    ///
    /// A `BTreeMap` rather than a `HashMap` so that iteration order — and therefore the order
    /// handlers are invoked in, and the order log lines appear in — is deterministic across
    /// runs. §2.2 forbids repeating an event identifier, so a map loses nothing.
    pub events: BTreeMap<String, Value>,

    /// Any other claim, preserved for profiling specifications this crate does not model.
    #[serde(flatten)]
    pub additional: Map<String, Value>,
}

impl SecurityEventToken {
    /// Decodes every entry of [`SecurityEventToken::events`] into a typed [`CaepEvent`].
    ///
    /// Fails on the first event whose type is modelled but whose payload does not conform;
    /// unmodelled event types become [`CaepEvent::Unknown`] rather than an error, so a SET
    /// carrying one CAEP event and one RISC event still yields both.
    pub fn caep_events(&self) -> Result<Vec<CaepEvent>, EventDecodeError> {
        self.events
            .iter()
            .map(|(uri, payload)| CaepEvent::decode(uri, payload))
            .collect()
    }

    /// The event type URIs this SET carries, in deterministic order.
    pub fn event_type_uris(&self) -> impl Iterator<Item = &str> {
        self.events.keys().map(String::as_str)
    }

    /// Whether this SET carries an event of type `uri`.
    pub fn contains_event(&self, uri: &str) -> bool {
        self.events.contains_key(uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caep::EVENT_TYPE_SESSION_REVOKED;
    use serde_json::json;

    fn parse(value: Value) -> Result<SecurityEventToken, serde_json::Error> {
        serde_json::from_value(value)
    }

    fn minimal() -> Value {
        json!({
            "iss": "https://idp.example.com/",
            "jti": "756E69717565206964656E746966696572",
            "iat": 1_508_184_845_i64,
            "events": { EVENT_TYPE_SESSION_REVOKED: {} }
        })
    }

    #[test]
    fn parses_the_rfc_8935_example_claims() {
        let set = parse(json!({
            "iss": "https://idp.example.com/",
            "jti": "756E69717565206964656E746966696572",
            "iat": 1_508_184_845_i64,
            "aud": "636C69656E745F6964",
            "events": {
                "https://schemas.openid.net/secevent/risc/event-type/account-disabled": {
                    "subject": {
                        "subject_type": "iss-sub",
                        "iss": "https://idp.example.com/",
                        "sub": "7375626A656374"
                    },
                    "reason": "hijacking"
                }
            }
        }))
        .expect("the RFC 8935 §2.1 example must parse");
        assert_eq!(set.iss, "https://idp.example.com/");
        assert_eq!(set.iat, 1_508_184_845);
        assert!(set.aud.as_ref().unwrap().contains("636C69656E745F6964"));
        assert_eq!(set.events.len(), 1);
        assert!(set.exp.is_none());
    }

    #[test]
    fn required_claims_are_required() {
        for missing in ["iss", "jti", "iat", "events"] {
            let mut value = minimal();
            value.as_object_mut().unwrap().remove(missing);
            let err = parse(value).unwrap_err();
            assert!(
                err.to_string().contains(missing),
                "removing {missing} should be reported: {err}"
            );
        }
    }

    #[test]
    fn accepts_and_ignores_nbf() {
        let mut value = minimal();
        value
            .as_object_mut()
            .unwrap()
            .insert("nbf".into(), json!(4));
        let set = parse(value).unwrap();
        assert_eq!(set.nbf, Some(4));
    }

    #[test]
    fn preserves_unmodelled_top_level_claims() {
        let mut value = minimal();
        value
            .as_object_mut()
            .unwrap()
            .insert("tenant".into(), json!("acme"));
        let set = parse(value).unwrap();
        assert_eq!(set.additional["tenant"], "acme");
    }

    #[test]
    fn audience_accepts_a_single_string_or_an_array() {
        let mut single = minimal();
        single
            .as_object_mut()
            .unwrap()
            .insert("aud".into(), json!("https://sp.example.com/caep"));
        let set = parse(single).unwrap();
        assert_eq!(
            set.aud,
            Some(Audience::Single("https://sp.example.com/caep".into()))
        );
        assert!(set
            .aud
            .as_ref()
            .unwrap()
            .contains("https://sp.example.com/caep"));
        assert!(!set.aud.as_ref().unwrap().contains("https://other/"));
        assert!(!set.aud.as_ref().unwrap().is_empty());
        assert_eq!(
            set.aud.as_ref().unwrap().iter().collect::<Vec<_>>(),
            vec!["https://sp.example.com/caep"]
        );

        let mut multiple = minimal();
        multiple
            .as_object_mut()
            .unwrap()
            .insert("aud".into(), json!(["a", "b"]));
        let set = parse(multiple).unwrap();
        assert_eq!(
            set.aud,
            Some(Audience::Multiple(vec!["a".into(), "b".into()]))
        );
        assert!(set.aud.as_ref().unwrap().contains("b"));
        assert!(!set.aud.as_ref().unwrap().contains("c"));
        assert_eq!(
            set.aud.as_ref().unwrap().iter().collect::<Vec<_>>(),
            vec!["a", "b"]
        );

        let empty = Audience::Multiple(Vec::new());
        assert!(empty.is_empty());
        assert!(!empty.contains(""));
    }

    #[test]
    fn round_trips_the_audience_shape_it_arrived_in() {
        let mut value = minimal();
        value
            .as_object_mut()
            .unwrap()
            .insert("aud".into(), json!("one"));
        let set = parse(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&set).unwrap(), value);

        let mut value = minimal();
        value
            .as_object_mut()
            .unwrap()
            .insert("aud".into(), json!(["one"]));
        let set = parse(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&set).unwrap(), value);
    }

    #[test]
    fn parses_optional_rfc_8417_claims() {
        let mut value = minimal();
        let obj = value.as_object_mut().unwrap();
        obj.insert("sub".into(), json!("user@example.com"));
        obj.insert(
            "sub_id".into(),
            json!({ "format": "email", "email": "user@example.com" }),
        );
        obj.insert("txn".into(), json!("txn-1"));
        obj.insert("toe".into(), json!(1_508_184_000_i64));
        obj.insert("exp".into(), json!(1_508_185_000_i64));

        let set = parse(value).unwrap();
        assert_eq!(set.sub.as_deref(), Some("user@example.com"));
        assert_eq!(
            set.sub_id,
            Some(SubjectIdentifier::Email {
                email: "user@example.com".into()
            })
        );
        assert_eq!(set.txn.as_deref(), Some("txn-1"));
        assert_eq!(set.toe, Some(1_508_184_000));
        assert_eq!(set.exp, Some(1_508_185_000));
    }

    #[test]
    fn event_helpers_expose_the_events_claim() {
        let set = parse(minimal()).unwrap();
        assert!(set.contains_event(EVENT_TYPE_SESSION_REVOKED));
        assert!(!set.contains_event("https://example.com/other"));
        assert_eq!(
            set.event_type_uris().collect::<Vec<_>>(),
            vec![EVENT_TYPE_SESSION_REVOKED]
        );
        let events = set.caep_events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type_uri(), EVENT_TYPE_SESSION_REVOKED);
    }

    #[test]
    fn caep_events_reports_a_malformed_known_payload() {
        let mut value = minimal();
        value.as_object_mut().unwrap().insert(
            "events".into(),
            json!({ crate::caep::EVENT_TYPE_CREDENTIAL_CHANGE: {} }),
        );
        let set = parse(value).unwrap();
        let err = set.caep_events().unwrap_err();
        assert_eq!(err.uri(), crate::caep::EVENT_TYPE_CREDENTIAL_CHANGE);
    }

    #[test]
    fn media_type_constants_match_rfc_8417_section_2_3() {
        assert_eq!(SET_MEDIA_TYPE, "application/secevent+jwt");
        assert_eq!(SET_TYP, "secevent+jwt");
        assert_eq!(SET_MEDIA_TYPE, format!("application/{SET_TYP}"));
    }
}
