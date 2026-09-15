//! Subject Identifiers for Security Events, per
//! [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493).
//!
//! A Subject Identifier is a JSON object with a `format` member naming its Identifier Format,
//! plus whatever members that format requires (RFC 9493 §3). It appears in a SET as the
//! `sub_id` JWT claim (§4.1) and, for CAEP, also inside individual event payloads.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

/// A Subject Identifier (RFC 9493 §3).
///
/// The formats modelled explicitly are the ones a CAEP receiver realistically has to act on.
/// Every other registered format — `account`, `did`, `uri`, `aliases`, `jwt_id`, plus any
/// Collision-Resistant Name a transmitter invents — lands in [`SubjectIdentifier::Other`] with
/// its JSON intact, because RFC 9493 §4.1 explicitly contemplates a receiver that "does not
/// understand the format" of an identifier, and silently dropping such a subject would turn an
/// event about *someone* into an event about nobody.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubjectIdentifier {
    /// Issuer and Subject Identifier Format (RFC 9493 §3.2.3), `format: "iss_sub"`.
    IssSub {
        /// The issuer of the subject, following the JWT `iss` format.
        iss: String,
        /// The subject at that issuer, following the JWT `sub` format.
        sub: String,
    },
    /// Email Identifier Format (RFC 9493 §3.2.2), `format: "email"`.
    ///
    /// The value is *not* canonicalized here. RFC 9493 §3.2.2.1 is explicit that email
    /// canonicalization is not standardized and that the recipient should apply its own
    /// algorithm, so guessing one in a protocol crate would silently merge or split identities
    /// according to a rule the deployment never chose.
    Email {
        /// The subject's email address, as an RFC 5322 `addr-spec`.
        email: String,
    },
    /// Opaque Identifier Format (RFC 9493 §3.2.4), `format: "opaque"`.
    Opaque {
        /// An identifier string with no asserted semantics beyond identifying the subject.
        id: String,
    },
    /// Phone Number Identifier Format (RFC 9493 §3.2.5), `format: "phone_number"`.
    PhoneNumber {
        /// The subject's full telephone number in E.164 form, including the dialing prefix.
        phone_number: String,
    },
    /// Any other Identifier Format, preserved verbatim.
    Other {
        /// The value of the `format` member.
        format: String,
        /// The complete original JSON object, `format` member included, so that a receiver that
        /// *does* understand the format can still parse it.
        raw: Map<String, Value>,
    },
}

impl SubjectIdentifier {
    /// The value of the `format` member for this identifier.
    pub fn format(&self) -> &str {
        match self {
            SubjectIdentifier::IssSub { .. } => "iss_sub",
            SubjectIdentifier::Email { .. } => "email",
            SubjectIdentifier::Opaque { .. } => "opaque",
            SubjectIdentifier::PhoneNumber { .. } => "phone_number",
            SubjectIdentifier::Other { format, .. } => format.as_str(),
        }
    }
}

/// The known formats, parsed strictly: an identifier that *claims* a registered format but omits
/// the member that format requires is a spec violation (RFC 9493 §3: "MUST contain all members
/// required by its Identifier Format"), not an unknown format, and must not be quietly demoted
/// to [`SubjectIdentifier::Other`].
#[derive(Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
enum KnownSubject {
    IssSub { iss: String, sub: String },
    Email { email: String },
    Opaque { id: String },
    PhoneNumber { phone_number: String },
}

impl<'de> Deserialize<'de> for SubjectIdentifier {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let Value::Object(obj) = value else {
            return Err(D::Error::custom(
                "a Subject Identifier must be a JSON object (RFC 9493 §3)",
            ));
        };

        let format = obj
            .get("format")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                D::Error::custom(
                    "a Subject Identifier must contain a string \"format\" member (RFC 9493 §3)",
                )
            })?
            .to_string();

        match format.as_str() {
            "iss_sub" | "email" | "opaque" | "phone_number" => {
                let known: KnownSubject =
                    serde_json::from_value(Value::Object(obj)).map_err(D::Error::custom)?;
                Ok(match known {
                    KnownSubject::IssSub { iss, sub } => SubjectIdentifier::IssSub { iss, sub },
                    KnownSubject::Email { email } => SubjectIdentifier::Email { email },
                    KnownSubject::Opaque { id } => SubjectIdentifier::Opaque { id },
                    KnownSubject::PhoneNumber { phone_number } => {
                        SubjectIdentifier::PhoneNumber { phone_number }
                    }
                })
            }
            _ => Ok(SubjectIdentifier::Other { format, raw: obj }),
        }
    }
}

impl Serialize for SubjectIdentifier {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = match self {
            SubjectIdentifier::IssSub { iss, sub } => {
                serde_json::json!({ "format": "iss_sub", "iss": iss, "sub": sub })
            }
            SubjectIdentifier::Email { email } => {
                serde_json::json!({ "format": "email", "email": email })
            }
            SubjectIdentifier::Opaque { id } => serde_json::json!({ "format": "opaque", "id": id }),
            SubjectIdentifier::PhoneNumber { phone_number } => {
                serde_json::json!({ "format": "phone_number", "phone_number": phone_number })
            }
            // Round-trips byte-for-byte modulo JSON object ordering: `raw` still holds the
            // `format` member, so nothing has to be re-inserted here.
            SubjectIdentifier::Other { raw, .. } => Value::Object(raw.clone()),
        };
        value.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: serde_json::Value) -> Result<SubjectIdentifier, serde_json::Error> {
        serde_json::from_value(json)
    }

    #[test]
    fn parses_iss_sub_format() {
        let subject = parse(serde_json::json!({
            "format": "iss_sub",
            "iss": "https://issuer.example.com/",
            "sub": "145234573"
        }))
        .expect("iss_sub should parse");
        assert_eq!(
            subject,
            SubjectIdentifier::IssSub {
                iss: "https://issuer.example.com/".into(),
                sub: "145234573".into(),
            }
        );
        assert_eq!(subject.format(), "iss_sub");
    }

    #[test]
    fn parses_email_format() {
        let subject =
            parse(serde_json::json!({ "format": "email", "email": "user@example.com" })).unwrap();
        assert_eq!(
            subject,
            SubjectIdentifier::Email {
                email: "user@example.com".into()
            }
        );
        assert_eq!(subject.format(), "email");
    }

    #[test]
    fn parses_opaque_format() {
        let subject =
            parse(serde_json::json!({ "format": "opaque", "id": "11112222333344445555" })).unwrap();
        assert_eq!(
            subject,
            SubjectIdentifier::Opaque {
                id: "11112222333344445555".into()
            }
        );
        assert_eq!(subject.format(), "opaque");
    }

    #[test]
    fn parses_phone_number_format() {
        let subject =
            parse(serde_json::json!({ "format": "phone_number", "phone_number": "+12065550100" }))
                .unwrap();
        assert_eq!(
            subject,
            SubjectIdentifier::PhoneNumber {
                phone_number: "+12065550100".into()
            }
        );
        assert_eq!(subject.format(), "phone_number");
    }

    #[test]
    fn preserves_unknown_format_verbatim() {
        let json = serde_json::json!({
            "format": "did",
            "url": "did:example:123456/did/url/path?versionId=1"
        });
        let subject = parse(json.clone()).unwrap();
        match &subject {
            SubjectIdentifier::Other { format, raw } => {
                assert_eq!(format, "did");
                assert_eq!(
                    raw.get("url").unwrap(),
                    "did:example:123456/did/url/path?versionId=1"
                );
            }
            other => panic!("expected Other, got {other:?}"),
        }
        assert_eq!(subject.format(), "did");
        assert_eq!(serde_json::to_value(&subject).unwrap(), json);
    }

    #[test]
    fn preserves_nested_aliases_format() {
        let json = serde_json::json!({
            "format": "aliases",
            "identifiers": [
                { "format": "email", "email": "user@example.com" },
                { "format": "phone_number", "phone_number": "+12065550100" }
            ]
        });
        let subject = parse(json.clone()).unwrap();
        assert_eq!(subject.format(), "aliases");
        assert_eq!(serde_json::to_value(&subject).unwrap(), json);
    }

    #[test]
    fn rejects_known_format_missing_its_required_member() {
        let err = parse(serde_json::json!({ "format": "email" })).unwrap_err();
        assert!(err.to_string().contains("email"), "{err}");
    }

    #[test]
    fn rejects_missing_format_member() {
        let err = parse(serde_json::json!({ "email": "user@example.com" })).unwrap_err();
        assert!(err.to_string().contains("format"), "{err}");
    }

    #[test]
    fn rejects_non_object() {
        let err = parse(serde_json::json!("user@example.com")).unwrap_err();
        assert!(err.to_string().contains("JSON object"), "{err}");
    }

    #[test]
    fn known_formats_round_trip() {
        for json in [
            serde_json::json!({ "format": "iss_sub", "iss": "https://i/", "sub": "s" }),
            serde_json::json!({ "format": "email", "email": "user@example.com" }),
            serde_json::json!({ "format": "opaque", "id": "abc" }),
            serde_json::json!({ "format": "phone_number", "phone_number": "+12065550100" }),
        ] {
            let subject = parse(json.clone()).unwrap();
            assert_eq!(serde_json::to_value(&subject).unwrap(), json);
        }
    }
}
