//! Rejection reasons for SET ingestion, and their mapping onto the registered
//! [RFC 8935 §2.4](https://www.rfc-editor.org/rfc/rfc8935#section-2.4) error codes.
//!
//! Every variant of [`SetError`] carries a *distinct* reason a SET was refused, so a caller — or
//! a conformance test — can assert on which check failed rather than just "it failed". The
//! coarse-grained [`SetErrorCode`] is what goes on the wire; the fine-grained variant is what
//! goes in the logs.

use thiserror::Error;

use crate::caep::EventDecodeError;
use crate::keys::KeyResolveError;

/// The registered Security Event Token Error Codes from the IANA registry established by
/// [RFC 8935 §7.1](https://www.rfc-editor.org/rfc/rfc8935#section-7.1), with the initial set
/// defined in [§2.4](https://www.rfc-editor.org/rfc/rfc8935#section-2.4).
///
/// The registry is extensible, but this enum deliberately is not: emitting an unregistered code
/// would leave a SET Transmitter with a value it has no way to interpret, which is strictly
/// worse than reusing the closest registered one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetErrorCode {
    /// The request body cannot be parsed as a SET, or an Event Payload within the SET does not
    /// conform to the event's definition.
    InvalidRequest,
    /// A key used to sign the SET is invalid or otherwise unacceptable to the recipient
    /// (unknown `kid`, unusable key material, disallowed algorithm).
    InvalidKey,
    /// The SET Issuer is invalid for this recipient.
    InvalidIssuer,
    /// The SET Audience does not correspond to this recipient.
    InvalidAudience,
    /// The recipient could not authenticate the SET Transmitter — in practice, the signature
    /// did not verify under the resolved key.
    AuthenticationFailed,
    /// The SET Transmitter is not authorized to transmit this SET to this recipient.
    AccessDenied,
}

impl SetErrorCode {
    /// The registered wire string (e.g. `"invalid_request"`), which is what goes in the `err`
    /// member of an RFC 8935 §2.3 failure response body.
    pub fn as_str(&self) -> &'static str {
        match self {
            SetErrorCode::InvalidRequest => "invalid_request",
            SetErrorCode::InvalidKey => "invalid_key",
            SetErrorCode::InvalidIssuer => "invalid_issuer",
            SetErrorCode::InvalidAudience => "invalid_audience",
            SetErrorCode::AuthenticationFailed => "authentication_failed",
            SetErrorCode::AccessDenied => "access_denied",
        }
    }
}

impl std::fmt::Display for SetErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a SET was refused by [`crate::SetVerifier`].
///
/// Never carries the token, the signature, or any key material — only enough to log, alert on,
/// or return in an RFC 8935 §2.3 `description`.
#[derive(Debug, Error, Clone, PartialEq)]
#[non_exhaustive]
pub enum SetError {
    /// The body is not a syntactically valid compact JWS, or its header is not JSON.
    #[error("malformed SET: {0}")]
    Malformed(String),

    /// The JOSE header has no `typ`.
    ///
    /// RFC 8417 §2.3 only says `typ` "MUST be included if the SET could be used in an
    /// application context in which it could be confused with other kinds of JWTs" — and
    /// §4.1/§4.2 spend two sections on exactly how a SET gets confused with an ID Token or an
    /// access token. A general-purpose receiver *is* such a context, so this crate requires it.
    #[error("missing typ header: RFC 8417 §2.3 explicit typing is required by this receiver")]
    MissingType,

    /// The JOSE header's `typ` is present but is not `secevent+jwt`.
    #[error("unexpected typ header {0:?}: expected \"secevent+jwt\" (RFC 8417 §2.3)")]
    UnexpectedType(String),

    /// `alg` is `none`, is not a JWS algorithm this build understands, or is not in the
    /// verifier's configured allow-list.
    #[error("disallowed alg: {0}")]
    DisallowedAlgorithm(String),

    /// No usable key could be resolved for the token's `kid`.
    #[error("key resolution failed: {0}")]
    KeyResolution(#[from] KeyResolveError),

    /// The signature did not verify under the resolved key, or the key is unusable for the
    /// header's algorithm.
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),

    /// The payload is not a JSON object with the claims RFC 8417 §2.2 requires (`iss`, `iat`,
    /// `jti`, `events`), or one of them has the wrong JSON type.
    #[error("invalid SET claims: {0}")]
    InvalidClaims(String),

    /// `iss` does not equal the issuer this verifier was configured for.
    ///
    /// The `Display` text deliberately names neither value. It reaches an unauthenticated caller
    /// through the RFC 8935 §2.3 `description` member — the push endpoint has no authentication
    /// of its own — so echoing the configured issuer back would let anyone POST a bogus SET and
    /// enumerate the deployment's trust configuration. Both values are still carried in the
    /// struct, and [`crate::SetVerifier`] logs them as structured fields on rejection.
    #[error("invalid issuer")]
    IssuerMismatch {
        /// The issuer the verifier was configured with.
        expected: String,
        /// The issuer the SET actually carried.
        found: String,
    },

    /// The verifier expects an audience but the SET has no `aud` claim.
    ///
    /// As with [`SetError::IssuerMismatch`], the expected values are kept out of the `Display`
    /// text because it is returned to an unauthenticated caller.
    #[error("missing aud claim")]
    MissingAudience {
        /// The audience values that would have been accepted.
        expected: Vec<String>,
    },

    /// The SET's `aud` does not include any audience this verifier accepts.
    ///
    /// As with [`SetError::IssuerMismatch`], the expected values are kept out of the `Display`
    /// text because it is returned to an unauthenticated caller.
    #[error("audience mismatch")]
    AudienceMismatch {
        /// The audience values that would have been accepted.
        expected: Vec<String>,
    },

    /// `iat` is further in the future than the configured leeway allows. A SET describes
    /// something that has *already happened* (RFC 8417 §2.2), so an `iat` in the future is
    /// either clock skew — hence the leeway — or a forgery attempt.
    ///
    /// As with [`SetError::IssuerMismatch`], the `Display` text names no numbers: it reaches an
    /// unauthenticated caller through the RFC 8935 §2.3 `description`, and the configured leeway
    /// is deployment policy rather than something a transmitter needs to be told. All three
    /// values stay in the struct and are logged as structured fields on rejection.
    #[error("iat is too far in the future")]
    IatInFuture {
        /// The `iat` the SET carried.
        iat: i64,
        /// The time verification was performed at.
        now: i64,
        /// The configured tolerance, in seconds.
        leeway: i64,
    },

    /// `iat` is older than the configured maximum age.
    ///
    /// As with [`SetError::IatInFuture`], the configured maximum age is kept out of the `Display`
    /// text because it is returned to an unauthenticated caller.
    #[error("SET is too old")]
    TooOld {
        /// The `iat` the SET carried.
        iat: i64,
        /// The time verification was performed at.
        now: i64,
        /// The configured maximum age, in seconds.
        max_age: i64,
    },

    /// `exp` is in the past.
    ///
    /// RFC 8417 §2.2 says use of `exp` in a SET is NOT RECOMMENDED, so this is never *required*
    /// to be present — but an issuer that went out of its way to say "do not accept this after
    /// T" is not to be second-guessed, so it is honoured when it is there.
    #[error("SET expired at {exp} (now {now})")]
    Expired {
        /// The `exp` the SET carried.
        exp: i64,
        /// The time verification was performed at.
        now: i64,
    },

    /// The `jti` claim is present but empty (or only whitespace).
    ///
    /// RFC 8417 §2.2 makes `jti` "a unique identifier for the SET" that a client "MAY use to
    /// track whether a particular SET has already been received". An empty string identifies
    /// nothing: accepting it would collapse the replay guard to a single slot per issuer, so
    /// the first empty-`jti` SET from an issuer would permanently suppress every subsequent one.
    #[error("empty jti claim: a SET's jti must uniquely identify it (RFC 8417 §2.2)")]
    EmptyJti,

    /// The `events` claim is present but empty. RFC 8417 §2.2 defines `events` as "a set of
    /// event statements"; a SET conveying none of them describes nothing and cannot be acted on.
    #[error("empty events claim: a SET must convey at least one event (RFC 8417 §2.2)")]
    EmptyEvents,

    /// An event payload does not conform to its event type's definition.
    #[error("{0}")]
    EventPayload(#[from] EventDecodeError),

    /// This `(iss, jti)` pair has already been ingested.
    ///
    /// Note that the RFC 8935 push receiver never turns this into a failure response — see
    /// [`crate::PushReceiver::receive`] for why RFC 8935 §2 mandates a 202 on retransmission.
    /// The variant exists so that a caller driving [`crate::SetVerifier`] directly can tell
    /// "already seen" apart from "accepted", and so replays are visible in logs and metrics.
    #[error("replayed SET: jti {jti:?} from issuer {iss:?} was already ingested")]
    Replay {
        /// The `jti` that had already been recorded.
        jti: String,
        /// The issuer the `jti` is scoped to.
        iss: String,
    },
}

impl SetError {
    /// The RFC 8935 §2.4 error code this rejection maps onto.
    ///
    /// The mapping is many-to-one on purpose: the registry has six codes and this crate
    /// distinguishes far more failure modes than that, because collapsing them at the point of
    /// detection would make the logs useless. Only the wire response is coarse.
    pub fn code(&self) -> SetErrorCode {
        match self {
            SetError::Malformed(_)
            | SetError::MissingType
            | SetError::UnexpectedType(_)
            | SetError::InvalidClaims(_)
            | SetError::IatInFuture { .. }
            | SetError::TooOld { .. }
            | SetError::Expired { .. }
            | SetError::EmptyJti
            | SetError::EmptyEvents
            | SetError::EventPayload(_) => SetErrorCode::InvalidRequest,
            SetError::DisallowedAlgorithm(_) | SetError::KeyResolution(_) => {
                SetErrorCode::InvalidKey
            }
            SetError::InvalidSignature(_) => SetErrorCode::AuthenticationFailed,
            SetError::IssuerMismatch { .. } => SetErrorCode::InvalidIssuer,
            SetError::MissingAudience { .. } | SetError::AudienceMismatch { .. } => {
                SetErrorCode::InvalidAudience
            }
            // Unreachable through `PushReceiver` (a replay answers 202), but a direct caller
            // that chooses to surface it needs *some* registered code; "the transmitter may not
            // send this SET to this recipient" is the closest fit.
            SetError::Replay { .. } => SetErrorCode::AccessDenied,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_have_registered_wire_strings() {
        assert_eq!(SetErrorCode::InvalidRequest.as_str(), "invalid_request");
        assert_eq!(SetErrorCode::InvalidKey.as_str(), "invalid_key");
        assert_eq!(SetErrorCode::InvalidIssuer.as_str(), "invalid_issuer");
        assert_eq!(SetErrorCode::InvalidAudience.as_str(), "invalid_audience");
        assert_eq!(
            SetErrorCode::AuthenticationFailed.as_str(),
            "authentication_failed"
        );
        assert_eq!(SetErrorCode::AccessDenied.as_str(), "access_denied");
        assert_eq!(SetErrorCode::AccessDenied.to_string(), "access_denied");
    }

    #[test]
    fn every_variant_maps_to_a_code() {
        let cases: Vec<(SetError, SetErrorCode)> = vec![
            (
                SetError::Malformed("x".into()),
                SetErrorCode::InvalidRequest,
            ),
            (SetError::MissingType, SetErrorCode::InvalidRequest),
            (
                SetError::UnexpectedType("JWT".into()),
                SetErrorCode::InvalidRequest,
            ),
            (
                SetError::DisallowedAlgorithm("none".into()),
                SetErrorCode::InvalidKey,
            ),
            (
                SetError::KeyResolution(KeyResolveError::UnknownKid(Some("k".into()))),
                SetErrorCode::InvalidKey,
            ),
            (
                SetError::InvalidSignature("bad".into()),
                SetErrorCode::AuthenticationFailed,
            ),
            (
                SetError::InvalidClaims("no iss".into()),
                SetErrorCode::InvalidRequest,
            ),
            (
                SetError::IssuerMismatch {
                    expected: "a".into(),
                    found: "b".into(),
                },
                SetErrorCode::InvalidIssuer,
            ),
            (
                SetError::MissingAudience {
                    expected: vec!["a".into()],
                },
                SetErrorCode::InvalidAudience,
            ),
            (
                SetError::AudienceMismatch {
                    expected: vec!["a".into()],
                },
                SetErrorCode::InvalidAudience,
            ),
            (
                SetError::IatInFuture {
                    iat: 10,
                    now: 0,
                    leeway: 1,
                },
                SetErrorCode::InvalidRequest,
            ),
            (
                SetError::TooOld {
                    iat: 0,
                    now: 10,
                    max_age: 1,
                },
                SetErrorCode::InvalidRequest,
            ),
            (
                SetError::Expired { exp: 0, now: 10 },
                SetErrorCode::InvalidRequest,
            ),
            (SetError::EmptyJti, SetErrorCode::InvalidRequest),
            (SetError::EmptyEvents, SetErrorCode::InvalidRequest),
            (
                SetError::EventPayload(EventDecodeError::new("uri", "boom")),
                SetErrorCode::InvalidRequest,
            ),
            (
                SetError::Replay {
                    jti: "j".into(),
                    iss: "i".into(),
                },
                SetErrorCode::AccessDenied,
            ),
        ];

        for (err, expected) in cases {
            assert_eq!(err.code(), expected, "wrong code for {err:?}");
            assert!(!err.to_string().is_empty(), "empty Display for {err:?}");
        }
    }

    #[test]
    fn freshness_errors_keep_their_values_but_never_display_them() {
        // The numbers are exactly what an operator needs and what an unauthenticated caller must
        // not be handed: `leeway` and `max_age` are deployment policy. They live in the variant
        // (and in the verifier's structured tracing fields), never in `Display`.
        let err = SetError::IatInFuture {
            iat: 130,
            now: 100,
            leeway: 5,
        };
        match &err {
            SetError::IatInFuture { iat, now, leeway } => {
                assert_eq!((*iat, *now, *leeway), (130, 100, 5));
            }
            other => panic!("unexpected variant {other:?}"),
        }
        let message = err.to_string();
        for leaked in ["130", "100", "5"] {
            assert!(!message.contains(leaked), "{message} leaked {leaked}");
        }

        let err = SetError::TooOld {
            iat: 100,
            now: 400,
            max_age: 60,
        };
        match &err {
            SetError::TooOld { iat, now, max_age } => {
                assert_eq!((*iat, *now, *max_age), (100, 400, 60));
            }
            other => panic!("unexpected variant {other:?}"),
        }
        let message = err.to_string();
        for leaked in ["100", "400", "60"] {
            assert!(!message.contains(leaked), "{message} leaked {leaked}");
        }
    }
}
