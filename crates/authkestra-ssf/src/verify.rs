//! Ingestion and validation of Security Event Tokens.
//!
//! [`SetVerifier`] implements the recipient-side checks RFC 8935 §2 requires ("the SET Recipient
//! can parse the SET", "the SET is authentic", "the SET Recipient is identified as an intended
//! audience", "the SET Issuer is recognized") on top of the RFC 8417 claim profile, plus the two
//! freshness controls that a specification which discourages `exp` leaves to the receiver.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use thiserror::Error;

use crate::caep::CaepEvent;
use crate::error::SetError;
use crate::keys::{SetKeyResolver, SingleKeyResolver};
use crate::replay::SetReplayGuard;
use crate::set::{SecurityEventToken, SET_TYP};

/// The default tolerance for an `iat` in the future, absorbing ordinary clock skew between
/// transmitter and receiver.
const DEFAULT_IAT_LEEWAY: Duration = Duration::from_secs(60);

/// Why a [`SetVerifier`] could not be built. Every variant is a configuration mistake that would
/// otherwise become a runtime security hole, so it is refused up front rather than defaulted.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SetVerifierError {
    /// No issuer was given, or it was empty. Without one, the RFC 8935 §2 "SET Issuer is
    /// recognized" check has nothing to compare against.
    #[error("a SET verifier needs a non-empty expected issuer")]
    MissingIssuer,

    /// No accepted algorithms were configured. An empty allow-list would accept whatever
    /// algorithm the token names.
    #[error("a SET verifier needs at least one accepted algorithm")]
    NoAlgorithms,

    /// Neither [`SetVerifierBuilder::key`] nor [`SetVerifierBuilder::key_resolver`] was called.
    #[error("a SET verifier needs either a decoding key or a key resolver")]
    MissingKeySource,
}

/// A SET that passed every check in [`SetVerifier::verify_at`], together with its decoded events.
///
/// The events travel with the token rather than being decoded by the caller afterwards, and that
/// is the whole point of the type: event-payload decoding is one of the checks that decides
/// whether a SET is acceptable, so it has to happen *before* the replay slot for `(iss, jti)` is
/// taken. A caller that received a bare `SecurityEventToken` and then called
/// [`SecurityEventToken::caep_events`] itself would be rejecting the SET after the verifier had
/// already recorded it — and RFC 8935 §2 lets the transmitter fix the payload and retransmit
/// under the same `jti`, which would then be silently swallowed as a replay.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct VerifiedSet {
    /// The validated token and its claims.
    pub set: SecurityEventToken,
    /// Every entry of the token's `events` claim, decoded. Never empty: an empty `events` claim
    /// is refused as [`SetError::EmptyEvents`] before this is built.
    pub events: Vec<CaepEvent>,
}

impl VerifiedSet {
    /// Pairs a token with its decoded events.
    ///
    /// **Exists so consumers can construct one in their own tests** — sealing an output type with
    /// no way to build it is the problem reported against `authkestra-devsig`'s `DeviceIdentity`
    /// in [authkestra#282](https://github.com/marcjazz/authkestra/issues/282). It performs **no
    /// validation and no decoding**: the name is not a promise, and a `VerifiedSet` built here
    /// has been verified by nobody. Only [`SetVerifier::verify_at`] produces a trustworthy one.
    pub fn new(set: SecurityEventToken, events: Vec<CaepEvent>) -> Self {
        Self { set, events }
    }

    /// Consumes the wrapper, yielding the token and its events.
    pub fn into_parts(self) -> (SecurityEventToken, Vec<CaepEvent>) {
        (self.set, self.events)
    }
}

/// Validates Security Event Tokens against one transmitter's configuration.
///
/// Build one with [`SetVerifier::builder`]. A verifier is cheap to share (`Arc`) and holds no
/// mutable state of its own — any state lives behind the [`SetReplayGuard`].
pub struct SetVerifier {
    issuer: String,
    audiences: Vec<String>,
    algorithms: Vec<Algorithm>,
    keys: Arc<dyn SetKeyResolver>,
    iat_leeway: Duration,
    max_age: Option<Duration>,
    replay_guard: Option<Arc<dyn SetReplayGuard>>,
}

/// Hand-written rather than derived: the key source is a trait object, and more importantly a
/// derived `Debug` on a future field holding key material would leak it into logs. Only the
/// policy is printed; whether a key or a resolver is installed is a boolean.
impl std::fmt::Debug for SetVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetVerifier")
            .field("issuer", &self.issuer)
            .field("audiences", &self.audiences)
            .field("algorithms", &self.algorithms)
            .field("iat_leeway", &self.iat_leeway)
            .field("max_age", &self.max_age)
            .field("replay_guard", &self.replay_guard.is_some())
            .finish_non_exhaustive()
    }
}

/// Builder for [`SetVerifier`].
pub struct SetVerifierBuilder {
    issuer: String,
    audiences: Vec<String>,
    algorithms: Vec<Algorithm>,
    keys: Option<Arc<dyn SetKeyResolver>>,
    iat_leeway: Duration,
    max_age: Option<Duration>,
    replay_guard: Option<Arc<dyn SetReplayGuard>>,
}

impl SetVerifier {
    /// Starts building a verifier for SETs issued by `issuer`.
    pub fn builder(issuer: impl Into<String>) -> SetVerifierBuilder {
        SetVerifierBuilder {
            issuer: issuer.into(),
            audiences: Vec::new(),
            algorithms: Vec::new(),
            keys: None,
            iat_leeway: DEFAULT_IAT_LEEWAY,
            max_age: None,
            replay_guard: None,
        }
    }

    /// The issuer this verifier accepts SETs from.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Verifies `token` against the current system clock.
    pub async fn verify(&self, token: &str) -> Result<VerifiedSet, SetError> {
        self.verify_at(token, current_unix_time()).await
    }

    /// Verifies `token` as if the current time were `now` (seconds since the Unix epoch).
    ///
    /// Public, not test-only: a receiver that buffers SETs and validates them out of band needs
    /// to be able to say *when* it is validating, and a caller with a trusted time source should
    /// not be forced through `SystemTime::now`.
    ///
    /// The order below is load-bearing:
    ///
    /// 1. **Header, `typ`, `alg`** — cheap, and done against the raw JSON before `jsonwebtoken`'s
    ///    typed API sees it. `jsonwebtoken::Algorithm` has no variant for `none` and its
    ///    `Deserialize` hard-fails on unknown names, so a typed header parse cannot tell
    ///    `alg: "none"` from a corrupt token; this crate must, because they are a
    ///    `disallowed alg` and a `malformed` SET respectively.
    /// 2. **Key resolution and signature** — before *any* claim is trusted. Claims from an
    ///    unverified token are attacker-controlled strings, so no rejection above this line may
    ///    depend on them, and the key is resolved for the *configured* issuer rather than the
    ///    token's self-asserted `iss`.
    /// 3. **Claims** — issuer, audience, freshness, non-empty `jti`, non-empty `events`.
    /// 4. **Event payloads** — every entry of `events` is decoded here, not by the caller
    ///    afterwards. A modelled event type whose payload does not conform is an
    ///    `invalid_request` rejection just like a bad claim, so it has to be discovered before
    ///    the `jti` is spent; decoding it after this function returned would burn the slot on a
    ///    SET that is then refused, and RFC 8935 §2 retransmission of the corrected SET under
    ///    the same `jti` would be swallowed as a replay.
    /// 5. **Replay** — last, so a SET rejected for any other reason does not consume its `jti`
    ///    and thereby stop a corrected retransmission from being processed.
    pub async fn verify_at(&self, token: &str, now: i64) -> Result<VerifiedSet, SetError> {
        tracing::debug!(target: "authkestra_ssf", issuer = %self.issuer, "verifying SET");

        // --- Step 1: header, typ, alg (raw JSON, pre-`jsonwebtoken`) ---
        let header = decode_header_json(token).map_err(reject)?;

        let typ = header
            .get("typ")
            .and_then(Value::as_str)
            .ok_or(SetError::MissingType)
            .map_err(reject)?;
        if !is_set_typ(typ) {
            return Err(reject(SetError::UnexpectedType(typ.to_string())));
        }

        let alg = self.check_algorithm(&header).map_err(reject)?;
        let kid = header.get("kid").and_then(Value::as_str);

        // --- Step 2: key resolution and signature ---
        let key = self
            .keys
            .resolve(&self.issuer, kid)
            .await
            .map_err(SetError::from)
            .map_err(reject)?;
        let claims = decode_claims(token, &key, alg).map_err(reject)?;
        let set: SecurityEventToken = serde_json::from_value(claims)
            .map_err(|err| SetError::InvalidClaims(err.to_string()))
            .map_err(reject)?;

        // --- Step 3: claims ---
        self.check_issuer(&set).map_err(reject)?;
        self.check_audience(&set).map_err(reject)?;
        self.check_freshness(&set, now).map_err(reject)?;
        // Checked here rather than in the claim model, which only knows `jti` is a string: a
        // present-but-empty `jti` parses fine and would then silently defeat the replay guard
        // below, since every such SET from an issuer hashes to the same key.
        if set.jti.trim().is_empty() {
            return Err(reject(SetError::EmptyJti));
        }
        if set.events.is_empty() {
            return Err(reject(SetError::EmptyEvents));
        }

        // --- Step 4: event payloads, before the replay slot is spent ---
        let events = set.caep_events().map_err(SetError::from).map_err(reject)?;

        // --- Step 5: replay ---
        if let Some(guard) = &self.replay_guard {
            if !guard.check_and_record(&set.jti, &set.iss).await {
                return Err(reject(SetError::Replay {
                    jti: set.jti.clone(),
                    iss: set.iss.clone(),
                }));
            }
        }

        tracing::info!(
            target: "authkestra_ssf",
            iss = %set.iss,
            jti = %set.jti,
            events = events.len(),
            "accepted SET"
        );
        Ok(VerifiedSet { set, events })
    }

    fn check_algorithm(&self, header: &Value) -> Result<Algorithm, SetError> {
        let raw = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| SetError::Malformed("JOSE header has no alg".to_string()))?;

        // Checked by name, before parsing: an unsecured JWT is exactly what RFC 8417 §2.4's own
        // example uses, so a receiver will see one, and accepting it would make every other
        // check in this function decorative.
        if raw.eq_ignore_ascii_case("none") {
            return Err(SetError::DisallowedAlgorithm(
                "alg \"none\" is never accepted: an unsecured SET authenticates nothing"
                    .to_string(),
            ));
        }

        let alg: Algorithm = raw
            .parse()
            .map_err(|_| SetError::DisallowedAlgorithm(format!("unsupported alg {raw:?}")))?;

        if !self.algorithms.contains(&alg) {
            return Err(SetError::DisallowedAlgorithm(format!(
                "{alg:?} is not in this verifier's allow-list"
            )));
        }
        Ok(alg)
    }

    fn check_issuer(&self, set: &SecurityEventToken) -> Result<(), SetError> {
        if set.iss == self.issuer {
            Ok(())
        } else {
            Err(SetError::IssuerMismatch {
                expected: self.issuer.clone(),
                found: set.iss.clone(),
            })
        }
    }

    fn check_audience(&self, set: &SecurityEventToken) -> Result<(), SetError> {
        // An unconfigured audience list means "this receiver has no audience identifier of its
        // own"; RFC 8417 §2.2 only RECOMMENDs `aud`, so requiring it unconditionally would
        // reject conformant SETs. Configuring one makes the check mandatory.
        if self.audiences.is_empty() {
            return Ok(());
        }
        match &set.aud {
            None => Err(SetError::MissingAudience {
                expected: self.audiences.clone(),
            }),
            Some(aud) => {
                if self.audiences.iter().any(|expected| aud.contains(expected)) {
                    Ok(())
                } else {
                    Err(SetError::AudienceMismatch {
                        expected: self.audiences.clone(),
                    })
                }
            }
        }
    }

    fn check_freshness(&self, set: &SecurityEventToken, now: i64) -> Result<(), SetError> {
        let leeway = self.iat_leeway.as_secs() as i64;
        if set.iat > now.saturating_add(leeway) {
            return Err(SetError::IatInFuture {
                iat: set.iat,
                now,
                leeway,
            });
        }

        if let Some(max_age) = self.max_age {
            let max_age = max_age.as_secs() as i64;
            // The same leeway applies on this side too: a receiver whose clock runs fast must
            // not start calling fresh SETs stale.
            if now.saturating_sub(set.iat) > max_age.saturating_add(leeway) {
                return Err(SetError::TooOld {
                    iat: set.iat,
                    now,
                    max_age,
                });
            }
        }

        if let Some(exp) = set.exp {
            if now.saturating_sub(leeway) >= exp {
                return Err(SetError::Expired { exp, now });
            }
        }

        Ok(())
    }
}

impl SetVerifierBuilder {
    /// Adds an audience identifier this receiver answers to.
    ///
    /// Calling this at least once makes the `aud` check mandatory; leaving it unset skips the
    /// check entirely (see [`SetVerifier::verify_at`]).
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audiences.push(audience.into());
        self
    }

    /// Adds several audience identifiers at once.
    pub fn audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.audiences.extend(audiences.into_iter().map(Into::into));
        self
    }

    /// Sets the accepted JWS algorithms, replacing any previously configured.
    ///
    /// There is no way to allow `none` here: `jsonwebtoken::Algorithm` has no such variant, so
    /// the unsecured-JWT case cannot be configured in — only detected on the wire.
    pub fn algorithms(mut self, algorithms: impl IntoIterator<Item = Algorithm>) -> Self {
        self.algorithms = algorithms.into_iter().collect();
        self
    }

    /// Uses a single decoding key for every SET, regardless of `kid`.
    ///
    /// Mutually exclusive with [`SetVerifierBuilder::key_resolver`]; the last call wins.
    pub fn key(mut self, key: DecodingKey) -> Self {
        self.keys = Some(Arc::new(SingleKeyResolver::new(key)));
        self
    }

    /// Resolves the decoding key per token, by `kid` — the JWKS-backed case.
    ///
    /// Mutually exclusive with [`SetVerifierBuilder::key`]; the last call wins.
    pub fn key_resolver(mut self, resolver: Arc<dyn SetKeyResolver>) -> Self {
        self.keys = Some(resolver);
        self
    }

    /// How far into the future an `iat` may be before the SET is rejected. Defaults to 60
    /// seconds.
    pub fn iat_leeway(mut self, leeway: Duration) -> Self {
        self.iat_leeway = leeway;
        self
    }

    /// Rejects SETs whose `iat` is older than `max_age`.
    ///
    /// Off by default, because a SET is historical (RFC 8417 §2.2) and a legitimate transmitter
    /// may be replaying a backlog after an outage. Deployments that would rather drop a stale
    /// backlog than act on it opt in here.
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Installs replay protection.
    ///
    /// Off by default: RFC 8417 §2.2 says a client MAY use `jti` to track SETs it has already
    /// received, and a deployment whose handlers are idempotent may legitimately not want the
    /// state.
    pub fn replay_guard(mut self, guard: Arc<dyn SetReplayGuard>) -> Self {
        self.replay_guard = Some(guard);
        self
    }

    /// Validates the configuration and builds the verifier.
    pub fn build(self) -> Result<SetVerifier, SetVerifierError> {
        if self.issuer.trim().is_empty() {
            return Err(SetVerifierError::MissingIssuer);
        }
        if self.algorithms.is_empty() {
            return Err(SetVerifierError::NoAlgorithms);
        }
        let keys = self.keys.ok_or(SetVerifierError::MissingKeySource)?;

        Ok(SetVerifier {
            issuer: self.issuer,
            audiences: self.audiences,
            algorithms: self.algorithms,
            keys,
            iat_leeway: self.iat_leeway,
            max_age: self.max_age,
            replay_guard: self.replay_guard,
        })
    }
}

/// Logs every rejection uniformly, so no branch of the algorithm can go unobserved in production
/// (the workspace `AGENTS.md` tracing Definition of Done).
fn reject(err: SetError) -> SetError {
    // The issuer, audience and freshness variants are logged with their values as structured
    // fields rather than through `Display`, because `Display` is what the RFC 8935 §2.3 failure
    // body returns to an unauthenticated caller and must not disclose the deployment's
    // configuration — its trusted issuer, its audience identifiers, its clock leeway or its
    // maximum accepted age. Operators still get the full picture here, where the log is trusted.
    match &err {
        SetError::IssuerMismatch { expected, found } => tracing::warn!(
            target: "authkestra_ssf",
            code = %err.code(),
            error = %err,
            expected_issuer = %expected,
            found_issuer = %found,
            "rejecting SET"
        ),
        SetError::MissingAudience { expected } | SetError::AudienceMismatch { expected } => {
            tracing::warn!(
                target: "authkestra_ssf",
                code = %err.code(),
                error = %err,
                expected_audiences = ?expected,
                "rejecting SET"
            )
        }
        SetError::IatInFuture { iat, now, leeway } => tracing::warn!(
            target: "authkestra_ssf",
            code = %err.code(),
            error = %err,
            iat = iat,
            now = now,
            leeway_secs = leeway,
            "rejecting SET"
        ),
        SetError::TooOld { iat, now, max_age } => tracing::warn!(
            target: "authkestra_ssf",
            code = %err.code(),
            error = %err,
            iat = iat,
            now = now,
            max_age_secs = max_age,
            "rejecting SET"
        ),
        _ => tracing::warn!(
            target: "authkestra_ssf",
            code = %err.code(),
            error = %err,
            "rejecting SET"
        ),
    }
    err
}

/// Whether `typ` is the SET explicit type from RFC 8417 §2.3.
///
/// Both `secevent+jwt` (what §2.3 says SHOULD be used) and the full `application/secevent+jwt`
/// media type are accepted, and both case-insensitively: RFC 7515 §4.1.9 defines `typ` as a
/// media type whose `application/` prefix may be omitted, and media types are case-insensitive
/// per RFC 2045 §5.1. Rejecting `Secevent+JWT` would refuse a conformant transmitter.
fn is_set_typ(typ: &str) -> bool {
    let typ = typ.trim();
    let bare = match typ.get(..12) {
        Some(prefix) if prefix.eq_ignore_ascii_case("application/") => &typ[12..],
        _ => typ,
    };
    bare.eq_ignore_ascii_case(SET_TYP)
}

/// Base64url-decodes and JSON-parses a compact JWS's protected header.
///
/// An *empty* signature segment is accepted at this stage even though no such token can ever be
/// valid, because that is exactly the shape of the unsecured JWT in RFC 8417 §2.4's own example.
/// Rejecting it here as "malformed" would hide the far more useful `disallowed alg` diagnostic
/// that [`SetVerifier::check_algorithm`] produces two steps later.
fn decode_header_json(token: &str) -> Result<Value, SetError> {
    let mut parts = token.split('.');
    let header_b64 = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(header), Some(_), Some(_), None) if !header.is_empty() => header,
        _ => {
            return Err(SetError::Malformed(
                "expected a compact JWS with three non-empty dot-separated segments".to_string(),
            ))
        }
    };

    let bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|err| SetError::Malformed(format!("JOSE header is not base64url: {err}")))?;
    let header: Value = serde_json::from_slice(&bytes)
        .map_err(|err| SetError::Malformed(format!("JOSE header is not JSON: {err}")))?;
    if !header.is_object() {
        return Err(SetError::Malformed(
            "JOSE header is not a JSON object".to_string(),
        ));
    }
    Ok(header)
}

/// Verifies the signature and returns the raw claims.
///
/// Every time-based check `jsonwebtoken` offers is switched off here and re-done in
/// [`SetVerifier::check_freshness`]: its `exp` handling is mandatory-by-default, which is the
/// opposite of RFC 8417 §2.2, and its errors are not granular enough to map onto the RFC 8935
/// §2.4 error codes.
fn decode_claims(token: &str, key: &DecodingKey, alg: Algorithm) -> Result<Value, SetError> {
    let mut validation = Validation::new(alg);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    // Exactly the one algorithm the header named — and which was already checked against the
    // verifier's allow-list — so the key can never be used with a different family.
    validation.algorithms = vec![alg];

    decode::<Value>(token, key, &validation)
        .map(|data| data.claims)
        .map_err(map_jwt_error)
}

fn map_jwt_error(err: jsonwebtoken::errors::Error) -> SetError {
    match err.kind() {
        ErrorKind::InvalidToken | ErrorKind::Base64(_) | ErrorKind::Utf8(_) => {
            SetError::Malformed(err.to_string())
        }
        ErrorKind::Json(_) => SetError::InvalidClaims(err.to_string()),
        ErrorKind::InvalidAlgorithm
        | ErrorKind::InvalidKeyFormat
        | ErrorKind::InvalidEcdsaKey
        | ErrorKind::InvalidEddsaKey
        | ErrorKind::InvalidRsaKey(_)
        | ErrorKind::UnsupportedAlgorithm
        | ErrorKind::MissingAlgorithm => SetError::DisallowedAlgorithm(err.to_string()),
        // Everything else means "we could not authenticate this token", which is what
        // RFC 8935's `authentication_failed` is for. Notably `InvalidSignature`.
        _ => SetError::InvalidSignature(err.to_string()),
    }
}

fn current_unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_both_spellings_of_the_set_type() {
        assert!(is_set_typ("secevent+jwt"));
        assert!(is_set_typ("application/secevent+jwt"));
        assert!(is_set_typ("Application/SecEvent+JWT"));
        assert!(is_set_typ("  secevent+jwt  "));
    }

    #[test]
    fn rejects_other_types() {
        assert!(!is_set_typ("JWT"));
        assert!(!is_set_typ("at+jwt"));
        assert!(!is_set_typ(""));
        assert!(!is_set_typ("application/jwt"));
        // A multi-byte prefix must not panic the byte-slicing shortcut.
        assert!(!is_set_typ("æææææææææææ/secevent+jwt"));
    }

    #[test]
    fn header_decoding_rejects_non_compact_input() {
        for token in ["", "a.b", "a.b.c.d", ".b.c"] {
            let err = decode_header_json(token).unwrap_err();
            assert!(matches!(err, SetError::Malformed(_)), "{token:?}: {err:?}");
        }
    }

    #[test]
    fn header_decoding_tolerates_an_empty_signature_segment() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"secevent+jwt","alg":"none"}"#);
        let header = decode_header_json(&format!("{header}.payload.")).unwrap();
        assert_eq!(header["alg"], "none");
    }

    #[test]
    fn header_decoding_rejects_bad_base64_and_bad_json() {
        let err = decode_header_json("!!!.payload.sig").unwrap_err();
        assert!(err.to_string().contains("base64url"), "{err}");

        let not_json = URL_SAFE_NO_PAD.encode(b"not json");
        let err = decode_header_json(&format!("{not_json}.payload.sig")).unwrap_err();
        assert!(err.to_string().contains("not JSON"), "{err}");

        let not_object = URL_SAFE_NO_PAD.encode(b"\"a string\"");
        let err = decode_header_json(&format!("{not_object}.payload.sig")).unwrap_err();
        assert!(err.to_string().contains("not a JSON object"), "{err}");
    }

    #[test]
    fn header_decoding_accepts_a_well_formed_header() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"secevent+jwt","alg":"HS256"}"#);
        let header = decode_header_json(&format!("{header}.payload.sig")).unwrap();
        assert_eq!(header["alg"], "HS256");
    }

    fn verifier() -> SetVerifier {
        SetVerifier::builder("https://idp.example.com/")
            .algorithms([Algorithm::HS256])
            .key(DecodingKey::from_secret(b"secret"))
            .build()
            .unwrap()
    }

    #[test]
    fn builder_rejects_incomplete_configuration() {
        assert_eq!(
            SetVerifier::builder("   ")
                .algorithms([Algorithm::HS256])
                .key(DecodingKey::from_secret(b"s"))
                .build()
                .unwrap_err(),
            SetVerifierError::MissingIssuer
        );
        assert_eq!(
            SetVerifier::builder("https://idp/")
                .key(DecodingKey::from_secret(b"s"))
                .build()
                .unwrap_err(),
            SetVerifierError::NoAlgorithms
        );
        assert_eq!(
            SetVerifier::builder("https://idp/")
                .algorithms([Algorithm::HS256])
                .build()
                .unwrap_err(),
            SetVerifierError::MissingKeySource
        );
        for err in [
            SetVerifierError::MissingIssuer,
            SetVerifierError::NoAlgorithms,
            SetVerifierError::MissingKeySource,
        ] {
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn builder_exposes_the_configured_issuer() {
        assert_eq!(verifier().issuer(), "https://idp.example.com/");
    }

    #[test]
    fn audiences_accumulate_across_both_setters() {
        let verifier = SetVerifier::builder("https://idp/")
            .audience("one")
            .audiences(["two", "three"])
            .algorithms([Algorithm::HS256])
            .key(DecodingKey::from_secret(b"s"))
            .build()
            .unwrap();

        let mut set = set_with(0, None);
        set.iss = "https://idp/".into();
        for accepted in ["one", "two", "three"] {
            set.aud = Some(crate::set::Audience::Single(accepted.to_string()));
            assert!(verifier.check_audience(&set).is_ok(), "{accepted}");
        }
        set.aud = Some(crate::set::Audience::Single("four".to_string()));
        assert!(matches!(
            verifier.check_audience(&set),
            Err(SetError::AudienceMismatch { .. })
        ));
    }

    #[test]
    fn algorithm_check_rejects_none_unknown_and_unlisted() {
        let verifier = verifier();

        let err = verifier
            .check_algorithm(&serde_json::json!({ "alg": "none" }))
            .unwrap_err();
        assert!(err.to_string().contains("none"), "{err}");

        let err = verifier
            .check_algorithm(&serde_json::json!({ "alg": "NoNe" }))
            .unwrap_err();
        assert!(err.to_string().contains("none"), "{err}");

        let err = verifier
            .check_algorithm(&serde_json::json!({ "alg": "XS999" }))
            .unwrap_err();
        assert!(err.to_string().contains("unsupported"), "{err}");

        let err = verifier
            .check_algorithm(&serde_json::json!({ "alg": "RS256" }))
            .unwrap_err();
        assert!(err.to_string().contains("allow-list"), "{err}");

        let err = verifier
            .check_algorithm(&serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, SetError::Malformed(_)), "{err:?}");

        assert_eq!(
            verifier
                .check_algorithm(&serde_json::json!({ "alg": "HS256" }))
                .unwrap(),
            Algorithm::HS256
        );
    }

    fn set_with(iat: i64, exp: Option<i64>) -> SecurityEventToken {
        SecurityEventToken {
            iss: "https://idp.example.com/".into(),
            jti: "jti".into(),
            iat,
            aud: None,
            sub: None,
            sub_id: None,
            txn: None,
            toe: None,
            exp,
            nbf: None,
            events: Default::default(),
            additional: Default::default(),
        }
    }

    #[test]
    fn freshness_honours_leeway_max_age_and_exp() {
        let verifier = SetVerifier::builder("https://idp.example.com/")
            .algorithms([Algorithm::HS256])
            .key(DecodingKey::from_secret(b"secret"))
            .iat_leeway(Duration::from_secs(10))
            .max_age(Duration::from_secs(100))
            .build()
            .unwrap();

        // Inside the leeway window.
        assert!(verifier
            .check_freshness(&set_with(1_010, None), 1_000)
            .is_ok());
        // Beyond it.
        assert!(matches!(
            verifier.check_freshness(&set_with(1_011, None), 1_000),
            Err(SetError::IatInFuture { .. })
        ));
        // Within max_age + leeway.
        assert!(verifier
            .check_freshness(&set_with(890, None), 1_000)
            .is_ok());
        assert!(matches!(
            verifier.check_freshness(&set_with(889, None), 1_000),
            Err(SetError::TooOld { .. })
        ));
        // exp is honoured when present, with the same leeway.
        assert!(verifier
            .check_freshness(&set_with(1_000, Some(991)), 1_000)
            .is_ok());
        assert!(matches!(
            verifier.check_freshness(&set_with(1_000, Some(990)), 1_000),
            Err(SetError::Expired { .. })
        ));
    }

    #[test]
    fn freshness_without_max_age_accepts_arbitrarily_old_sets() {
        let verifier = verifier();
        assert!(verifier
            .check_freshness(&set_with(0, None), 2_000_000_000)
            .is_ok());
    }

    #[test]
    fn issuer_check_compares_exactly() {
        let verifier = verifier();
        assert!(verifier.check_issuer(&set_with(0, None)).is_ok());

        let mut other = set_with(0, None);
        other.iss = "https://evil.example.com/".into();
        assert!(matches!(
            verifier.check_issuer(&other),
            Err(SetError::IssuerMismatch { .. })
        ));
    }

    #[test]
    fn audience_check_is_skipped_when_unconfigured() {
        assert!(verifier().check_audience(&set_with(0, None)).is_ok());
    }

    #[test]
    fn map_jwt_error_classifies_by_kind() {
        use jsonwebtoken::errors::Error;
        assert!(matches!(
            map_jwt_error(Error::from(ErrorKind::InvalidToken)),
            SetError::Malformed(_)
        ));
        assert!(matches!(
            map_jwt_error(Error::from(ErrorKind::InvalidSignature)),
            SetError::InvalidSignature(_)
        ));
        assert!(matches!(
            map_jwt_error(Error::from(ErrorKind::InvalidAlgorithm)),
            SetError::DisallowedAlgorithm(_)
        ));
        assert!(matches!(
            map_jwt_error(Error::from(ErrorKind::InvalidKeyFormat)),
            SetError::DisallowedAlgorithm(_)
        ));
        let json_error = serde_json::from_str::<i32>("not a number").unwrap_err();
        assert!(matches!(
            map_jwt_error(Error::from(ErrorKind::Json(std::sync::Arc::new(
                json_error
            )))),
            SetError::InvalidClaims(_)
        ));
        assert!(matches!(
            map_jwt_error(Error::from(ErrorKind::MissingRequiredClaim("iss".into()))),
            SetError::InvalidSignature(_)
        ));
    }

    #[test]
    fn current_unix_time_is_after_2020() {
        assert!(current_unix_time() > 1_577_836_800);
    }
}
