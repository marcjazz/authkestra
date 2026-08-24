//! SD-JWT (Selective Disclosure for JWTs) issuance and verification, per
//! `draft-ietf-oauth-selective-disclosure-jwt`.
//!
//! An SD-JWT lets an issuer mint a single signed token that carries some
//! claims in the clear and others only as *digests* (`_sd[]`), plus a
//! separate list of *Disclosures* — `[salt, claim_name, claim_value]`
//! triples — that reveal what each digest stands for. A holder decides,
//! per presentation, which Disclosures to forward alongside the JWT; a
//! verifier can only recover the claims for the Disclosures it was handed,
//! and can cryptographically prove every disclosed value was actually
//! vouched for by the issuer (its digest is in `_sd[]`, which is inside
//! the signed payload) without the issuer needing to mint one token per
//! disclosure combination.
//!
//! # What this module does and does not implement
//!
//! In scope: issuing and verifying **flat, top-level, object-property**
//! Disclosures, serialized in SD-JWT compact form (`<jwt>~<d1>~<d2>~`).
//!
//! Deliberately out of scope (spec features this module does not touch):
//! - **Key Binding JWT (KB-JWT)** — holder proof-of-possession. This module
//!   verifies the issuer's signature and the Disclosure digests only; it
//!   has no notion of a holder key or a `~<kb-jwt>` suffix.
//! - **Array-element and recursive/nested Disclosures** — only flat
//!   top-level object properties are supported, matching every consumer
//!   this crate has today.
//! - **SD-JWT VC** (`vc+sd-jwt`) — no `vct`/type metadata handling.
//!
//! None of these are hard to misuse into thinking they're covered — there
//! is simply no code path for them. A caller needing KB-JWT or nested
//! disclosures needs to build that on top, not assume it's already here.
//!
//! # Security properties this module enforces (and why)
//!
//! - **`_sd_alg` is never silently defaulted to `sha-256` when present and
//!   unrecognized.** A verifier that treats an unknown digest algorithm as
//!   "must mean sha-256" is an algorithm-confusion bug: an attacker who
//!   controls (or can influence) the claimed `_sd_alg` could otherwise
//!   coax a verifier into hashing Disclosures with a weaker/attacker-
//!   favorable function while the verifier's logic still believes it's
//!   checking sha-256 digests. This module fails closed instead: an
//!   absent `_sd_alg` defaults to sha-256 (per spec, the assumed default),
//!   but a *present-and-different* value is rejected outright.
//! - **A presented Disclosure whose digest is not found in `_sd[]` fails
//!   the whole verification**, not just that one claim. Accepting it would
//!   let a holder (or a network attacker who can append to the compact
//!   form) inject arbitrary claims the issuer never signed for — the
//!   entire point of `_sd[]` living inside the signed JWT payload is that
//!   only digests the issuer actually put there are trustworthy.
//! - **Duplicate digests in `_sd[]` are rejected.** They serve no
//!   legitimate purpose (each Disclosure is independently salted, so two
//!   honestly-generated Disclosures never collide) and are a cheap way to
//!   smuggle a second, attacker-chosen Disclosure past the "digest found"
//!   check above once one legitimate Disclosure's digest becomes known.
//! - **A disclosed claim can never shadow a registered top-level JWT claim
//!   (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`) or an
//!   already-present `extra` claim.** Selective disclosure is additive by
//!   design; letting a Disclosure silently overwrite `aud` or `exp` would
//!   let a holder forge the very claims the issuer's signature is supposed
//!   to pin down.

use super::{Claims, TokenManager};
use crate::auth::error::AuthError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::Header;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// The only digest algorithm this module issues or accepts. Per
/// `draft-ietf-oauth-selective-disclosure-jwt`, `_sd_alg` is OPTIONAL and
/// `sha-256` is the assumed default when it's absent — but see the module
/// docs above for why a *present* value that isn't this one is rejected,
/// never coerced into this one.
const SD_ALG_SHA256: &str = "sha-256";

/// Claim names a Disclosure is never allowed to introduce, because they
/// are either registered top-level [`Claims`] fields (forging them would
/// let a holder rewrite the token's own identity/validity claims) or the
/// SD-JWT mechanism's own bookkeeping keys.
const RESERVED_CLAIM_NAMES: &[&str] = &[
    "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "scope", "identity", "_sd", "_sd_alg",
];

/// A claim an issuer wants to make selectively disclosable, instead of
/// stamping it directly onto the JWT payload.
///
/// Handed to [`TokenManager::issue_sd_jwt`] in a batch; each one becomes
/// one Disclosure (with its own fresh salt — see
/// [`generate_disclosure_salt`]) and one digest in the issued token's
/// `_sd[]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosableClaim {
    /// The claim name, e.g. `"email"`. Must not collide with a
    /// [`RESERVED_CLAIM_NAMES`] entry — [`TokenManager::issue_sd_jwt`]
    /// does not currently validate this at issuance time (that check is
    /// enforced on the verify side, where it actually matters for
    /// security); an issuer accidentally naming a Disclosure `"aud"`
    /// simply produces a Disclosure no verifier using this module will
    /// ever accept.
    pub name: String,
    /// The claim value. Any JSON value is accepted (object, array,
    /// string, number, bool, null) — this module does not interpret it.
    pub value: Value,
}

impl DisclosableClaim {
    /// Convenience constructor so callers don't have to name the struct
    /// fields at every call site.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use authkestra_engine::token::sd_jwt::DisclosableClaim;
    /// let claim = DisclosableClaim::new("email", "user@example.com");
    /// assert_eq!(claim.name, "email");
    /// ```
    pub fn new(name: impl Into<String>, value: impl Into<Value>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// The result of issuing an SD-JWT: the signed JWT, the SD-JWT compact
/// serialization ready to hand to a holder, and the raw Disclosure strings
/// (in case the caller wants to persist or selectively re-forward a subset
/// later, e.g. to build a holder-controlled presentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedSdJwt {
    /// The Issuer-signed JWT alone — three dot-separated segments, no `~`.
    /// Useful for callers that want to store the JWT and Disclosures
    /// separately rather than as one compact string.
    pub jwt: String,
    /// SD-JWT compact serialization: `<jwt>~<disclosure_1>~...~<disclosure_n>~`
    /// (a trailing `~` and no Key Binding JWT segment, since KB-JWT is out
    /// of scope for this module — see the module docs). If
    /// `disclosable_claims` was empty, this equals `jwt` with no `~`
    /// appended at all, matching a plain (non-SD) JWT.
    pub compact: String,
    /// The base64url-encoded Disclosure strings, in the same order as the
    /// `disclosable_claims` they were built from.
    pub disclosures: Vec<String>,
}

/// The result of verifying a presented SD-JWT compact form: the validated
/// JWT claims (signature, `iss`/`aud`/`exp` already checked by
/// [`TokenManager::validate_token`]) plus whatever claims the presented
/// Disclosures actually proved out.
///
/// `disclosed_claims` only contains claims from Disclosures that were
/// *both* presented *and* verified against `_sd[]` — a claim whose digest
/// the issuer never signed for cannot appear here (see
/// [`TokenManager::validate_sd_jwt`]'s rejection rules).
#[derive(Debug, Clone)]
pub struct VerifiedSdJwt {
    /// The underlying JWT claims, already validated (signature, issuer,
    /// audience, expiry) by [`TokenManager::validate_token`].
    pub claims: Claims,
    /// Claim name -> value, recovered from the presented Disclosures that
    /// verified successfully.
    pub disclosed_claims: HashMap<String, Value>,
}

/// Generates a fresh, cryptographically random salt for one Disclosure.
///
/// Per `draft-ietf-oauth-selective-disclosure-jwt` §5.2.1, each Disclosure
/// needs its own salt with "sufficient entropy" — the spec's own examples
/// use 128 bits. This uses the workspace's existing CSPRNG (`rand`, the
/// same `rand::rng()` source already used for OAuth `state`/`nonce` and
/// AES-GCM nonces elsewhere in this crate — see `auth::state::OAuth2State`)
/// rather than pulling in a dedicated RNG dependency. Reusing a salt across
/// Disclosures — e.g. deriving it from the claim name/value instead of
/// generating it fresh — would let two verifiers who both learn the same
/// claim name/value pair recognize they're looking at the same subject
/// even without ever seeing the digest, defeating the unlinkability this
/// mechanism exists to provide.
fn generate_disclosure_salt() -> String {
    let mut salt_bytes = [0u8; 16]; // 128 bits, matching the spec's own examples.
    rand::rng().fill_bytes(&mut salt_bytes);
    URL_SAFE_NO_PAD.encode(salt_bytes)
}

/// Base64url (no padding) of the SHA-256 digest of an encoded Disclosure
/// string — the value that goes into `_sd[]`, per §5.2.1.
fn disclosure_digest(encoded_disclosure: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(encoded_disclosure.as_bytes()))
}

/// Builds one Disclosure — `base64url(json([salt, name, value]))` — and its
/// digest, from a [`DisclosableClaim`].
fn encode_disclosure(claim: &DisclosableClaim) -> Result<(String, String), AuthError> {
    let salt = generate_disclosure_salt();
    let triple = serde_json::json!([salt, claim.name, claim.value]);
    let bytes = serde_json::to_vec(&triple)
        .map_err(|e| AuthError::Token(format!("failed to encode SD-JWT disclosure: {e}")))?;
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    let digest = disclosure_digest(&encoded);
    Ok((encoded, digest))
}

/// Splits an SD-JWT compact form into its JWT segment and its Disclosure
/// strings. Tolerates a plain (non-SD) JWT with no `~` at all — the whole
/// input is then returned as the JWT with an empty Disclosure list — and a
/// trailing `~` with nothing after it (an empty final segment from
/// `split('~')`, filtered out).
fn split_sd_jwt(compact: &str) -> (&str, Vec<String>) {
    let mut parts = compact.split('~');
    let jwt = parts.next().unwrap_or(compact);
    let disclosures = parts
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
        .collect();
    (jwt, disclosures)
}

/// Decodes one Disclosure string into its `(claim_name, claim_value)` pair,
/// without checking it against any `_sd[]` digest set — that check is the
/// caller's job (see [`verify_disclosures`]). Rejects anything that isn't
/// valid base64url JSON, or whose decoded array isn't exactly the
/// `[salt, name, value]` triple the spec requires (the salt itself is
/// discarded here; its only job was to make the digest unguessable).
fn decode_disclosure(encoded: &str) -> Result<(String, Value), AuthError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| AuthError::Token(format!("invalid SD-JWT disclosure encoding: {e}")))?;
    let triple: Vec<Value> = serde_json::from_slice(&bytes)
        .map_err(|e| AuthError::Token(format!("invalid SD-JWT disclosure JSON: {e}")))?;
    if triple.len() != 3 {
        return Err(AuthError::Token(
            "SD-JWT disclosure must be a [salt, claim_name, claim_value] triple".to_string(),
        ));
    }
    let mut fields = triple.into_iter();
    let _salt = fields.next();
    let name = fields
        .next()
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or_else(|| {
            AuthError::Token("SD-JWT disclosure claim name must be a JSON string".to_string())
        })?;
    let value = fields.next().unwrap_or(Value::Null);
    Ok((name, value))
}

/// Checks the presented Disclosures against the validated JWT's `_sd[]`/
/// `_sd_alg`, per the security rules documented on the module itself.
/// Returns the recovered `name -> value` map, or the first rejection
/// reason encountered.
fn verify_disclosures(
    claims: &Claims,
    disclosure_strings: &[String],
) -> Result<HashMap<String, Value>, AuthError> {
    if disclosure_strings.is_empty() {
        return Ok(HashMap::new());
    }

    if let Some(alg_value) = claims.extra.get("_sd_alg") {
        let alg = alg_value
            .as_str()
            .ok_or_else(|| AuthError::Token("_sd_alg claim must be a JSON string".to_string()))?;
        if alg != SD_ALG_SHA256 {
            tracing::warn!(
                sd_alg = %alg,
                "rejecting SD-JWT: unrecognized _sd_alg, refusing to default to sha-256"
            );
            return Err(AuthError::Token(format!(
                "unsupported SD-JWT _sd_alg '{alg}': only '{SD_ALG_SHA256}' is supported, \
                 and an unrecognized value is rejected rather than assumed to mean sha-256"
            )));
        }
    }

    let sd_entries = claims
        .extra
        .get("_sd")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut known_digests: HashSet<String> = HashSet::with_capacity(sd_entries.len());
    for entry in &sd_entries {
        let digest = entry
            .as_str()
            .ok_or_else(|| AuthError::Token("_sd entries must be JSON strings".to_string()))?
            .to_string();
        if !known_digests.insert(digest.clone()) {
            tracing::warn!(digest = %digest, "rejecting SD-JWT: duplicate digest in _sd[]");
            return Err(AuthError::Token(format!(
                "duplicate digest in SD-JWT _sd[]: {digest}"
            )));
        }
    }

    let mut disclosed = HashMap::with_capacity(disclosure_strings.len());
    for encoded in disclosure_strings {
        let digest = disclosure_digest(encoded);
        if !known_digests.contains(&digest) {
            tracing::warn!(
                digest = %digest,
                "rejecting SD-JWT: presented disclosure digest not found in _sd[]"
            );
            return Err(AuthError::Token(
                "presented SD-JWT disclosure digest is not present in _sd[]".to_string(),
            ));
        }

        let (name, value) = decode_disclosure(encoded)?;
        if RESERVED_CLAIM_NAMES.contains(&name.as_str()) || claims.extra.contains_key(&name) {
            tracing::warn!(
                claim_name = %name,
                "rejecting SD-JWT: disclosed claim shadows a registered or already-present claim"
            );
            return Err(AuthError::Token(format!(
                "SD-JWT disclosure claim name '{name}' shadows a registered or already-present claim"
            )));
        }

        disclosed.insert(name, value);
    }

    tracing::debug!(
        disclosed_count = disclosed.len(),
        "verified SD-JWT disclosures"
    );
    Ok(disclosed)
}

impl TokenManager {
    /// Issues an SD-JWT: a JWT whose payload carries `_sd[]` digests (and
    /// `_sd_alg`) for each of `disclosable_claims`, plus the matching
    /// Disclosure strings, serialized to SD-JWT compact form.
    ///
    /// Works with whichever signing algorithm this `TokenManager` was
    /// constructed with — HS256 ([`TokenManager::new`]), RS256
    /// ([`TokenManager::new_asymmetric`]), or Ed25519
    /// ([`TokenManager::new_ed25519`]) — since the SD-JWT mechanism only
    /// concerns the *payload* (which claims are digested vs. plain), not
    /// how the JWT itself gets signed.
    ///
    /// `sub`/`expires_in_secs`/`aud`/`scope` populate the same standard
    /// claims as [`TokenManager::issue_client_token_with_extra`]; `extra`
    /// is stamped the same way (including the `extra["jti"]` override —
    /// see [`super::take_jti`]). If `disclosable_claims` is empty, the
    /// result is a plain JWT: no `_sd`/`_sd_alg` claims are added, and
    /// `compact == jwt` with no trailing `~`.
    ///
    /// Reusing a claim name across `disclosable_claims`, or clashing with
    /// a key already in `extra`, is not rejected at issuance — each
    /// becomes its own Disclosure/digest, and a verifier will happily
    /// accept whichever ones it's shown. Callers that need "exactly one
    /// value per name" are responsible for enforcing that themselves; nothing
    /// about the wire format requires it.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use authkestra_engine::token::sd_jwt::DisclosableClaim;
    /// # use authkestra_engine::TokenManager;
    /// # use std::collections::HashMap;
    /// let manager = TokenManager::new(b"example-secret", Some("issuer".to_string()));
    /// let issued = manager.issue_sd_jwt(
    ///     "user-1".to_string(),
    ///     3600,
    ///     None,
    ///     None,
    ///     vec![DisclosableClaim::new("email", "user@example.com")],
    ///     HashMap::new(),
    /// )?;
    /// assert_eq!(issued.disclosures.len(), 1);
    /// assert!(issued.compact.starts_with(&issued.jwt));
    /// # Ok::<(), authkestra_engine::AuthError>(())
    /// ```
    #[tracing::instrument(skip(self, extra, disclosable_claims), fields(sub = %sub, disclosure_count = disclosable_claims.len()))]
    pub fn issue_sd_jwt(
        &self,
        sub: String,
        expires_in_secs: u64,
        aud: Option<String>,
        scope: Option<String>,
        disclosable_claims: Vec<DisclosableClaim>,
        mut extra: HashMap<String, Value>,
    ) -> Result<IssuedSdJwt, AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let expiration = now + expires_in_secs as usize;
        let jti = super::take_jti(&mut extra);

        let mut digests = Vec::with_capacity(disclosable_claims.len());
        let mut disclosures = Vec::with_capacity(disclosable_claims.len());
        for claim in &disclosable_claims {
            let (encoded, digest) = encode_disclosure(claim)?;
            digests.push(Value::String(digest));
            disclosures.push(encoded);
        }

        if !disclosures.is_empty() {
            tracing::debug!(
                disclosure_count = disclosures.len(),
                "stamping _sd/_sd_alg claims onto SD-JWT"
            );
            extra.insert("_sd".to_string(), Value::Array(digests));
            extra.insert(
                "_sd_alg".to_string(),
                Value::String(SD_ALG_SHA256.to_string()),
            );
        }

        let claims = Claims {
            iss: self.issuer.clone(),
            sub,
            aud: aud.map(super::Audience::from),
            exp: expiration,
            iat: now,
            nbf: Some(now),
            jti: Some(jti),
            scope,
            identity: None,
            extra,
        };

        let mut header = Header::new(self.alg);
        if let Some(ref kid) = self.kid {
            header.kid = Some(kid.clone());
        }

        let jwt = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AuthError::Token(e.to_string()))?;

        let mut compact = jwt.clone();
        for disclosure in &disclosures {
            compact.push('~');
            compact.push_str(disclosure);
        }
        if !disclosures.is_empty() {
            compact.push('~');
        }

        tracing::info!("issued SD-JWT");
        Ok(IssuedSdJwt {
            jwt,
            compact,
            disclosures,
        })
    }

    /// Verifies a presented SD-JWT compact form (`<jwt>~<d1>~...~`, or a
    /// plain JWT with no `~` segments): validates the underlying JWT
    /// exactly as [`TokenManager::validate_token`] does (signature,
    /// issuer, audience, expiry), then checks every presented Disclosure
    /// against the validated `_sd[]`/`_sd_alg`, per the module-level
    /// security rules.
    ///
    /// Rejects the whole presentation — not just the offending claim — if
    /// any Disclosure fails: digest not found in `_sd[]`, a duplicate
    /// digest in `_sd[]`, an unrecognized (present-and-different)
    /// `_sd_alg`, or a disclosed claim name that shadows a registered or
    /// already-present claim. See the module docs for why each of these
    /// has to fail closed rather than degrading gracefully.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use authkestra_engine::token::sd_jwt::DisclosableClaim;
    /// # use authkestra_engine::TokenManager;
    /// # use std::collections::HashMap;
    /// let manager = TokenManager::new(b"example-secret", Some("issuer".to_string()));
    /// let issued = manager.issue_sd_jwt(
    ///     "user-1".to_string(),
    ///     3600,
    ///     None,
    ///     None,
    ///     vec![DisclosableClaim::new("email", "user@example.com")],
    ///     HashMap::new(),
    /// )?;
    ///
    /// // A holder can present the full compact form...
    /// let verified = manager.validate_sd_jwt(&issued.compact, None)?;
    /// assert_eq!(
    ///     verified.disclosed_claims.get("email"),
    ///     Some(&serde_json::Value::String("user@example.com".to_string()))
    /// );
    ///
    /// // ...or withhold the Disclosure entirely and present the bare JWT.
    /// let bare = manager.validate_sd_jwt(&issued.jwt, None)?;
    /// assert!(bare.disclosed_claims.is_empty());
    /// # Ok::<(), authkestra_engine::AuthError>(())
    /// ```
    #[tracing::instrument(skip(self, presented))]
    pub fn validate_sd_jwt(
        &self,
        presented: &str,
        expected_aud: Option<&str>,
    ) -> Result<VerifiedSdJwt, AuthError> {
        let (jwt, disclosure_strings) = split_sd_jwt(presented);
        let claims = self.validate_token(jwt, expected_aud)?;
        let disclosed_claims = verify_disclosures(&claims, &disclosure_strings)?;
        Ok(VerifiedSdJwt {
            claims,
            disclosed_claims,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Throwaway Ed25519 private key (PKCS#8 PEM), test-only. Same key used
    /// in `token::mod`'s own test suite.
    const TEST_ED25519_PRIVATE_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKIPR2jojpdobYr1M/pjIRuMONpZGYQ+y5yxSqKX9T9/
-----END PRIVATE KEY-----";

    fn hs256_manager() -> TokenManager {
        TokenManager::new(b"sd-jwt-test-secret", Some("issuer".to_string()))
    }

    fn ed25519_manager() -> TokenManager {
        TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("ed25519-kid".to_string()),
        )
        .expect("test Ed25519 key must construct a TokenManager")
    }

    fn sample_disclosures() -> Vec<DisclosableClaim> {
        vec![
            DisclosableClaim::new("email", Value::String("user@example.com".to_string())),
            DisclosableClaim::new("is_over_18", Value::Bool(true)),
        ]
    }

    /// Round trip: issue with disclosures, verify presenting all of them,
    /// recover both claim values — on HS256.
    #[test]
    fn hs256_round_trip_issue_and_verify_all_disclosures() {
        let manager = hs256_manager();
        let issued = manager
            .issue_sd_jwt(
                "user-1".to_string(),
                3600,
                Some("client-1".to_string()),
                None,
                sample_disclosures(),
                HashMap::new(),
            )
            .expect("issuance should succeed");

        assert_eq!(issued.disclosures.len(), 2);
        assert!(issued.compact.starts_with(&issued.jwt));
        assert!(issued.compact.ends_with('~'));

        let verified = manager
            .validate_sd_jwt(&issued.compact, Some("client-1"))
            .expect("verification should succeed");

        assert_eq!(verified.claims.sub, "user-1");
        assert_eq!(
            verified.disclosed_claims.get("email"),
            Some(&Value::String("user@example.com".to_string()))
        );
        assert_eq!(
            verified.disclosed_claims.get("is_over_18"),
            Some(&Value::Bool(true))
        );
    }

    /// Same round trip, on the Ed25519 signer — proves the SD-JWT
    /// mechanism composes with every signing algorithm this crate
    /// supports, not just HS256.
    #[test]
    fn ed25519_round_trip_issue_and_verify_all_disclosures() {
        let manager = ed25519_manager();
        let issued = manager
            .issue_sd_jwt(
                "user-2".to_string(),
                3600,
                None,
                None,
                sample_disclosures(),
                HashMap::new(),
            )
            .expect("issuance should succeed");

        let verified = manager
            .validate_sd_jwt(&issued.compact, None)
            .expect("verification should succeed");

        assert_eq!(verified.claims.sub, "user-2");
        assert_eq!(verified.disclosed_claims.len(), 2);
    }

    /// A holder is allowed to withhold a Disclosure: presenting only one
    /// of two issued Disclosures verifies fine, and only that one claim is
    /// recovered.
    #[test]
    fn selective_presentation_of_a_subset_of_disclosures_succeeds() {
        let manager = hs256_manager();
        let issued = manager
            .issue_sd_jwt(
                "user-1".to_string(),
                3600,
                None,
                None,
                sample_disclosures(),
                HashMap::new(),
            )
            .expect("issuance should succeed");

        // Hand-build a presentation carrying only the first disclosure.
        let partial = format!("{}~{}~", issued.jwt, issued.disclosures[0]);

        let verified = manager
            .validate_sd_jwt(&partial, None)
            .expect("presenting a subset of disclosures should still verify");

        assert_eq!(verified.disclosed_claims.len(), 1);
        assert!(verified.disclosed_claims.contains_key("email"));
        assert!(!verified.disclosed_claims.contains_key("is_over_18"));
    }

    /// Presenting zero disclosures (a bare JWT, no `~`) against a token
    /// that does carry `_sd[]` must still verify — the standard claims are
    /// unaffected, and `disclosed_claims` is simply empty.
    #[test]
    fn presenting_the_bare_jwt_with_no_disclosures_still_verifies() {
        let manager = hs256_manager();
        let issued = manager
            .issue_sd_jwt(
                "user-1".to_string(),
                3600,
                None,
                None,
                sample_disclosures(),
                HashMap::new(),
            )
            .expect("issuance should succeed");

        let verified = manager
            .validate_sd_jwt(&issued.jwt, None)
            .expect("bare JWT without disclosures should still verify");

        assert_eq!(verified.claims.sub, "user-1");
        assert!(verified.disclosed_claims.is_empty());
    }

    /// Issuing with an empty disclosure list produces a plain JWT: no
    /// `_sd`/`_sd_alg` claims, and `compact == jwt` (no trailing `~`).
    #[test]
    fn issuing_with_no_disclosures_yields_a_plain_jwt() {
        let manager = hs256_manager();
        let issued = manager
            .issue_sd_jwt(
                "user-1".to_string(),
                3600,
                None,
                None,
                Vec::new(),
                HashMap::new(),
            )
            .expect("issuance should succeed");

        assert_eq!(issued.compact, issued.jwt);
        assert!(!issued.compact.contains('~'));

        let verified = manager
            .validate_sd_jwt(&issued.compact, None)
            .expect("plain JWT should still verify via validate_sd_jwt");
        assert!(!verified.claims.extra.contains_key("_sd"));
        assert!(!verified.claims.extra.contains_key("_sd_alg"));
    }

    /// Security rule: an unrecognized `_sd_alg` must be rejected outright,
    /// never treated as though it meant sha-256. Constructed by hand since
    /// `issue_sd_jwt` itself only ever stamps `"sha-256"`.
    #[test]
    fn unrecognized_sd_alg_is_rejected_not_defaulted() {
        let manager = hs256_manager();
        let mut extra = HashMap::new();
        let (encoded, digest) = encode_disclosure(&DisclosableClaim::new(
            "email",
            Value::String("user@example.com".to_string()),
        ))
        .unwrap();
        extra.insert("_sd".to_string(), serde_json::json!([digest]));
        extra.insert("_sd_alg".to_string(), serde_json::json!("sha-1"));

        let jwt = manager
            .issue_client_token_with_extra("client-1", 3600, None, None, extra)
            .expect("hand-built token should issue");
        let presented = format!("{jwt}~{encoded}~");

        let err = manager
            .validate_sd_jwt(&presented, None)
            .expect_err("an unrecognized _sd_alg must be rejected");
        assert!(
            err.to_string().contains("_sd_alg"),
            "error should mention _sd_alg, got: {err}"
        );
    }

    /// Security rule: a presented disclosure whose digest is absent from
    /// `_sd[]` must be rejected — a holder cannot inject a claim the
    /// issuer never signed for.
    #[test]
    fn disclosure_digest_not_in_sd_is_rejected() {
        let manager = hs256_manager();
        let issued = manager
            .issue_sd_jwt(
                "user-1".to_string(),
                3600,
                None,
                None,
                sample_disclosures(),
                HashMap::new(),
            )
            .expect("issuance should succeed");

        // Forge a disclosure for a claim the issuer never included.
        let (forged_encoded, _forged_digest) = encode_disclosure(&DisclosableClaim::new(
            "role",
            Value::String("admin".to_string()),
        ))
        .unwrap();
        let forged = format!("{}~{forged_encoded}~", issued.jwt);

        let err = manager
            .validate_sd_jwt(&forged, None)
            .expect_err("a disclosure not backed by a digest in _sd[] must be rejected");
        assert!(
            err.to_string().contains("_sd[]") || err.to_string().contains("not present"),
            "unexpected error message: {err}"
        );
    }

    /// Security rule: duplicate digests inside `_sd[]` are rejected, even
    /// before any disclosure is checked against them.
    #[test]
    fn duplicate_digest_in_sd_is_rejected() {
        let manager = hs256_manager();
        let (encoded, digest) = encode_disclosure(&DisclosableClaim::new(
            "email",
            Value::String("user@example.com".to_string()),
        ))
        .unwrap();

        let mut extra = HashMap::new();
        extra.insert(
            "_sd".to_string(),
            serde_json::json!([digest.clone(), digest]),
        );
        extra.insert("_sd_alg".to_string(), serde_json::json!("sha-256"));

        let jwt = manager
            .issue_client_token_with_extra("client-1", 3600, None, None, extra)
            .expect("hand-built token should issue");
        let presented = format!("{jwt}~{encoded}~");

        let err = manager
            .validate_sd_jwt(&presented, None)
            .expect_err("duplicate digests in _sd[] must be rejected");
        assert!(
            err.to_string().contains("duplicate"),
            "unexpected error message: {err}"
        );
    }

    /// Security rule: a disclosed claim cannot shadow a registered
    /// top-level claim (`sub`, in this case) — the token would otherwise
    /// let a holder present a forged `sub` that a naive verifier merges
    /// over the signed one.
    #[test]
    fn disclosed_claim_cannot_shadow_registered_claim_name() {
        let manager = hs256_manager();
        let (encoded, digest) = encode_disclosure(&DisclosableClaim::new(
            "sub",
            Value::String("attacker".to_string()),
        ))
        .unwrap();

        let mut extra = HashMap::new();
        extra.insert("_sd".to_string(), serde_json::json!([digest]));
        extra.insert("_sd_alg".to_string(), serde_json::json!("sha-256"));

        let jwt = manager
            .issue_client_token_with_extra("client-1", 3600, None, None, extra)
            .expect("hand-built token should issue");
        let presented = format!("{jwt}~{encoded}~");

        let err = manager
            .validate_sd_jwt(&presented, None)
            .expect_err("a disclosure named 'sub' must be rejected");
        assert!(
            err.to_string().contains("shadow"),
            "unexpected error message: {err}"
        );
    }

    /// Same shadowing rule, but against an already-present `extra` claim
    /// rather than a registered top-level one.
    #[test]
    fn disclosed_claim_cannot_shadow_already_present_extra_claim() {
        let manager = hs256_manager();
        let (encoded, digest) = encode_disclosure(&DisclosableClaim::new(
            "org_id",
            Value::String("attacker-org".to_string()),
        ))
        .unwrap();

        let mut extra = HashMap::new();
        extra.insert("org_id".to_string(), serde_json::json!("real-org"));
        extra.insert("_sd".to_string(), serde_json::json!([digest]));
        extra.insert("_sd_alg".to_string(), serde_json::json!("sha-256"));

        let jwt = manager
            .issue_client_token_with_extra("client-1", 3600, None, None, extra)
            .expect("hand-built token should issue");
        let presented = format!("{jwt}~{encoded}~");

        let err = manager
            .validate_sd_jwt(&presented, None)
            .expect_err("a disclosure shadowing an already-present extra claim must be rejected");
        assert!(
            err.to_string().contains("shadow"),
            "unexpected error message: {err}"
        );
    }

    /// A tampered disclosure (payload byte flipped after issuance) no
    /// longer hashes to anything in `_sd[]`, so it's rejected the same way
    /// an unbacked forged disclosure is — proving the digest check, not
    /// just structural JSON validity, is what's enforced.
    #[test]
    fn tampered_disclosure_is_rejected() {
        let manager = hs256_manager();
        let issued = manager
            .issue_sd_jwt(
                "user-1".to_string(),
                3600,
                None,
                None,
                sample_disclosures(),
                HashMap::new(),
            )
            .expect("issuance should succeed");

        let mut tampered = issued.disclosures[0].clone();
        let last = tampered.pop().unwrap();
        let replacement = if last == 'A' { 'B' } else { 'A' };
        tampered.push(replacement);

        let presented = format!("{}~{tampered}~", issued.jwt);

        let err = manager
            .validate_sd_jwt(&presented, None)
            .expect_err("a tampered disclosure must be rejected");
        assert!(
            err.to_string().contains("_sd[]")
                || err.to_string().contains("not present")
                || err.to_string().contains("disclosure"),
            "unexpected error message: {err}"
        );
    }

    /// A structurally invalid disclosure (not a 3-element array) is
    /// rejected with a decoding error, distinct from — but still a hard
    /// failure like — the digest-mismatch cases above. Built by hand with
    /// a real backing digest so the failure is provably about shape, not
    /// digest membership.
    #[test]
    fn malformed_disclosure_triple_is_rejected() {
        let manager = hs256_manager();
        let malformed_encoded =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!(["salt-only"])).unwrap());
        let digest = disclosure_digest(&malformed_encoded);

        let mut extra = HashMap::new();
        extra.insert("_sd".to_string(), serde_json::json!([digest]));
        extra.insert("_sd_alg".to_string(), serde_json::json!("sha-256"));

        let jwt = manager
            .issue_client_token_with_extra("client-1", 3600, None, None, extra)
            .expect("hand-built token should issue");
        let presented = format!("{jwt}~{malformed_encoded}~");

        let err = manager
            .validate_sd_jwt(&presented, None)
            .expect_err("a malformed disclosure triple must be rejected");
        assert!(
            err.to_string().contains("triple"),
            "unexpected error message: {err}"
        );
    }

    /// `_sd_alg` absent entirely still verifies (defaults to sha-256 per
    /// spec) — proving the "reject unrecognized _sd_alg" rule only fires
    /// when a *different* value is actually present, not merely absent.
    #[test]
    fn missing_sd_alg_defaults_to_sha256_and_still_verifies() {
        let manager = hs256_manager();
        let (encoded, digest) = encode_disclosure(&DisclosableClaim::new(
            "email",
            Value::String("user@example.com".to_string()),
        ))
        .unwrap();

        let mut extra = HashMap::new();
        extra.insert("_sd".to_string(), serde_json::json!([digest]));
        // Deliberately no "_sd_alg" entry.

        let jwt = manager
            .issue_client_token_with_extra("client-1", 3600, None, None, extra)
            .expect("hand-built token should issue");
        let presented = format!("{jwt}~{encoded}~");

        let verified = manager
            .validate_sd_jwt(&presented, None)
            .expect("a missing _sd_alg should default to sha-256, not be rejected");
        assert_eq!(
            verified.disclosed_claims.get("email"),
            Some(&Value::String("user@example.com".to_string()))
        );
    }

    /// The `extra["jti"]` override documented on `issue_client_token_with_extra`
    /// composes correctly through `issue_sd_jwt` too — proves this method
    /// didn't bypass the shared `take_jti` plumbing.
    #[test]
    fn issue_sd_jwt_honors_extra_jti_override() {
        let manager = hs256_manager();
        let mut extra = HashMap::new();
        extra.insert("jti".to_string(), serde_json::json!("caller-supplied-id"));

        let issued = manager
            .issue_sd_jwt("user-1".to_string(), 3600, None, None, Vec::new(), extra)
            .expect("issuance should succeed");

        let verified = manager
            .validate_sd_jwt(&issued.compact, None)
            .expect("verification should succeed");
        assert_eq!(verified.claims.jti, Some("caller-supplied-id".to_string()));
    }

    /// Two Disclosures for the same claim name/value must still get
    /// distinct salts (and thus distinct digests/encodings) — the whole
    /// point of per-disclosure salting is that identical claim data
    /// doesn't produce a recognizably identical Disclosure across issuances.
    #[test]
    fn disclosure_salts_are_unique_across_issuances() {
        let claim = DisclosableClaim::new("email", Value::String("user@example.com".to_string()));
        let (first, first_digest) = encode_disclosure(&claim).unwrap();
        let (second, second_digest) = encode_disclosure(&claim).unwrap();

        assert_ne!(first, second, "salts must differ across issuances");
        assert_ne!(first_digest, second_digest);
    }
}
