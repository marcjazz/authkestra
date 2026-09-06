use crate::auth::error::AuthError;
use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};

/// A JSON Web Key, as published at `/jwks.json`.
///
/// This struct is widened (not an enum) rather than split per key type, so one
/// set of fields describes whatever shape a key has. See the `to_decoding_key`
/// doc comment for why an enum/`#[serde(untagged)]` representation was
/// rejected in favor of this.
///
/// `use` and `key_ops` (RFC 7517 §4.2/§4.3) are carried so that key-use
/// separation can be enforced when selecting a verification key — see
/// [`Jwk::is_usable_for_signature_verification`].
///
/// # Why `#[non_exhaustive]`
///
/// A JWK has as many members as the RFCs care to define, so this struct gets
/// widened whenever a new one turns out to matter — `crv`/`x` for the OKP
/// shape, then `use`/`key_ops` for key-use separation. While downstream could
/// build one with a struct literal, every one of those widenings was a
/// breaking change for code that had nothing to do with the new field.
///
/// `#[non_exhaustive]` ends that: construction goes through [`Jwk::rsa`] /
/// [`Jwk::ed25519`] and the `with_*` builders, so a future field is additive
/// and costs downstream nothing. This matches the rest of the crate —
/// including this type's own containers, `Jwks` and `JwksResponse`, which
/// were already `#[non_exhaustive]`. Reading and mutating the public fields
/// is unaffected; only literal construction and exhaustive destructuring are
/// restricted, and a key with some other `kty` can still be obtained by
/// deserializing it.
///
/// Two shapes are represented today:
/// - RSA (`kty: "RSA"`): `n`, `e` are populated; `crv`, `x` are `None`.
/// - OKP/Ed25519 (`kty: "OKP"`): `crv` (always `"Ed25519"`), `x` are
///   populated; `n`, `e` are `None`.
///
/// `None` fields are omitted from the serialized JSON (`skip_serializing_if`)
/// so each shape's wire format matches its RFC exactly: RFC 7517 §6.3.1 for
/// RSA (`kty`, `n`, `e`), RFC 8037 §2 for OKP (`kty`, `crv`, `x`). Neither
/// shape ever emits the other's fields, and neither emits a stray `"n":null`
/// / `"x":null`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Jwk {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// RSA modulus (base64url, unpadded). `None` for OKP keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA public exponent (base64url, unpadded). `None` for OKP keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// OKP subtype curve name, e.g. `"Ed25519"` (RFC 8037 §2). `None` for
    /// RSA keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// OKP public key (base64url, unpadded, RFC 8037 §2). `None` for RSA
    /// keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Intended use of the public key (RFC 7517 §4.2): `"sig"` or `"enc"`.
    ///
    /// Named `r#use` because `use` is a keyword; it is `use` on the wire.
    /// `None` — the shape most IdPs publish — asserts nothing either way,
    /// and [`Jwk::is_usable_for_signature_verification`] treats it as
    /// permitted.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    /// Operations the key is intended for (RFC 7517 §4.3), e.g. `["verify"]`.
    ///
    /// RFC 7517 §4.3 says `use` and `key_ops` "SHOULD NOT be used together";
    /// both are honoured here because a publisher that ignores that advice
    /// should not end up with *neither* restriction enforced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
}

impl Jwk {
    /// An RSA public key (RFC 7517 §6.3.1) from its base64url modulus and
    /// exponent.
    ///
    /// `kid`, `alg`, `use` and `key_ops` are unset; add them with the
    /// `with_*` builders.
    pub fn rsa(n: impl Into<String>, e: impl Into<String>) -> Self {
        Self {
            kid: None,
            kty: "RSA".to_string(),
            alg: None,
            n: Some(n.into()),
            e: Some(e.into()),
            crv: None,
            x: None,
            r#use: None,
            key_ops: None,
        }
    }

    /// An Ed25519 OKP public key (RFC 8037 §2) from its base64url public key.
    ///
    /// `kid`, `alg`, `use` and `key_ops` are unset; add them with the
    /// `with_*` builders.
    pub fn ed25519(x: impl Into<String>) -> Self {
        Self {
            kid: None,
            kty: "OKP".to_string(),
            alg: None,
            n: None,
            e: None,
            crv: Some("Ed25519".to_string()),
            x: Some(x.into()),
            r#use: None,
            key_ops: None,
        }
    }

    /// Sets the key ID (RFC 7517 §4.5).
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Sets the algorithm this key is intended for (RFC 7517 §4.4).
    pub fn with_alg(mut self, alg: impl Into<String>) -> Self {
        self.alg = Some(alg.into());
        self
    }

    /// Sets the intended use (RFC 7517 §4.2) — `"sig"` or `"enc"`.
    ///
    /// See [`Jwk::is_usable_for_signature_verification`] for what this
    /// declaration then rules in or out.
    pub fn with_use(mut self, r#use: impl Into<String>) -> Self {
        self.r#use = Some(r#use.into());
        self
    }

    /// Sets the permitted key operations (RFC 7517 §4.3), e.g. `["verify"]`.
    pub fn with_key_ops(mut self, key_ops: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.key_ops = Some(key_ops.into_iter().map(Into::into).collect());
        self
    }

    /// Whether this key may be used to **verify a signature**.
    ///
    /// A JWKS endpoint routinely publishes keys that exist for something
    /// other than signature verification. A stock Keycloak realm serves an
    /// RSA signing key and an RSA *encryption* key side by side, both
    /// `kty: "RSA"` and distinguishable only by `use`/`alg`, so selecting a
    /// verification key on `kty` (or on JWKS member order) alone can land on
    /// the encryption key and reject a perfectly good token with a bare
    /// `InvalidSignature` — see #341.
    ///
    /// Only an *explicit* exclusion rejects: `use: "enc"`, or a `key_ops`
    /// that is present and does not list `"verify"`. A key declaring neither
    /// is permitted, because that is what the majority of IdPs publish and
    /// refusing it would fail closed on the common case.
    ///
    /// This is about key **purpose**, not about trust: it never decides
    /// whether a key is the right one, only whether it is the right *kind*.
    pub fn is_usable_for_signature_verification(&self) -> bool {
        if let Some(r#use) = self.r#use.as_deref() {
            if r#use != "sig" {
                return false;
            }
        }

        if let Some(key_ops) = self.key_ops.as_deref() {
            if !key_ops.iter().any(|op| op == "verify") {
                return false;
            }
        }

        true
    }

    /// Derives a `DecodingKey` from this JWK, dispatching on `kty`.
    ///
    /// Supports `"RSA"` (unchanged from before this key gained the OKP
    /// shape) and `"OKP"` with `crv: "Ed25519"` (RFC 8037). Any other `kty`,
    /// or an OKP key advertising an unsupported curve, is rejected.
    pub fn to_decoding_key(&self) -> Result<DecodingKey, AuthError> {
        match self.kty.as_str() {
            "RSA" => {
                let n = self
                    .n
                    .as_ref()
                    .ok_or_else(|| AuthError::Token("Missing 'n' component in JWK".to_string()))?;
                let e = self
                    .e
                    .as_ref()
                    .ok_or_else(|| AuthError::Token("Missing 'e' component in JWK".to_string()))?;

                DecodingKey::from_rsa_components(n, e).map_err(|e| AuthError::Token(e.to_string()))
            }
            "OKP" => {
                match self.crv.as_deref() {
                    Some("Ed25519") => {}
                    Some(other) => {
                        return Err(AuthError::Token(format!(
                            "Unsupported OKP curve '{}' in JWK",
                            other
                        )));
                    }
                    None => {
                        return Err(AuthError::Token(
                            "Missing 'crv' component in OKP JWK".to_string(),
                        ));
                    }
                }

                let x_str = self
                    .x
                    .as_ref()
                    .ok_or_else(|| AuthError::Token("Missing 'x' component in JWK".to_string()))?;

                authkestra_crypto_util::parse_ed25519_verifying_key_strict(x_str)
                    .map_err(|e| AuthError::Token(e.to_string()))?;

                DecodingKey::from_ed_components(x_str).map_err(|e| AuthError::Token(e.to_string()))
            }
            other => Err(AuthError::Token(format!(
                "Unsupported JWK 'kty' '{}' — only RSA and OKP are supported",
                other
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal RSA-shaped JWK; the `use`/`key_ops` fields are what each
    /// test below varies.
    fn rsa_jwk(r#use: Option<&str>, key_ops: Option<&[&str]>) -> Jwk {
        let mut jwk = Jwk::rsa("bg", "AQAB").with_kid("kid-1").with_alg("RS256");
        if let Some(r#use) = r#use {
            jwk = jwk.with_use(r#use);
        }
        if let Some(key_ops) = key_ops {
            jwk = jwk.with_key_ops(key_ops.iter().copied());
        }
        jwk
    }

    #[test]
    fn a_key_declaring_no_restriction_may_verify() {
        // The shape most IdPs publish. Rejecting it would fail closed on
        // nearly every deployment in existence.
        assert!(rsa_jwk(None, None).is_usable_for_signature_verification());
    }

    #[test]
    fn use_decides_when_it_is_the_only_restriction() {
        assert!(rsa_jwk(Some("sig"), None).is_usable_for_signature_verification());
        assert!(!rsa_jwk(Some("enc"), None).is_usable_for_signature_verification());
        // An unrecognised `use` is not "no restriction": it is a restriction
        // to something that is not signing.
        assert!(!rsa_jwk(Some("wat"), None).is_usable_for_signature_verification());
    }

    #[test]
    fn key_ops_decides_when_it_is_the_only_restriction() {
        assert!(rsa_jwk(None, Some(&["verify"])).is_usable_for_signature_verification());
        assert!(rsa_jwk(None, Some(&["sign", "verify"])).is_usable_for_signature_verification());
        assert!(!rsa_jwk(None, Some(&["encrypt"])).is_usable_for_signature_verification());
        // Present but empty still means "these are the operations", and
        // `verify` is not among them.
        assert!(!rsa_jwk(None, Some(&[])).is_usable_for_signature_verification());
    }

    /// RFC 7517 §4.3 says `use` and `key_ops` "SHOULD NOT be used together",
    /// but a publisher that ignores that must not end up with *neither*
    /// restriction enforced: either one alone is enough to disqualify a key.
    #[test]
    fn use_and_key_ops_are_both_honoured_when_both_are_present() {
        assert!(rsa_jwk(Some("sig"), Some(&["verify"])).is_usable_for_signature_verification());
        assert!(!rsa_jwk(Some("sig"), Some(&["encrypt"])).is_usable_for_signature_verification());
        assert!(!rsa_jwk(Some("enc"), Some(&["verify"])).is_usable_for_signature_verification());
    }

    #[test]
    fn rejects_low_order_ed25519_key() {
        // The identity point: the canonical universal low-order vector.
        let identity_b64 = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let jwk = Jwk::ed25519(identity_b64);

        let err = jwk
            .to_decoding_key()
            .expect_err("should reject low order point");
        assert!(
            err.to_string().contains("low-order"),
            "expected low-order point rejection, got: {}",
            err
        );
    }
}
