use crate::auth::error::AuthError;
use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};

/// A JSON Web Key, as published at `/jwks.json`.
///
/// This struct is widened (not an enum) rather than split per key type, so a
/// call site that builds a `Jwk` with a plain struct literal names one set of
/// fields whatever shape it is describing. See the `to_decoding_key` doc
/// comment for why an enum/`#[serde(untagged)]` representation was rejected
/// in favor of this. The trade-off is that widening it again is a breaking
/// change for those literals, which is what adding `use`/`key_ops` cost.
///
/// `use` and `key_ops` (RFC 7517 §4.2/§4.3) are carried so that key-use
/// separation can be enforced when selecting a verification key — see
/// [`Jwk::is_usable_for_signature_verification`].
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
        Jwk {
            kid: Some("kid-1".to_string()),
            kty: "RSA".to_string(),
            alg: Some("RS256".to_string()),
            n: Some("bg".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            r#use: r#use.map(str::to_string),
            key_ops: key_ops.map(|ops| ops.iter().map(|op| op.to_string()).collect()),
        }
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
        let jwk = Jwk {
            kid: None,
            kty: "OKP".to_string(),
            alg: None,
            n: None,
            e: None,
            crv: Some("Ed25519".to_string()),
            x: Some(identity_b64.to_string()),
            r#use: None,
            key_ops: None,
        };

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
