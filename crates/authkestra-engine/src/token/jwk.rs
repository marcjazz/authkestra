use crate::auth::error::AuthError;
use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};

/// A JSON Web Key, as published at `/jwks.json`.
///
/// This struct is widened (not an enum) so that every existing call site
/// that builds a `Jwk` with a plain struct literal — inside this crate and
/// downstream — keeps compiling: it only needs two more fields (`crv`, `x`),
/// both `None` for the RSA shape it already builds. See the `to_decoding_key`
/// doc comment for why an enum/`#[serde(untagged)]` representation was
/// rejected in favor of this.
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
}

impl Jwk {
    /// Derives a `DecodingKey` from this JWK, dispatching on `kty`.
    ///
    /// Supports `"RSA"` (unchanged from before this key gained the OKP
    /// shape) and `"OKP"` with `crv: "Ed25519"` (RFC 8037). Any other `kty`,
    /// or an OKP key advertising an unsupported curve, is rejected.
    pub fn to_decoding_key(&self) -> Result<DecodingKey, AuthError> {
        // Reported at one boundary rather than at each of the nine rejection
        // points inside. Every one of them builds an `AuthError::Token` whose
        // message already names what was wrong — a missing `n`, an
        // unsupported curve, a low-order Ed25519 point — so one line here
        // carries the same information and cannot fall out of step with the
        // checks.
        //
        // `debug!`, not `warn!`, and the distinction is load-bearing: this is
        // the per-token verification path, so an issuer publishing one key
        // shape this crate rejects would otherwise emit a warning for *every*
        // token that resolves to it, for as long as the key stays in the
        // JWKS. Warn-level visibility of the condition is not lost —
        // `AuthError` propagates as `ValidationError::Discovery` and
        // `JwtStrategy::authenticate` reports it as "could not determine
        // whether the token is valid" — so what belongs here is the
        // structured identification of *which* published key was unusable,
        // which is a debugging detail rather than an alert.
        let outcome = self.to_decoding_key_inner();
        if let Err(error) = &outcome {
            tracing::debug!(
                kid = ?self.kid,
                kty = %self.kty,
                alg = ?self.alg,
                %error,
                "JWKS key could not be turned into a verification key"
            );
        }
        outcome
    }

    /// The conversion itself. Split out so [`Jwk::to_decoding_key`] can report
    /// the outcome in one place; see the comment there.
    fn to_decoding_key_inner(&self) -> Result<DecodingKey, AuthError> {
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

    /// #353: a key the issuer published but this crate cannot use was
    /// indistinguishable, to a caller, from a forged token — nine rejection
    /// branches here all collapse into the same downstream rejection. The
    /// reason is now reported at the boundary.
    ///
    /// At `DEBUG`, asserted below: this runs per token, so a warning here
    /// would repeat for every token resolving to an unusable key.
    #[test]
    fn an_unusable_key_reports_why_and_identifies_the_key() {
        let jwk = Jwk {
            kid: Some("kid-1".to_string()),
            kty: "EC".to_string(),
            alg: Some("ES256".to_string()),
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: Some("irrelevant".to_string()),
        };

        let (result, logs) = crate::test_support::capture(|| jwk.to_decoding_key());

        assert!(result.is_err());
        assert!(
            logs.contains("could not be turned into a verification key"),
            "the failure should be reported; got:\n{logs}"
        );
        assert!(
            logs.contains("kid-1") && logs.contains("EC"),
            "and should identify which published key was unusable; got:\n{logs}"
        );
        assert!(
            logs.contains("only RSA and OKP are supported"),
            "and say what was wrong with it; got:\n{logs}"
        );
        assert!(
            logs.contains("DEBUG") && !logs.contains("WARN"),
            "this is a per-token path; a warning here would repeat for every \
             token resolving to the same unusable key; got:\n{logs}"
        );
    }

    /// A usable key logs nothing: this is a per-token hot path, and a warning
    /// on every successful verification would be noise.
    #[test]
    fn a_usable_key_is_silent() {
        // A real Ed25519 point, so the strict parse succeeds.
        use base64::Engine as _;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signing.verifying_key().to_bytes());
        let jwk = Jwk {
            kid: None,
            kty: "OKP".to_string(),
            alg: None,
            n: None,
            e: None,
            crv: Some("Ed25519".to_string()),
            x: Some(x),
        };

        let (result, logs) = crate::test_support::capture(|| jwk.to_decoding_key());

        assert!(result.is_ok(), "the fixture must produce a usable key");
        assert!(
            logs.is_empty(),
            "a successful conversion should not log on a per-token path:\n{logs}"
        );
    }
}
