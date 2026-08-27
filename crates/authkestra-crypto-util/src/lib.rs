use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EdDsaKeyError {
    #[error("OKP 'x' is not valid base64url: {0}")]
    Base64(String),
    #[error("an Ed25519 public key must be exactly 32 bytes, got {0}")]
    InvalidLength(usize),
    #[error("OKP 'x' is not a valid Ed25519 point")]
    InvalidPoint,
    #[error("Ed25519 public key is a low-order point; no private key exists for it, so a signature under it proves nothing")]
    LowOrderPoint,
}

/// Extracts an Ed25519 verifying key from a base64url-encoded `x` string, **rejecting low-order ("weak") keys**.
///
/// This check (authkestra#242, authkestra#256) must run before any verification
/// attempt, so that the key is rejected on its own merits rather than on whichever signature
/// bytes happened to accompany it.
pub fn parse_ed25519_verifying_key_strict(x_b64: &str) -> Result<VerifyingKey, EdDsaKeyError> {
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|e| EdDsaKeyError::Base64(e.to_string()))?;

    let x_arr: [u8; 32] = x_bytes
        .as_slice()
        .try_into()
        .map_err(|_| EdDsaKeyError::InvalidLength(x_bytes.len()))?;

    let key = VerifyingKey::from_bytes(&x_arr).map_err(|_| EdDsaKeyError::InvalidPoint)?;

    if key.is_weak() {
        tracing::warn!(
            target: "authkestra_crypto",
            "rejecting Ed25519 key: it is a low-order (weak) point, for which no private key \
             exists — a signature under it would prove possession of nothing, so it is refused \
             before verification is even attempted (authkestra#242)"
        );
        return Err(EdDsaKeyError::LowOrderPoint);
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The identity point: the canonical universal low-order vector.
    const IDENTITY: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    #[test]
    fn rejects_low_order_identity_point() {
        let x_b64 = URL_SAFE_NO_PAD.encode(IDENTITY);
        let err =
            parse_ed25519_verifying_key_strict(&x_b64).expect_err("should reject low order point");
        assert!(matches!(err, EdDsaKeyError::LowOrderPoint));
    }

    #[test]
    fn accepts_valid_point() {
        // A valid Ed25519 point (signing key scalar = 7)
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        let x_b64 = URL_SAFE_NO_PAD.encode(verifying.as_bytes());
        let key = parse_ed25519_verifying_key_strict(&x_b64).expect("should accept valid point");
        assert_eq!(key.as_bytes(), verifying.as_bytes());
    }

    #[test]
    fn rejects_invalid_length() {
        let x_b64 = URL_SAFE_NO_PAD.encode([0u8; 31]);
        let err = parse_ed25519_verifying_key_strict(&x_b64).expect_err("should reject short key");
        assert!(matches!(err, EdDsaKeyError::InvalidLength(31)));
    }
}
