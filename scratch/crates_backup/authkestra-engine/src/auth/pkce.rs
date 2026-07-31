use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{distr::Alphanumeric, rng, Rng};
use sha2::{Digest, Sha256};

/// Proof Key for Code Exchange (PKCE) parameters.
#[derive(Debug, Clone)]
pub struct Pkce {
    /// High-entropy cryptographic random string
    pub code_verifier: String,
    /// BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    pub code_challenge: String,
}

impl Pkce {
    /// Generates a new PKCE verifier and challenge.
    pub fn new() -> Self {
        let code_verifier: String = rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let hash = hasher.finalize();

        let code_challenge = URL_SAFE_NO_PAD.encode(hash);

        Self {
            code_verifier,
            code_challenge,
        }
    }
}

impl Default for Pkce {
    fn default() -> Self {
        Self::new()
    }
}
