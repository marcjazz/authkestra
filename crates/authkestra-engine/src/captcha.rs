use serde::Deserialize;

/// Supported third-party CAPTCHA/bot-protection providers.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum CaptchaProvider {
    /// Cloudflare Turnstile
    Turnstile,
    /// hCaptcha
    HCaptcha,
    /// Google reCAPTCHA
    ReCaptcha,
}

/// Verification service for CAPTCHA/bot-protection tokens.
pub struct CaptchaVerifier {
    provider: CaptchaProvider,
    secret_key: String,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct CaptchaResponse {
    success: bool,
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<String>>,
}

impl CaptchaVerifier {
    /// Create a new `CaptchaVerifier` for the specified provider and secret key.
    pub fn new(provider: CaptchaProvider, secret_key: &str) -> Self {
        Self {
            provider,
            secret_key: secret_key.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Verify a token against the provider's validation API.
    pub async fn verify(&self, token: &str, remote_ip: Option<&str>) -> Result<bool, String> {
        let verify_url = match self.provider {
            CaptchaProvider::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            CaptchaProvider::HCaptcha => "https://hcaptcha.com/siteverify",
            CaptchaProvider::ReCaptcha => "https://www.google.com/recaptcha/api/siteverify",
        };

        let mut form = vec![
            ("secret", self.secret_key.as_str()),
            ("response", token),
        ];
        if let Some(ip) = remote_ip {
            form.push(("remoteip", ip));
        }

        let resp = self.client.post(verify_url)
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("Network request to CAPTCHA API failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("CAPTCHA API returned non-success status code: {}", resp.status()));
        }

        let body: CaptchaResponse = resp.json()
            .await
            .map_err(|e| format!("Failed to parse CAPTCHA API response JSON: {e}"))?;

        if body.success {
            Ok(true)
        } else {
            let errors = body.error_codes.unwrap_or_default().join(", ");
            Err(format!("CAPTCHA verification failed: {errors}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_captcha_verification_invalid_token() {
        let verifier = CaptchaVerifier::new(CaptchaProvider::Turnstile, "invalid_secret");
        let res = verifier.verify("bogus_token", None).await;
        assert!(res.is_err());
        let err_msg = res.unwrap_err();
        assert!(err_msg.contains("verification failed") || err_msg.contains("request"));
    }
}
