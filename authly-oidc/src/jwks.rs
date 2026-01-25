use serde::Deserialize;
use crate::error::OidcError;
use jsonwebtoken::DecodingKey;

#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kid: Option<String>,
    pub kty: String,
    pub alg: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
}

impl Jwks {
    pub async fn fetch(jwks_uri: &str, client: &reqwest::Client) -> Result<Self, OidcError> {
        client.get(jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::Network(e.to_string()))?
            .json::<Jwks>()
            .await
            .map_err(|e| OidcError::Provider(format!("Failed to parse JWKS: {}", e)))
    }

    pub fn find_key(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(id) => self.keys.iter().find(|k| k.kid.as_deref() == Some(id)),
            None => self.keys.first(),
        }
    }
}

impl Jwk {
    pub fn to_decoding_key(&self) -> Result<DecodingKey, OidcError> {
        if self.kty != "RSA" {
            return Err(OidcError::ValidationError("Only RSA keys are supported currently".to_string()));
        }

        let n = self.n.as_ref().ok_or_else(|| OidcError::ValidationError("Missing 'n' component in JWK".to_string()))?;
        let e = self.e.as_ref().ok_or_else(|| OidcError::ValidationError("Missing 'e' component in JWK".to_string()))?;

        DecodingKey::from_rsa_components(n, e)
            .map_err(|e| OidcError::ValidationError(format!("Invalid RSA components: {}", e)))
    }
}
