use crate::error::OidcError;
use async_trait::async_trait;
use authkestra_engine::{
    auth::{Provider, ProviderConfig},
    discovery::ProviderMetadata,
    error::AuthError,
    state::{Identity, OAuthToken},
    OAuthProvider,
};
use authkestra_resource::jwt::{validate_jwt_generic, JwksCache};
use jsonwebtoken::Validation;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{collections::HashMap, time::Duration};

#[derive(Clone)]
pub struct OidcProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    metadata: Arc<std::sync::RwLock<ProviderMetadata>>,
    http_client: reqwest::Client,
    cache: Arc<std::sync::RwLock<Arc<JwksCache>>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Deserialize)]
struct OidcTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
    id_token: Option<String>,
}

impl OidcProvider {
    /// Creates a new provider by performing discovery.
    /// Spawns a background task to periodically refresh the discovery document
    /// and JWKS cache based on the Cache-Control max-age header.
    /// If the header is missing, `fallback_refresh_interval` is used.
    #[tracing::instrument(skip(client_id, client_secret))]
    pub async fn discover(
        client_id: String,
        client_secret: String,
        redirect_uri: String,
        issuer_url: &str,
        fallback_refresh_interval: Duration,
    ) -> Result<Self, OidcError> {
        tracing::debug!("starting OIDC discovery process");
        let client = reqwest::Client::new();
        let (metadata, cache_max_age) = ProviderMetadata::discover(issuer_url, client.clone())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "OIDC discovery failed");
                e
            })?;
        tracing::info!(issuer = %metadata.issuer, "successfully discovered OIDC provider metadata");

        let refresh_interval = match cache_max_age {
            Some(duration) => duration,
            None => {
                tracing::warn!(
                    "No valid Cache-Control max-age found in discovery document from {}. Using fallback interval of {} seconds.",
                    issuer_url,
                    fallback_refresh_interval.as_secs()
                );
                fallback_refresh_interval
            }
        };

        let cache = Arc::new(JwksCache::new(metadata.jwks_uri.clone(), refresh_interval));

        let provider = Self {
            client_id,
            client_secret,
            redirect_uri,
            metadata: Arc::new(std::sync::RwLock::new(metadata)),
            http_client: client.clone(),
            cache: Arc::new(std::sync::RwLock::new(cache)),
        };

        // Spawn background refresh task
        let issuer_url_owned = issuer_url.to_string();
        let metadata_ref = Arc::downgrade(&provider.metadata);
        let cache_ref = Arc::downgrade(&provider.cache);

        tokio::spawn(async move {
            let mut current_interval = refresh_interval;
            loop {
                tokio::time::sleep(current_interval).await;

                // If the provider has been dropped, exit the background task
                let (metadata_arc, cache_arc) = match (metadata_ref.upgrade(), cache_ref.upgrade())
                {
                    (Some(m), Some(c)) => (m, c),
                    _ => break,
                };

                tracing::debug!(
                    "Refreshing OIDC discovery document for {}",
                    issuer_url_owned
                );

                match ProviderMetadata::discover(&issuer_url_owned, client.clone()).await {
                    Ok((new_metadata, new_cache_max_age)) => {
                        current_interval = match new_cache_max_age {
                            Some(duration) => duration,
                            None => {
                                tracing::warn!(
                                    "No valid Cache-Control max-age found in discovery document from {}. Using fallback interval of {} seconds.",
                                    issuer_url_owned,
                                    fallback_refresh_interval.as_secs()
                                );
                                fallback_refresh_interval
                            }
                        };

                        let mut meta_write = metadata_arc.write().unwrap();
                        let jwks_uri_changed = meta_write.jwks_uri != new_metadata.jwks_uri;
                        *meta_write = new_metadata.clone();
                        drop(meta_write); // Release lock early

                        if jwks_uri_changed {
                            tracing::info!(
                                "OIDC jwks_uri changed for {}, recreating JwksCache",
                                issuer_url_owned
                            );
                            let new_cache =
                                Arc::new(JwksCache::new(new_metadata.jwks_uri, current_interval));
                            let mut cache_write = cache_arc.write().unwrap();
                            *cache_write = new_cache;
                        } else {
                            // If JWKS didn't change, its internal TTL might still need updating if current_interval changed,
                            // but currently JwksCache doesn't expose a method to update TTL. Recreating it is safe anyway
                            // and ensures we use the new interval. Or we can just let it be since it manages its own refresh
                            // based on its original TTL. For simplicity and correctness, we just leave it unless uri changes,
                            // as JwksCache will refetch keys when they expire.
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to refresh OIDC discovery document for {}: {e}",
                            issuer_url_owned
                        );
                        // Retry after a short delay on failure to avoid tight loop
                        current_interval = Duration::from_secs(60);
                    }
                }
            }
        });

        Ok(provider)
    }

    pub async fn get_metadata(&self) -> ProviderMetadata {
        self.metadata.read().unwrap().clone()
    }
}

#[async_trait]
impl Provider for OidcProvider {
    async fn config(&self) -> ProviderConfig {
        ProviderConfig {
            id: "oidc".to_string(),
            name: "OIDC".to_string(),
            extra: HashMap::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for OidcProvider {
    fn provider_id(&self) -> &str {
        "oidc"
    }

    fn get_authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_challenge: Option<&str>,
        nonce: Option<&str>,
    ) -> String {
        let metadata = self.metadata.read().unwrap().clone();

        let mut full_scopes = scopes.to_vec();
        if !full_scopes.contains(&"openid") {
            full_scopes.push("openid");
        }

        let scope_param = full_scopes.join(" ");

        let mut url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            metadata.authorization_endpoint,
            self.client_id,
            urlencoding::encode(&self.redirect_uri),
            state,
            urlencoding::encode(&scope_param)
        );

        if let Some(challenge) = code_challenge {
            url.push_str(&format!(
                "&code_challenge={challenge}&code_challenge_method=S256"
            ));
        }

        if let Some(n) = nonce {
            url.push_str(&format!("&nonce={n}"));
        }

        url
    }

    #[tracing::instrument(skip(self, code, code_verifier, nonce))]
    async fn exchange_code_for_identity(
        &self,
        code: &str,
        code_verifier: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError> {
        tracing::debug!("exchanging OIDC code for tokens");
        // 1. Exchange code for tokens
        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code".to_string());
        params.insert("code", code.to_string());
        params.insert("redirect_uri", self.redirect_uri.clone());
        params.insert("client_id", self.client_id.clone());
        params.insert("client_secret", self.client_secret.clone());

        if let Some(verifier) = code_verifier {
            params.insert("code_verifier", verifier.to_string());
        }

        let metadata = self.metadata.read().unwrap().clone();

        let token_response = self
            .http_client
            .post(&metadata.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "network error while exchanging OIDC code");
                AuthError::Network
            })?
            .json::<OidcTokenResponse>()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to parse OIDC token response");
                AuthError::Provider(format!("Failed to parse token response: {e}"))
            })?;

        let id_token = token_response.id_token.ok_or_else(|| {
            tracing::error!("missing id_token in OIDC response");
            AuthError::Token("Missing id_token in response".to_string())
        })?;

        tracing::debug!("validating OIDC ID Token");
        // 2. Validate ID Token using the validator
        let cache = self.cache.read().unwrap().clone(); // Clone the Arc, releasing the lock immediately
        let claims = validate_jwt_generic::<Claims>(&id_token, &cache, &Validation::default())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to validate OIDC ID Token");
                AuthError::from(OidcError::from(e))
            })?;

        // 3. Validate Nonce
        if let Some(expected_nonce) = nonce {
            if claims.nonce.as_deref() != Some(expected_nonce) {
                tracing::error!("nonce mismatch in OIDC ID Token");
                return Err(AuthError::Token("Nonce mismatch".to_string()));
            }
        }

        // 4. Construct Identity
        let mut attributes = HashMap::new();
        if let Some(picture) = claims.picture {
            attributes.insert("picture".to_string(), picture);
        }

        let identity = Identity {
            provider_id: "oidc".to_string(), // Could be parameterized or inferred from issuer
            external_id: claims.sub,
            email: claims.email,
            username: claims.name,
            attributes,
        };

        let token = OAuthToken {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_in: token_response.expires_in,
            refresh_token: token_response.refresh_token,
            scope: token_response.scope,
            id_token: Some(id_token),
        };

        tracing::info!(external_id = %identity.external_id, "successfully exchanged OIDC code for identity");
        Ok((identity, token))
    }
}
