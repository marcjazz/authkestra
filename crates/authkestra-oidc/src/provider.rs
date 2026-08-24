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
use jsonwebtoken::{Algorithm, Validation};
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
    /// Overrides the ID-token `Validation` policy computed by
    /// [`default_validation`]. `None` (the default from [`OidcProvider::discover`])
    /// means "derive `iss`/`aud`/`algorithms` from the discovery document and
    /// `client_id`"; see [`OidcProvider::with_validation`].
    validation_override: Option<Validation>,
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
            validation_override: None,
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
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "Failed to refresh OIDC discovery document for {}",
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

    /// Overrides the ID-token validation policy used by
    /// [`OidcProvider::exchange_code_for_identity`].
    ///
    /// By default (see [`default_validation`]) the provider derives `iss`
    /// from the discovered issuer, `aud` from `client_id`, and `algorithms`
    /// from the discovery document's `id_token_signing_alg_values_supported`
    /// (falling back to RS256). Use this to accept additional/alternate
    /// audiences, add clock-skew leeway, or otherwise diverge from that
    /// default when a given IdP requires it. See issue #225.
    ///
    /// # This replaces the derived policy — it does not extend it
    ///
    /// Whatever you pass becomes the entire policy. `Validation::new` starts
    /// with no issuer and no audience configured, so passing a bare
    /// `Validation::new(Algorithm::RS256)` silently disables the `iss` and
    /// `aud` checks [`default_validation`] would otherwise apply —
    /// reintroducing exactly the gaps #225 fixed. Call `set_issuer` and
    /// `set_audience` on the `Validation` you supply.
    pub fn with_validation(mut self, validation: Validation) -> Self {
        self.validation_override = Some(validation);
        self
    }
}

/// Builds the default ID-token `Validation` policy from discovered metadata.
///
/// `jsonwebtoken::Validation::default()` is HS256-only and checks neither
/// `iss` nor `aud` (see #225), which both rejects every RS256-signed ID
/// token (Keycloak, Auth0, Google, ...) and, independently, would silently
/// skip the issuer/audience checks the OIDC Core spec (3.1.3.7) requires
/// even if HS256 were in use. This builds a spec-compliant default instead:
/// `iss` must equal the discovered issuer, `aud` must contain `client_id`,
/// and `algorithms` is taken from the discovery document (falling back to
/// RS256, the most common IdP default, if the document omits it).
fn default_validation(metadata: &ProviderMetadata, client_id: &str) -> Validation {
    let algorithms = metadata
        .id_token_signing_alg_values_supported
        .as_ref()
        .map(|algs| {
            algs.iter()
                .filter_map(|alg| alg.parse::<Algorithm>().ok())
                .collect::<Vec<_>>()
        })
        .filter(|algs| !algs.is_empty())
        .unwrap_or_else(|| vec![Algorithm::RS256]);

    let mut validation = Validation::new(algorithms[0]);
    validation.algorithms = algorithms;
    validation.set_issuer(std::slice::from_ref(&metadata.issuer));
    validation.set_audience(std::slice::from_ref(&client_id.to_string()));
    validation
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
        let validation = self
            .validation_override
            .clone()
            .unwrap_or_else(|| default_validation(&metadata, &self.client_id));
        tracing::debug!(
            algorithms = ?validation.algorithms,
            issuer = ?metadata.issuer,
            "using ID token validation policy"
        );
        let claims = validate_jwt_generic::<Claims>(&id_token, &cache, &validation)
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
        // authkestra-engine's `OAuth2Flow::finalize_login` re-checks the nonce
        // by reading it back out of `identity.attributes["nonce"]`; without
        // this, that check always fails (see #225 Defect 5), since
        // `OAuth2Flow::initiate_login` always generates a nonce to check.
        if let Some(claim_nonce) = &claims.nonce {
            attributes.insert("nonce".to_string(), claim_nonce.clone());
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
