# OIDC Implementation Technical Specification

## 1. Overview
This document outlines the design for adding OpenID Connect (OIDC) support to `authly-rs`. The goal is to provide a standard-compliant way to integrate with OIDC providers (like Google, Azure AD, Auth0) using Discovery and ID Token validation.

## 2. Architecture Changes

### 2.1 `authly-core` Updates
We will modify `authly-core` to support the `id_token` field, which is standard in OAuth2/OIDC responses but currently missing.

**File:** `authly-core/src/lib.rs`

```rust
pub struct OAuthToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    // NEW: OIDC ID Token
    pub id_token: Option<String>, 
}
```

### 2.2 New Crate: `authly-oidc`
We will create a new crate `authly-oidc` to house the specific logic for OIDC. This avoids bloating the core crate with specific crypto/validation logic and heavy dependencies like `jsonwebtoken` (if not already used) or specific `reqwest` features.

**Dependencies:**
- `authly-core`
- `serde` (derive)
- `serde_json`
- `reqwest` (json, rustls-tls/native-tls)
- `jsonwebtoken`
- `thiserror`
- `async-trait`
- `url`

## 3. Component Design (`authly-oidc`)

### 3.1 OIDC Discovery (`discovery.rs`)
This module handles fetching the provider configuration.

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Option<Vec<String>>,
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
}

impl ProviderMetadata {
    /// Fetches metadata from the issuer URL (appends /.well-known/openid-configuration)
    pub async fn discover(issuer_url: &str, client: &reqwest::Client) -> Result<Self, OidcError>;
}
```

### 3.2 JWKS Management (`jwks.rs`)
Handles fetching and parsing JSON Web Key Sets.

```rust
use serde::Deserialize;

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
    // ... other fields as needed
}

// Helper to find a decoding key for a given token header
```

### 3.3 The OIDC Provider (`lib.rs` or `provider.rs`)
The main struct that implements `OAuthProvider`.

```rust
pub struct OidcProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    metadata: ProviderMetadata,
    http_client: reqwest::Client,
    // Optional: Strategy for caching JWKS. 
    // For MVP, we might fetch JWKS on validation if not present, or allow manual pre-fetching.
}

impl OidcProvider {
    /// Creates a new provider by performing discovery
    pub async fn discover(
        client_id: String,
        client_secret: String,
        redirect_uri: String,
        issuer_url: &str
    ) -> Result<Self, OidcError> {
        let client = reqwest::Client::new();
        let metadata = ProviderMetadata::discover(issuer_url, &client).await?;
        Ok(Self {
            client_id,
            client_secret,
            redirect_uri,
            metadata,
            http_client: client,
        })
    }
}
```

### 3.4 Implementing `OAuthProvider`
The core logic resides in `exchange_code_for_identity`.

```rust
#[async_trait]
impl OAuthProvider for OidcProvider {
    fn get_authorization_url(&self, state: &str, scopes: &[&str], code_challenge: Option<&str>) -> String {
        // Use self.metadata.authorization_endpoint
        // Construct URL standard OIDC params
        // Default scope should include "openid"
    }

    async fn exchange_code_for_identity(&self, code: &str, code_verifier: Option<&str>) -> Result<(Identity, OAuthToken), AuthError> {
        // 1. Exchange code for tokens at self.metadata.token_endpoint
        
        // 2. Extract id_token from response
        
        // 3. Fetch JWKS from self.metadata.jwks_uri
        // (Optimization: Cache this)
        
        // 4. Decode and Validate ID Token
        // - Verify signature using JWKS
        // - Verify issuer == self.metadata.issuer
        // - Verify audience == self.client_id
        // - Verify expiration
        
        // 5. Construct Identity from ID Token Claims
        // - sub -> external_id
        // - email, name, picture -> standard attributes
        
        // 6. Return Identity and OAuthToken
    }
}
```

## 4. ID Token Validation Details
We will use the `jsonwebtoken` crate.

- **Header Parsing**: Decode header to get `kid`.
- **Key Selection**: Find matching key in JWKS.
- **DecodingKey Creation**: `DecodingKey::from_rsa_components` (for RS256).
- **ValidationConfig**:
  - `iss`: Set to `metadata.issuer`
  - `aud`: Set to `client_id`
  - `exp`: validated automatically

## 5. Example Usage

```rust
// In main.rs

let google_oidc = OidcProvider::discover(
    env::var("GOOGLE_CLIENT_ID")?,
    env::var("GOOGLE_CLIENT_SECRET")?,
    "http://localhost:3000/auth/callback".to_string(),
    "https://accounts.google.com",
).await?;

// Use it just like any other OAuthProvider
let auth_url = google_oidc.get_authorization_url(state, &["openid", "email"], None);
```

## 6. Migration for Existing Providers
Existing providers like `authly-providers-google` can eventually be deprecated in favor of `OidcProvider` configured with Google's issuer URL, or they can be refactored to wrap `OidcProvider` for convenience.
