use std::time::Duration;

use authkestra_token::offline_validation::{validate_jwt, JwksCache};
use jsonwebtoken::{Algorithm, Validation};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize the JWKS Cache
    // In a real scenario, this would be your OIDC provider's JWKS URI
    // For this example, we'll use a placeholder or a mock if we were testing,
    // but here we show the structure.
    let jwks_uri = "https://www.googleapis.com/oauth2/v3/certs".to_string();

    println!("Initializing JWKS cache for: {}", jwks_uri);

    // JwksCache::new is synchronous, but fetching JWKS happens lazily or via .refresh()
    let cache = JwksCache::new(jwks_uri, Duration::from_secs(3600));

    println!("JWKS cache initialized successfully.");

    // 2. Configure Validation
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://accounts.google.com"]);
    // validation.set_audience(&["your-client-id"]);

    // 3. Validate a Token
    // In a real app, you'd get this from an Authorization header
    let token = "your.jwt.token";

    println!("Validating token...");
    match validate_jwt(token, &cache, &validation).await {
        Ok(claims) => println!("Token is valid! Claims: {:?}", claims),
        Err(e) => println!("Token validation failed: {}", e),
    }

    Ok(())
}
