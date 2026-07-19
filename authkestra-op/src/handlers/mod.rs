/// Discovery endpoint handler (`/.well-known/openid-configuration`).
pub mod discovery;
pub use discovery::OidcDiscovery;

/// JWKS endpoint handler (`/jwks.json`).
pub mod jwks;
pub use jwks::JwksResponse;
