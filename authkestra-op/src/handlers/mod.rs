/// Discovery endpoint handler (`/.well-known/openid-configuration`).
pub mod discovery;
pub use discovery::OidcDiscovery;

/// JWKS endpoint handler (`/jwks.json`).
pub mod jwks;
pub use jwks::JwksResponse;

/// Authorization endpoint handler (`/authorize`).
pub mod authorize;
pub use authorize::{handle_authorize, AuthorizeOutcome, AuthorizeRequest};

/// Token endpoint handler (`/token`).
pub mod token;
pub use token::{handle_token, TokenErrorResponse, TokenRequest, TokenResponse};

/// UserInfo endpoint handler (`/userinfo`).
pub mod userinfo;
pub use userinfo::{handle_userinfo, UserInfoErrorResponse, UserInfoRequest, UserInfoResponse};
