use crate::error::OpError;
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

/// OAuth2/OIDC grant types a client may be permitted to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantType {
    /// Standard authorization code grant (with or without PKCE).
    AuthorizationCode,
    /// Refresh token grant.
    RefreshToken,
    /// Client credentials grant (machine-to-machine). See RFC-003 §9, `OP.7`.
    ClientCredentials,
    /// Device Code grant (RFC 8628).
    DeviceCode,
    /// Token Exchange grant (RFC 8693).
    TokenExchange,
    /// A custom grant type.
    Custom(String),
}

impl Serialize for GrantType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::RefreshToken => "refresh_token",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
            GrantType::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
            GrantType::Custom(custom) => custom,
        };
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for GrantType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "authorization_code" => GrantType::AuthorizationCode,
            "refresh_token" => GrantType::RefreshToken,
            "client_credentials" => GrantType::ClientCredentials,
            "urn:ietf:params:oauth:grant-type:device_code" => GrantType::DeviceCode,
            "urn:ietf:params:oauth:grant-type:token-exchange" => GrantType::TokenExchange,
            _ => GrantType::Custom(s),
        })
    }
}

/// The single client-authentication method a client is bound to at the token
/// endpoint (OIDC Core §9 / RFC 7591 `token_endpoint_auth_method`).
///
/// A registration names **one** method and the token endpoint accepts only
/// that one. This is not pedantry: a client that may authenticate *either*
/// with a shared secret *or* with a signed assertion is only ever as strong
/// as the weaker of the two, so an attacker holding the leaked secret of a
/// `private_key_jwt` client could simply present it instead and never touch
/// the private key. Binding the registration to one method removes that
/// downgrade entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    /// Shared secret presented in the HTTP `Authorization: Basic` header.
    ClientSecretBasic,
    /// Shared secret presented as the `client_secret` form field.
    ClientSecretPost,
    /// A JWT assertion signed by the client's private key and verified
    /// against [`ClientRegistration::jwks`] (RFC 7523 §2.2). See
    /// [`crate::client_assertion`].
    PrivateKeyJwt,
    /// No client authentication at all — public clients only, where PKCE
    /// rather than a credential is what protects the exchange.
    #[serde(rename = "none")]
    NoAuth,
}

/// A registered OAuth2/OIDC client application.
///
/// `redirect_uris` are matched **exactly** (no prefix/wildcard matching) —
/// see RFC-003 §7. This is the single most important invariant in this
/// type; do not relax it for convenience. The one exception, which RFC 8252
/// §7.3 makes mandatory, is the port of a loopback IP redirect URI; see
/// [`ClientRegistration::allows_redirect_uri`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistration {
    /// Public client identifier.
    pub client_id: String,
    /// Hash of the client secret. Never store or log the plaintext secret.
    /// `None` for public clients (e.g. SPAs, native apps using PKCE).
    pub client_secret_hash: Option<String>,
    /// Exact-match redirect URIs this client is permitted to use.
    ///
    /// One entry, one URI, compared byte-for-byte — with a single exception:
    /// registering a loopback IP URI (`http://127.0.0.1/...` or
    /// `http://[::1]/...`) means "this client may redirect to that host and
    /// path on **any** port", because RFC 8252 §7.3 requires it for native
    /// apps that take an ephemeral port from the OS at request time. Whatever
    /// port is written here is therefore not binding, and writing one is only
    /// a documentation aid. See
    /// [`ClientRegistration::allows_redirect_uri`] (authkestra#291).
    pub redirect_uris: Vec<String>,
    /// Grant types this client is permitted to use.
    pub grant_types: Vec<GrantType>,
    /// Scopes this client is permitted to request.
    pub scopes: Vec<String>,
    /// Retained for wire/storage compatibility, but no longer consulted:
    /// PKCE is mandatory for every client on the authorization code grant,
    /// unconditionally, per OAuth 2.1 §4.1 (authkestra#273) — both
    /// `handlers::authorize` and `handlers::token` enforce it regardless of
    /// this value.
    #[deprecated(
        since = "0.7.0",
        note = "PKCE is mandatory for every client on the authorization code grant, \
                unconditionally, per OAuth 2.1 §4.1 (authkestra#273). This field is no longer \
                read by handlers::authorize or handlers::token and has no effect."
    )]
    pub require_pkce: bool,
    /// Downstream audiences (resources) this client is permitted to target
    /// during token exchange.
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
    /// The client-authentication method this client is bound to at `/token`.
    ///
    /// `None` means the registration predates this field. Such a client keeps
    /// exactly the historical behaviour — a shared secret if
    /// `client_secret_hash` is set, no authentication otherwise — and is
    /// **never** accepted via `private_key_jwt`, which has to be opted into
    /// explicitly. Enforcement lives in `handlers::token`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    /// The client's public keys as an inline JWK Set (`{"keys": [...]}`) —
    /// the public half of the keypair used for `private_key_jwt`. There is
    /// deliberately no `jwks_uri` counterpart; see the module docs of
    /// [`crate::client_assertion`] for why.
    ///
    /// Kept as raw JSON rather than a typed `JwkSet` for the same reason
    /// `attestation::EnrolmentChallenge::public_jwk` is: a typed parse
    /// silently drops members it has no field for — including a smuggled
    /// private `d` — so the raw value is re-validated from scratch at every
    /// use through `attestation::parse_public_jwk`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,
}

impl ClientRegistration {
    /// Returns true if `redirect_uri` matches one of this client's registered
    /// URIs.
    ///
    /// The first and normal check is a plain `==` comparison — no
    /// normalization, no prefix matching. That exactness is the defence
    /// against open redirects and is not negotiable for ordinary URIs.
    ///
    /// The one relaxation is the port of a **loopback IP** redirect URI, which
    /// RFC 8252 §7.3 makes a MUST: a native app binds `127.0.0.1:0`, gets a
    /// kernel-assigned port, and cannot possibly have registered it. So a
    /// registered `http://127.0.0.1/cb` also matches
    /// `http://127.0.0.1:54321/cb`. Only the port is ignored; scheme, host,
    /// userinfo, path, query and fragment must still be equal, and both sides
    /// must be `http` on the IP literal `127.0.0.1` or `::1`. The name
    /// `localhost` deliberately does **not** qualify (RFC 8252 §8.3: it
    /// resolves through a name service the app does not control), nor does any
    /// other address in `127.0.0.0/8`. Since the exemption cannot apply to a
    /// non-loopback host, it does not widen the open-redirect surface: an
    /// attacker able to bind a port on the user's own loopback interface
    /// already has code execution there. See authkestra#291.
    pub fn allows_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|registered| {
            if registered == redirect_uri {
                return true;
            }
            if loopback_match(registered, redirect_uri) {
                tracing::debug!(
                    client_id = %self.client_id,
                    registered_uri = %registered,
                    presented_uri = %redirect_uri,
                    "redirect_uri accepted on the RFC 8252 §7.3 loopback any-port exemption"
                );
                return true;
            }
            false
        })
    }

    /// Checks if the client is allowed to use a specific grant type.
    pub fn allows_grant_type(&self, grant_type: &GrantType) -> bool {
        self.grant_types.contains(grant_type)
    }

    /// Checks if the client is registered for a single scope value.
    ///
    /// Takes one already-split scope token, not a space-delimited string —
    /// callers validating a whole `scope` request should split it
    /// themselves and check each token, so they can name the specific
    /// offending scope in their own error response (authkestra#278).
    pub fn allows_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Verifies the provided secret against the stored argon2 hash in constant time.
    pub fn verify_secret(&self, secret: &str) -> bool {
        if let Some(hash_str) = &self.client_secret_hash {
            let parsed_hash = match PasswordHash::new(hash_str) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to parse client secret hash");
                    return false;
                }
            };
            Argon2::default()
                .verify_password(secret.as_bytes(), &parsed_hash)
                .is_ok()
        } else {
            // No secret stored means public client; shouldn't be used for confidential flows
            false
        }
    }
}

/// RFC 8252 §7.3: compares a registered against a presented redirect URI on
/// every component **except** the port, and only when both are loopback IP
/// URIs. Returns false for anything else, so the caller's exact `==` remains
/// the only path by which a non-loopback URI can match.
///
/// Both sides are re-checked independently and symmetrically on purpose: a
/// loopback *registration* must not let a non-loopback URI through, and a
/// loopback URI presented against a non-loopback registration must not match
/// either. Everything the URI carries other than the port — including
/// userinfo, which no legitimate loopback redirect uses — has to be equal, so
/// the only authority this grants a caller is "some port on the user's own
/// machine".
fn loopback_match(registered: &str, presented: &str) -> bool {
    let (Ok(registered), Ok(presented)) = (Url::parse(registered), Url::parse(presented)) else {
        // A URI that does not parse cannot be reasoned about; it can still
        // match byte-for-byte at the call site, but never here.
        return false;
    };

    if registered.scheme() != "http" || presented.scheme() != "http" {
        return false;
    }

    let (Some(registered_host), Some(presented_host)) = (registered.host(), presented.host())
    else {
        return false;
    };
    if !is_loopback_ip(&registered_host) || !is_loopback_ip(&presented_host) {
        return false;
    }

    registered_host == presented_host
        && registered.path() == presented.path()
        && registered.query() == presented.query()
        && registered.fragment() == presented.fragment()
        && registered.username() == presented.username()
        && registered.password() == presented.password()
}

/// True only for the two IP literals RFC 8252 §7.3 names: `127.0.0.1` and
/// `::1`.
///
/// Deliberately not `Ipv4Addr::is_loopback()`: that accepts all of
/// `127.0.0.0/8`, and §7.3 enumerates the two addresses rather than the
/// ranges. `Host::Domain` is always false — that is what keeps `localhost`
/// out, per §8.3, since resolving it depends on a name service the app does
/// not control.
fn is_loopback_ip(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(addr) => *addr == Ipv4Addr::LOCALHOST,
        Host::Ipv6(addr) => *addr == Ipv6Addr::LOCALHOST,
        Host::Domain(_) => false,
    }
}

/// Storage interface for registered clients.
///
/// Mirrors the existing `SessionStore` pattern in `authkestra-engine`:
/// async trait, pluggable backends, in-memory implementation ships first.
#[async_trait]
pub trait ClientStore: Send + Sync {
    /// Look up a client by its `client_id`. Returns `Ok(None)` (not an
    /// error) if the client does not exist — callers map that to
    /// `OpError::UnknownClient`.
    async fn find_client(&self, client_id: &str) -> Result<Option<ClientRegistration>, OpError>;
}

use authkestra_engine::store::KvStore;

#[async_trait]
impl<S> ClientStore for S
where
    S: KvStore<ClientRegistration>,
{
    async fn find_client(&self, client_id: &str) -> Result<Option<ClientRegistration>, OpError> {
        tracing::trace!(client_id, "looking up client");
        self.get(client_id).await.map_err(|e| {
            tracing::error!(error = %e, "failed to lookup client");
            OpError::Storage
        })
    }
}

#[cfg(test)]
#[allow(deprecated)] // `require_pkce` (authkestra#273) — these fixtures don't exercise it
mod tests {

    use super::*;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        PasswordHasher,
    };

    #[test]
    fn test_verify_secret_valid() {
        let password = b"super_secret";
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password, &salt)
            .unwrap()
            .to_string();

        let client = ClientRegistration {
            client_id: "test".to_string(),
            client_secret_hash: Some(password_hash),
            redirect_uris: vec![],
            grant_types: vec![],
            scopes: vec![],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: None,
            jwks: None,
        };

        assert!(client.verify_secret("super_secret"));
    }

    #[test]
    fn test_verify_secret_invalid() {
        let password = b"super_secret";
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password, &salt)
            .unwrap()
            .to_string();

        let client = ClientRegistration {
            client_id: "test".to_string(),
            client_secret_hash: Some(password_hash),
            redirect_uris: vec![],
            grant_types: vec![],
            scopes: vec![],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: None,
            jwks: None,
        };

        assert!(!client.verify_secret("wrong_secret"));
    }

    #[test]
    fn test_verify_secret_public_client() {
        let client = ClientRegistration {
            client_id: "test".to_string(),
            client_secret_hash: None,
            redirect_uris: vec![],
            grant_types: vec![],
            scopes: vec![],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: None,
            jwks: None,
        };

        assert!(!client.verify_secret("some_secret"));
    }

    #[test]
    fn test_grant_type_serialization() {
        let client = ClientRegistration {
            client_id: "test".to_string(),
            client_secret_hash: None,
            redirect_uris: vec![],
            grant_types: vec![
                GrantType::ClientCredentials,
                GrantType::AuthorizationCode,
                GrantType::Custom("my_custom_grant".to_string()),
            ],
            scopes: vec![],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: None,
            jwks: None,
        };

        let serialized = serde_json::to_string(&client).unwrap();
        let deserialized: ClientRegistration = serde_json::from_str(&serialized).unwrap();

        assert_eq!(client.grant_types, deserialized.grant_types);
        assert!(serialized.contains("\"client_credentials\""));
        assert!(serialized.contains("\"authorization_code\""));
        assert!(serialized.contains("\"my_custom_grant\""));
    }

    fn client_with_redirect_uris(uris: &[&str]) -> ClientRegistration {
        ClientRegistration {
            client_id: "native-app".to_string(),
            client_secret_hash: None,
            redirect_uris: uris.iter().map(|u| (*u).to_string()).collect(),
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: vec![],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: None,
            jwks: None,
        }
    }

    /// The authkestra#291 regression: a native app binds an ephemeral port it
    /// could not have registered, and RFC 8252 §7.3 makes accepting it a MUST.
    #[test]
    fn loopback_registration_accepts_any_ephemeral_port() {
        let client = client_with_redirect_uris(&["http://127.0.0.1/cb"]);
        assert!(client.allows_redirect_uri("http://127.0.0.1:54321/cb"));
        assert!(client.allows_redirect_uri("http://127.0.0.1:1/cb"));
        // The registered value itself must keep working.
        assert!(client.allows_redirect_uri("http://127.0.0.1/cb"));
    }

    /// A port written at registration time is not binding — §7.3 is about the
    /// port being unknowable, so a registered port is documentation, not a
    /// constraint.
    #[test]
    fn loopback_registration_with_a_port_accepts_a_different_port() {
        let client = client_with_redirect_uris(&["http://127.0.0.1:8080/cb"]);
        assert!(client.allows_redirect_uri("http://127.0.0.1:9090/cb"));
        assert!(client.allows_redirect_uri("http://127.0.0.1/cb"));
    }

    #[test]
    fn ipv6_loopback_literal_gets_the_same_exemption() {
        let client = client_with_redirect_uris(&["http://[::1]/cb"]);
        assert!(client.allows_redirect_uri("http://[::1]:54321/cb"));
    }

    /// RFC 8252 §8.3: `localhost` resolves through a name service the app does
    /// not control, so it never earns the exemption — in either position.
    #[test]
    fn localhost_never_qualifies() {
        let registered_localhost = client_with_redirect_uris(&["http://localhost/cb"]);
        assert!(!registered_localhost.allows_redirect_uri("http://localhost:54321/cb"));
        assert!(!registered_localhost.allows_redirect_uri("http://127.0.0.1:54321/cb"));

        let registered_ip = client_with_redirect_uris(&["http://127.0.0.1/cb"]);
        assert!(!registered_ip.allows_redirect_uri("http://localhost:54321/cb"));

        // Exact equality still applies to `localhost`, as to anything else.
        assert!(registered_localhost.allows_redirect_uri("http://localhost/cb"));
    }

    /// §7.3 names `127.0.0.1`, not `127.0.0.0/8`.
    #[test]
    fn other_addresses_in_127_slash_8_never_qualify() {
        let client = client_with_redirect_uris(&["http://127.0.0.2/cb"]);
        assert!(!client.allows_redirect_uri("http://127.0.0.2:54321/cb"));

        let client = client_with_redirect_uris(&["http://127.0.0.1/cb"]);
        assert!(!client.allows_redirect_uri("http://127.0.0.2:54321/cb"));
    }

    #[test]
    fn scheme_must_match_and_must_be_http() {
        let client = client_with_redirect_uris(&["https://127.0.0.1/cb"]);
        assert!(!client.allows_redirect_uri("http://127.0.0.1:54321/cb"));
        assert!(!client.allows_redirect_uri("https://127.0.0.1:54321/cb"));

        let client = client_with_redirect_uris(&["http://127.0.0.1/cb"]);
        assert!(!client.allows_redirect_uri("https://127.0.0.1:54321/cb"));
    }

    #[test]
    fn only_the_port_is_ignored() {
        let client = client_with_redirect_uris(&["http://127.0.0.1/cb?x=1#frag"]);
        // Different path.
        assert!(!client.allows_redirect_uri("http://127.0.0.1:54321/other?x=1#frag"));
        // Different query.
        assert!(!client.allows_redirect_uri("http://127.0.0.1:54321/cb?x=2#frag"));
        // Missing query.
        assert!(!client.allows_redirect_uri("http://127.0.0.1:54321/cb#frag"));
        // Different fragment.
        assert!(!client.allows_redirect_uri("http://127.0.0.1:54321/cb?x=1#other"));
        // Only the port differs.
        assert!(client.allows_redirect_uri("http://127.0.0.1:54321/cb?x=1#frag"));
    }

    #[test]
    fn userinfo_must_match() {
        let client = client_with_redirect_uris(&["http://127.0.0.1/cb"]);
        assert!(!client.allows_redirect_uri("http://attacker@127.0.0.1:54321/cb"));
        assert!(!client.allows_redirect_uri("http://:secret@127.0.0.1:54321/cb"));
    }

    /// The exemption must not leak into ordinary URIs: for anything that is
    /// not loopback, the port is part of the exact match as it always was.
    #[test]
    fn non_loopback_uris_still_match_exactly_including_the_port() {
        let client = client_with_redirect_uris(&["https://app.example.com/cb"]);
        assert!(!client.allows_redirect_uri("https://app.example.com:8443/cb"));
        assert!(client.allows_redirect_uri("https://app.example.com/cb"));

        let client = client_with_redirect_uris(&["http://app.example.com:8080/cb"]);
        assert!(!client.allows_redirect_uri("http://app.example.com:9090/cb"));
    }

    /// A loopback registration must not become a wildcard for other hosts.
    #[test]
    fn loopback_registration_does_not_admit_a_non_loopback_uri() {
        let client = client_with_redirect_uris(&["http://127.0.0.1/cb"]);
        assert!(!client.allows_redirect_uri("http://evil.example.com/cb"));
        assert!(!client.allows_redirect_uri("http://evil.example.com:54321/cb"));
        assert!(!client.allows_redirect_uri("http://127.0.0.1.evil.example.com:54321/cb"));
    }

    #[test]
    fn malformed_presented_uri_does_not_match() {
        let client = client_with_redirect_uris(&["http://127.0.0.1/cb"]);
        assert!(!client.allows_redirect_uri("not a url"));
        assert!(!client.allows_redirect_uri("127.0.0.1:54321/cb"));
        assert!(!client.allows_redirect_uri(""));
    }

    /// A registration that does not parse as a URL is still usable through the
    /// exact `==` path; it just never reaches the loopback comparison.
    #[test]
    fn unparseable_registration_still_matches_exactly() {
        let client = client_with_redirect_uris(&["not a url"]);
        assert!(client.allows_redirect_uri("not a url"));
        assert!(!client.allows_redirect_uri("http://127.0.0.1:54321/cb"));
    }
}
