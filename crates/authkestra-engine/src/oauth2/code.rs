use crate::auth::state::Identity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An authorization code issued at `/authorize`, pending exchange at
/// `/token`.
///
/// Codes are single-use (`used`) and short-lived (`expires_at`) — see
/// RFC-003 §7. `AuthorizationCodeStore::consume_code` is responsible for
/// enforcing single-use atomically; this struct is deliberately a plain
/// data holder with no enforcement logic of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    /// The opaque code value handed to the client.
    pub code: String,
    /// The client this code was issued to.
    pub client_id: String,
    /// The exact redirect_uri presented at `/authorize`; `/token` must
    /// receive the same value.
    pub redirect_uri: String,
    /// Space-delimited scopes granted.
    pub scope: String,
    /// PKCE code_challenge, if the client used PKCE.
    pub code_challenge: Option<String>,
    /// PKCE code_challenge_method (`plain` or `S256`).
    pub code_challenge_method: Option<String>,
    /// OIDC nonce, if provided in the authorization request.
    pub nonce: Option<String>,
    /// The authenticated identity this code represents.
    pub identity: Identity,
    /// When this code expires. Recommend issuing with a short lifetime
    /// (≤60s per RFC-003 §7).
    pub expires_at: DateTime<Utc>,
    /// Whether this code has already been exchanged. Storage
    /// implementations must treat consuming an already-used code as an
    /// error, not a silent no-op.
    pub used: bool,
}

impl AuthorizationCode {
    /// Creates a new authorization code.
    ///
    /// this crate, but `AuthorizationCodeStore` implementations must be able
    /// to reconstruct a code from their own storage — this is the seam that
    /// makes that possible (authkestra#268). `used` is a required parameter
    /// rather than a default: this crate's own storage backends deliberately
    /// fail *closed* on it (treating a code as already-used if its stored
    /// value can't be read, e.g. `authkestra-store-sqlx`'s
    /// `row.try_get("used").unwrap_or(true)`), and a constructor that
    /// silently defaulted to `false` would make it easy for a downstream
    /// implementation to reconstruct an already-spent code as fresh by
    /// forgetting to set it. `code_challenge`, `code_challenge_method` and
    /// `nonce` start `None` and, since every field here is `pub`, can be set
    /// directly on the returned value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        code: String,
        client_id: String,
        redirect_uri: String,
        scope: String,
        identity: Identity,
        expires_at: DateTime<Utc>,
        used: bool,
    ) -> Self {
        Self {
            code,
            client_id,
            redirect_uri,
            scope,
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            identity,
            expires_at,
            used,
        }
    }

    /// Returns true if this code is expired as of `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}
