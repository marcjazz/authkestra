use crate::auth::state::Identity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents a stored refresh token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RefreshToken {
    /// The actual token string (usually a cryptographically secure random string).
    pub token: String,
    /// The client this token was issued to.
    pub client_id: String,
    /// The authenticated identity (user) this token acts on behalf of.
    pub identity: Identity,
    /// The scopes granted to this token.
    pub scope: String,
    /// When this token expires.
    pub expires_at: DateTime<Utc>,
    /// The RFC 7638 thumbprint of the DPoP key this token is bound to
    /// (RFC 9449 §5), if the request that minted it presented a DPoP proof.
    ///
    /// `None` means this refresh token is an ordinary bearer token — no
    /// continuity is required or enforced on rotation. Once `Some`, RFC
    /// 9449 §5 requires every future `refresh_token` grant redeeming this
    /// token (and each token it rotates into) to present a fresh DPoP
    /// proof for this *same* key; a request that omits DPoP, or presents a
    /// proof for a different key, must be refused. Without this check, an
    /// exfiltrated DPoP-bound refresh token could simply be redeemed with
    /// the attacker's own key (or with no proof at all), defeating exactly
    /// the sender-constraining guarantee DPoP exists to provide for public
    /// clients (authkestra#274).
    pub jkt: Option<String>,
}

impl RefreshToken {
    /// Creates a new refresh token.
    ///
    /// `#[non_exhaustive]` blocks struct-literal construction from outside
    /// this crate, but `RefreshTokenStore` implementations must be able to
    /// reconstruct a token from their own storage — this is the seam that
    /// makes that possible (authkestra#268).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: String,
        client_id: String,
        identity: Identity,
        scope: String,
        expires_at: DateTime<Utc>,
        jkt: Option<String>,
    ) -> Self {
        Self {
            token,
            client_id,
            identity,
            scope,
            expires_at,
            jkt,
        }
    }
}
