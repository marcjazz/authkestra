use crate::engine::{AkBase, Configured, Missing};
use crate::auth::SessionStore;
#[cfg(feature = "token")]
use crate::token::TokenManager;
use std::sync::Arc;

/// Authkestra configured for stateful web app sessions.
pub type AkWebAppEngine = AkBase<Configured<Arc<dyn SessionStore>>, Missing>;

/// Authkestra configured for stateless API tokens.
#[cfg(feature = "token")]
pub type AkApiEngine = AkBase<Missing, Configured<Arc<TokenManager>>>;

/// Authkestra configured for both sessions and tokens (e.g. OpenID Connect Provider).
#[cfg(feature = "token")]
pub type AkEngine = AkBase<Configured<Arc<dyn SessionStore>>, Configured<Arc<TokenManager>>>;
