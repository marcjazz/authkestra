use crate::auth::SessionStore;
use crate::engine::{Configured, Engine, Missing};
#[cfg(feature = "token")]
use crate::token::TokenManager;
use std::sync::Arc;

/// Authkestra configured for stateful web app sessions.
pub type AkWebAppEngine = Engine<Configured<Arc<dyn SessionStore>>, Missing>;

/// Authkestra configured for stateless API tokens.
#[cfg(feature = "token")]
pub type AkApiEngine = Engine<Missing, Configured<Arc<TokenManager>>>;

/// Authkestra configured for both sessions and tokens (e.g. OpenID Connect Provider).
#[cfg(feature = "token")]
pub type AkEngine = Engine<Configured<Arc<dyn SessionStore>>, Configured<Arc<TokenManager>>>;
