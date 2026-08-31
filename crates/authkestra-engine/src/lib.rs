// The outbound HTTP client needs a TLS backend. Fail loudly at compile time
// rather than letting `reqwest::Client::new()` panic at runtime.
#[cfg(not(any(feature = "rustls-aws-lc-rs", feature = "rustls-no-provider")))]
compile_error!(
    "authkestra-engine needs a TLS backend: enable the `rustls-aws-lc-rs` feature (the default) \
     or the `rustls-no-provider` feature and install a `rustls::CryptoProvider` yourself."
);

pub mod auth;
pub mod client_assertion;
pub mod engine;
pub mod flow;
pub mod protocol;
pub mod store;
pub mod token;

pub mod aliases;

pub use aliases::*;
pub use auth::*;
pub use engine::*;
pub use flow::*;
pub use token::*;

#[cfg(feature = "captcha")]
pub mod captcha;
#[cfg(feature = "captcha")]
pub use captcha::{CaptchaProvider, CaptchaVerifier};

#[cfg(test)]
mod tests;
pub mod oauth2;
