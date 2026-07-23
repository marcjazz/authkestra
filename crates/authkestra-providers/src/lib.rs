#[macro_use]
pub mod macros;

#[cfg(feature = "github")]
pub mod github;

#[cfg(feature = "google")]
pub mod google;

#[cfg(feature = "discord")]
pub mod discord;
