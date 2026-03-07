#[cfg(feature = "axum")]
use proc_macro::TokenStream;

#[cfg(feature = "axum")]
mod axum;

#[cfg(feature = "axum")]
#[proc_macro_derive(AuthkestraFromRef, attributes(authkestra))]
pub fn derive_authkestra_from_ref(input: TokenStream) -> TokenStream {
    axum::derive_authkestra_from_ref_impl(input)
}
