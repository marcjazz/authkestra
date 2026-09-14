use proc_macro::TokenStream;

mod anchor;

#[cfg(feature = "axum")]
mod axum;

#[cfg(feature = "actix")]
mod actix;

mod derive;

#[cfg(feature = "axum")]
#[proc_macro_derive(AxumState, attributes(authkestra))]
pub fn derive_authkestra_axum_state(input: TokenStream) -> TokenStream {
    axum::derive_authkestra_state_impl(input.into()).into()
}

#[cfg(feature = "actix")]
#[proc_macro_derive(ActixState, attributes(authkestra))]
pub fn derive_authkestra_actix_state(input: TokenStream) -> TokenStream {
    actix::derive_authkestra_state_impl(input.into()).into()
}

#[proc_macro_derive(KvStore, attributes(authkestra))]
pub fn derive_authkestra_kv_store(input: TokenStream) -> TokenStream {
    derive::derive_authkestra_kv_store_impl(input)
}
