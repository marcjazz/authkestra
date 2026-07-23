use proc_macro::TokenStream;

#[cfg(feature = "axum")]
mod axum;

mod derive;

#[cfg(feature = "axum")]
#[proc_macro_derive(State, attributes(authkestra))]
pub fn derive_authkestra_state(input: TokenStream) -> TokenStream {
    axum::derive_authkestra_state_impl(input)
}



#[proc_macro_derive(KvStore, attributes(authkestra))]
pub fn derive_authkestra_kv_store(input: TokenStream) -> TokenStream {
    derive::derive_authkestra_kv_store_impl(input)
}
