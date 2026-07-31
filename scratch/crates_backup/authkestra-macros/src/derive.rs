use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

pub(crate) fn derive_authkestra_kv_store_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let (_impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let expanded = quote! {
        #[::async_trait::async_trait]
        impl<T> authkestra_engine::store::KvStore<T> for #struct_name #ty_generics
        where
            T: ::serde::Serialize + ::serde::de::DeserializeOwned + Send + Sync + 'static,
            #where_clause
        {
            async fn get(&self, key: &str) -> ::std::result::Result<Option<T>, authkestra_engine::store::StoreError> {
                <_ as authkestra_engine::store::KvStore<T>>::get(&self.0, key).await
            }

            async fn set(&self, key: &str, value: T, ttl: std::time::Duration) -> ::std::result::Result<(), authkestra_engine::store::StoreError> {
                <_ as authkestra_engine::store::KvStore<T>>::set(&self.0, key, value, ttl).await
            }

            async fn delete(&self, key: &str) -> ::std::result::Result<(), authkestra_engine::store::StoreError> {
                <_ as authkestra_engine::store::KvStore<T>>::delete(&self.0, key).await
            }
        }
    };

    TokenStream::from(expanded)
}
