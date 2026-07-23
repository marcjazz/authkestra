use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, LitStr};

pub(crate) fn derive_authkestra_kv_store_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let (_impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let mut table_name = "authkestra_kv".to_string();

    for attr in &input.attrs {
        if attr.path().is_ident("authkestra") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("table") {
                    let value = meta.value()?;
                    let s: LitStr = value.parse()?;
                    table_name = s.value();
                }
                Ok(())
            });
        }
    }

    let expanded = quote! {
        #[::async_trait::async_trait]
        impl<T> authkestra_engine::store::KvStore<T> for #struct_name #ty_generics
        where
            T: ::serde::Serialize + ::serde::de::DeserializeOwned + Send + Sync + 'static,
            #where_clause
        {
            async fn get(&self, key: &str) -> ::std::result::Result<Option<T>, authkestra_engine::store::StoreError> {
                let temp_store = authkestra_engine::store::sql::SqlKvStore::<sqlx::Sqlite>::with_table_name(self.0.clone(), #table_name.to_string());
                <authkestra_engine::store::sql::SqlKvStore<sqlx::Sqlite> as authkestra_engine::store::KvStore<T>>::get(&temp_store, key).await
            }

            async fn set(&self, key: &str, value: T, ttl: std::time::Duration) -> ::std::result::Result<(), authkestra_engine::store::StoreError> {
                let temp_store = authkestra_engine::store::sql::SqlKvStore::<sqlx::Sqlite>::with_table_name(self.0.clone(), #table_name.to_string());
                <authkestra_engine::store::sql::SqlKvStore<sqlx::Sqlite> as authkestra_engine::store::KvStore<T>>::set(&temp_store, key, value, ttl).await
            }

            async fn delete(&self, key: &str) -> ::std::result::Result<(), authkestra_engine::store::StoreError> {
                let temp_store = authkestra_engine::store::sql::SqlKvStore::<sqlx::Sqlite>::with_table_name(self.0.clone(), #table_name.to_string());
                <authkestra_engine::store::sql::SqlKvStore<sqlx::Sqlite> as authkestra_engine::store::KvStore<T>>::delete(&temp_store, key).await
            }
        }
    };

    TokenStream::from(expanded)
}

pub(crate) fn derive_authkestra_repository_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let (_impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let mut table_name = "authkestra_repo".to_string();

    for attr in &input.attrs {
        if attr.path().is_ident("authkestra") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("table") {
                    let value: LitStr = meta.value()?.parse()?;
                    table_name = value.value();
                }
                Ok(())
            });
        }
    }

    let expanded = quote! {
        #[::async_trait::async_trait]
        impl<Entity, ID> authkestra_engine::store::Repository<Entity, ID> for #struct_name #ty_generics
        where
            Entity: ::serde::Serialize + ::serde::de::DeserializeOwned + Send + Sync + 'static,
            ID: ::std::fmt::Display + Send + Sync + 'static,
            #where_clause
        {
            async fn find_by_id(&self, id: &ID) -> ::std::result::Result<Option<Entity>, authkestra_engine::store::StoreError> {
                let temp_store = authkestra_engine::store::sql::SqlKvStore::<sqlx::Sqlite>::with_table_name(self.0.clone(), #table_name.to_string());
                <authkestra_engine::store::sql::SqlKvStore<sqlx::Sqlite> as authkestra_engine::store::KvStore<Entity>>::get(&temp_store, &id.to_string()).await
            }

            async fn save(&self, entity: &Entity) -> ::std::result::Result<(), authkestra_engine::store::StoreError> {
                ::std::result::Result::Err(authkestra_engine::store::StoreError::Internal("Not fully implemented in macro".to_string()))
            }

            async fn delete(&self, id: &ID) -> ::std::result::Result<(), authkestra_engine::store::StoreError> {
                let temp_store = authkestra_engine::store::sql::SqlKvStore::<sqlx::Sqlite>::with_table_name(self.0.clone(), #table_name.to_string());
                <authkestra_engine::store::sql::SqlKvStore<sqlx::Sqlite> as authkestra_engine::store::KvStore<Entity>>::delete(&temp_store, &id.to_string()).await
            }
        }
    };

    TokenStream::from(expanded)
}
