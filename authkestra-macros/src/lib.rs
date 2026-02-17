//! # Authkestra Macros
//!
//! Procedural macros for authkestra framework integrations to eliminate boilerplate
//! when integrating with custom application state.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use authkestra_axum::AuthkestraFromRef;
//! use authkestra::flow::Authkestra;
//!
//! #[derive(Clone, AuthkestraFromRef)]
//! struct AppState {
//!     #[authkestra]
//!     auth: Authkestra<Configured<Arc<dyn SessionStore>>, Missing>,
//!     db_pool: Arc<PgPool>,
//! }
//! ```
//!
//! This automatically generates the 4 required `FromRef` trait implementations.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Type};

/// Derive macro for automatic `FromRef` trait implementations.
///
/// This macro generates 4 `FromRef` implementations required for Axum extractors:
/// - `FromRef<YourState> for Authkestra<S, T>`
/// - `FromRef<YourState> for Result<Arc<dyn SessionStore>, AuthkestraAxumError>`
/// - `FromRef<YourState> for SessionConfig`
/// - `FromRef<YourState> for Result<Arc<TokenManager>, AuthkestraAxumError>`
///
/// ## Requirements
///
/// - The struct must have exactly one field marked with `#[authkestra]`
/// - That field must be of type `Authkestra<S, T>` where S and T are type parameters
///
/// ## Example
///
/// ```rust,ignore
/// #[derive(Clone, AuthkestraFromRef)]
/// struct AppState<S, T> {
///     #[authkestra]
///     auth: Authkestra<S, T>,
///     db_pool: Arc<PgPool>,
/// }
/// ```
#[proc_macro_derive(AuthkestraFromRef, attributes(authkestra))]
pub fn derive_authkestra_from_ref(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    // Extract struct name and generics
    let struct_name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Find the field marked with #[authkestra]
    let authkestra_field = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields) => fields.named.iter().find(|f| {
                f.attrs
                    .iter()
                    .any(|attr| attr.path().is_ident("authkestra"))
            }),
            _ => {
                return syn::Error::new_spanned(
                    &input,
                    "AuthkestraFromRef can only be derived for structs with named fields",
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(
                &input,
                "AuthkestraFromRef can only be derived for structs",
            )
            .to_compile_error()
            .into();
        }
    };

    let authkestra_field = match authkestra_field {
        Some(field) => field,
        None => {
            return syn::Error::new_spanned(
                &input,
                "No field marked with #[authkestra] found. Add #[authkestra] to your Authkestra field."
            )
            .to_compile_error()
            .into();
        }
    };

    let field_name = authkestra_field.ident.as_ref().unwrap();

    // Extract type parameters S and T from Authkestra<S, T>
    let (s_param, t_param) = match &authkestra_field.ty {
        Type::Path(type_path) => {
            let last_segment = type_path.path.segments.last().unwrap();
            if last_segment.ident != "Authkestra" {
                return syn::Error::new_spanned(
                    &authkestra_field.ty,
                    "Field marked with #[authkestra] must be of type Authkestra<S, T>",
                )
                .to_compile_error()
                .into();
            }

            match &last_segment.arguments {
                syn::PathArguments::AngleBracketed(args) => {
                    if args.args.len() != 2 {
                        return syn::Error::new_spanned(
                            &authkestra_field.ty,
                            "Authkestra must have exactly 2 type parameters: Authkestra<S, T>",
                        )
                        .to_compile_error()
                        .into();
                    }

                    let s = &args.args[0];
                    let t = &args.args[1];
                    (s, t)
                }
                _ => {
                    return syn::Error::new_spanned(
                        &authkestra_field.ty,
                        "Authkestra must have type parameters: Authkestra<S, T>",
                    )
                    .to_compile_error()
                    .into();
                }
            }
        }
        _ => {
            return syn::Error::new_spanned(
                &authkestra_field.ty,
                "Field marked with #[authkestra] must be of type Authkestra<S, T>",
            )
            .to_compile_error()
            .into();
        }
    };

    // Generate the 4 FromRef implementations
    let expanded = quote! {
        // 1. FromRef for Authkestra<S, T>
        impl #impl_generics axum::extract::FromRef<#struct_name #ty_generics> for authkestra_flow::Authkestra<#s_param, #t_param>
        where
            #s_param: Clone,
            #t_param: Clone,
            #where_clause
        {
            fn from_ref(state: &#struct_name #ty_generics) -> Self {
                state.#field_name.clone()
            }
        }

        // 2. FromRef for SessionStore (when S: SessionStoreState)
        impl #impl_generics axum::extract::FromRef<#struct_name #ty_generics>
            for ::std::result::Result<::std::sync::Arc<dyn authkestra_session::SessionStore>, authkestra_axum::AuthkestraAxumError>
        where
            #s_param: authkestra_flow::SessionStoreState,
            #where_clause
        {
            fn from_ref(state: &#struct_name #ty_generics) -> Self {
                Ok(state.#field_name.session_store.get_store())
            }
        }

        // 3. FromRef for SessionConfig
        impl #impl_generics axum::extract::FromRef<#struct_name #ty_generics> for authkestra_session::SessionConfig
        #where_clause
        {
            fn from_ref(state: &#struct_name #ty_generics) -> Self {
                state.#field_name.session_config.clone()
            }
        }

        // 4. FromRef for TokenManager (when T: TokenManagerState)
        impl #impl_generics axum::extract::FromRef<#struct_name #ty_generics>
            for ::std::result::Result<::std::sync::Arc<authkestra_token::TokenManager>, authkestra_axum::AuthkestraAxumError>
        where
            #t_param: authkestra_flow::TokenManagerState,
            #where_clause
        {
            fn from_ref(state: &#struct_name #ty_generics) -> Self {
                Ok(state.#field_name.token_manager.get_manager())
            }
        }
    };

    TokenStream::from(expanded)
}
