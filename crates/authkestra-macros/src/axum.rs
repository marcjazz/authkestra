//! # Authkestra Macros
//!
//! Procedural macros for authkestra framework integrations to eliminate boilerplate
//! when integrating with custom application state.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use authkestra_axum::State;
//! use authkestra::flow::Engine;
//!
//! #[derive(Clone, State)]
//! struct AppState {
//!     #[authkestra(engine)]
//!     auth: Engine<Configured<Arc<dyn SessionStore>>, Missing>,
//!     
//!     #[authkestra(store)]
//!     clients: Arc<dyn ClientStore>,
//!
//!     db_pool: Arc<PgPool>,
//! }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Type};

pub(crate) fn derive_authkestra_state_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    // Extract struct name and generics
    let struct_name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut engine_field = None;
    let mut store_fields = Vec::new();

    match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields) => {
                for field in &fields.named {
                    for attr in &field.attrs {
                        let is_authkestra = attr.path().is_ident("authkestra");

                        if is_authkestra {
                            let _ = attr.parse_nested_meta(|meta| {
                                if meta.path.is_ident("engine") {
                                    engine_field = Some(field);
                                } else if meta.path.is_ident("store") {
                                    store_fields.push(field);
                                }
                                Ok(())
                            });
                        }
                    }
                }
            }
            _ => {
                return syn::Error::new_spanned(
                    &input,
                    "State can only be derived for structs with named fields",
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(
                &input,
                "State can only be derived for structs",
            )
            .to_compile_error()
            .into();
        }
    };

    let mut generated_impls = Vec::new();

    // 1. Process Engine Field
    if let Some(field) = engine_field {
        let field_name = field.ident.as_ref().unwrap();

        let (s_param, t_param): (syn::Type, syn::Type) = match &field.ty {
            Type::Path(type_path) => {
                let last_segment = type_path.path.segments.last().unwrap();
                let ident_str = last_segment.ident.to_string();

                if ident_str == "AkWebAppEngine" {
                    (
                        syn::parse_quote!(
                            authkestra_engine::Configured<
                                ::std::sync::Arc<dyn authkestra_engine::auth::SessionStore>,
                            >
                        ),
                        syn::parse_quote!(authkestra_engine::Missing),
                    )
                } else if ident_str == "AkApiEngine" {
                    (
                        syn::parse_quote!(authkestra_engine::Missing),
                        syn::parse_quote!(
                            authkestra_engine::Configured<
                                ::std::sync::Arc<authkestra_engine::TokenManager>,
                            >
                        ),
                    )
                } else if ident_str == "AkEngine" {
                    (
                        syn::parse_quote!(
                            authkestra_engine::Configured<
                                ::std::sync::Arc<dyn authkestra_engine::auth::SessionStore>,
                            >
                        ),
                        syn::parse_quote!(
                            authkestra_engine::Configured<
                                ::std::sync::Arc<authkestra_engine::TokenManager>,
                            >
                        ),
                    )
                } else if ident_str == "Authkestra" || ident_str == "Engine" {
                    match &last_segment.arguments {
                        syn::PathArguments::AngleBracketed(args) => {
                            if args.args.len() != 2 {
                                return syn::Error::new_spanned(
                                    &field.ty,
                                    "Engine must have exactly 2 type parameters: Engine<S, T>",
                                )
                                .to_compile_error()
                                .into();
                            }
                            let s = &args.args[0];
                            let t = &args.args[1];
                            (syn::parse_quote!(#s), syn::parse_quote!(#t))
                        }
                        _ => {
                            return syn::Error::new_spanned(
                                &field.ty,
                                "Engine must have type parameters: Engine<S, T>",
                            )
                            .to_compile_error()
                            .into();
                        }
                    }
                } else {
                    return syn::Error::new_spanned(
                        &field.ty,
                        "Field marked with #[authkestra(engine)] must be of type Engine<S, T>, AkWebAppEngine, AkApiEngine, or AkEngine",
                    )
                    .to_compile_error()
                    .into();
                }
            }
            _ => {
                return syn::Error::new_spanned(
                    &field.ty,
                    "Field marked with #[authkestra(engine)] must be a valid path type",
                )
                .to_compile_error()
                .into();
            }
        };

        generated_impls.push(quote! {
            impl #impl_generics axum::extract::FromRef<#struct_name #ty_generics> for authkestra_engine::Engine<#s_param, #t_param>
            where
                #s_param: Clone,
                #t_param: Clone,
                #where_clause
            {
                fn from_ref(state: &#struct_name #ty_generics) -> Self {
                    state.#field_name.clone()
                }
            }

            #[allow(unused_imports)]
            use authkestra_engine::{SessionStoreState as _, TokenManagerState as _};

            impl #impl_generics axum::extract::FromRef<#struct_name #ty_generics>
                for ::std::result::Result<::std::sync::Arc<dyn authkestra_engine::auth::SessionStore>, authkestra_axum::Error>
            where
                #s_param: authkestra_engine::SessionStoreState,
                #where_clause
            {
                fn from_ref(state: &#struct_name #ty_generics) -> Self {
                    Ok(state.#field_name.session_store.get_store())
                }
            }

            impl #impl_generics axum::extract::FromRef<#struct_name #ty_generics> for authkestra_engine::SessionConfig
            #where_clause
            {
                fn from_ref(state: &#struct_name #ty_generics) -> Self {
                    state.#field_name.session_config.clone()
                }
            }
        });

        let t_param_str = quote!(#t_param).to_string();
        if !t_param_str.contains("Missing") {
            generated_impls.push(quote! {
                impl #impl_generics axum::extract::FromRef<#struct_name #ty_generics>
                    for ::std::result::Result<::std::sync::Arc<authkestra_engine::TokenManager>, authkestra_axum::Error>
                where
                    #t_param: authkestra_engine::TokenManagerState,
                    #where_clause
                {
                    fn from_ref(state: &#struct_name #ty_generics) -> Self {
                        Ok(state.#field_name.token_manager.get_manager())
                    }
                }
            });
        }
    }

    // 2. Process Store Fields
    for field in store_fields {
        let field_name = field.ident.as_ref().unwrap();
        let field_ty = &field.ty;

        generated_impls.push(quote! {
            impl #impl_generics axum::extract::FromRef<#struct_name #ty_generics> for #field_ty
            #where_clause
            {
                fn from_ref(state: &#struct_name #ty_generics) -> Self {
                    state.#field_name.clone()
                }
            }

            impl #impl_generics axum::extract::FromRef<#struct_name #ty_generics> for ::std::result::Result<#field_ty, authkestra_axum::Error>
            #where_clause
            {
                fn from_ref(state: &#struct_name #ty_generics) -> Self {
                    Ok(state.#field_name.clone())
                }
            }
        });
    }

    if engine_field.is_none() && generated_impls.is_empty() {
        return syn::Error::new_spanned(
            &input,
            "No field marked with #[authkestra(engine)] found. Add #[authkestra(engine)] to your Engine field."
        )
        .to_compile_error()
        .into();
    }

    let expanded = quote! {
        #(#generated_impls)*
    };

    TokenStream::from(expanded)
}
