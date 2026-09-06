//! # Engine Macros
//!
//! Procedural macros for authkestra framework integrations to eliminate boilerplate
//! when integrating with custom application state.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use authkestra_axum::AxumState;
//! use authkestra::flow::Engine;
//!
//! #[derive(Clone, AxumState)]
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
//!
//! ## Reaching the adapter under another name
//!
//! Every emitted path hangs off `::authkestra_axum`. A caller reaching this
//! adapter by a different name — the facade's `authkestra::axum` re-export,
//! say — redirects the anchor on the struct:
//!
//! ```rust,ignore
//! #[derive(Clone, AxumState)]
//! #[authkestra(crate = ::authkestra::axum)]
//! struct AppState { /* ... */ }
//! ```

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Type};

pub(crate) fn derive_authkestra_state_impl(input: TokenStream) -> TokenStream {
    let input = match syn::parse2::<DeriveInput>(input) {
        Ok(input) => input,
        Err(err) => return err.to_compile_error(),
    };

    // Every emitted path hangs off this, so the expansion never depends on
    // what the caller happens to have in scope (#332).
    let anchor = match crate::anchor::resolve(&input.attrs, "::authkestra_axum") {
        Ok(anchor) => anchor,
        Err(err) => return err.to_compile_error(),
    };
    let engine = quote!(#anchor::__private::authkestra_engine);
    let web = quote!(#anchor::__private::axum);

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
                    "AxumState can only be derived for structs with named fields",
                )
                .to_compile_error();
            }
        },
        _ => {
            return syn::Error::new_spanned(&input, "AxumState can only be derived for structs")
                .to_compile_error();
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
                            #engine::Configured<
                                ::std::sync::Arc<dyn #engine::auth::SessionStore>,
                            >
                        ),
                        syn::parse_quote!(#engine::Missing),
                    )
                } else if ident_str == "AkApiEngine" {
                    (
                        syn::parse_quote!(#engine::Missing),
                        syn::parse_quote!(
                            #engine::Configured<
                                ::std::sync::Arc<#engine::TokenManager>,
                            >
                        ),
                    )
                } else if ident_str == "AkEngine" {
                    (
                        syn::parse_quote!(
                            #engine::Configured<
                                ::std::sync::Arc<dyn #engine::auth::SessionStore>,
                            >
                        ),
                        syn::parse_quote!(
                            #engine::Configured<
                                ::std::sync::Arc<#engine::TokenManager>,
                            >
                        ),
                    )
                } else if ident_str == "Engine" {
                    match &last_segment.arguments {
                        syn::PathArguments::AngleBracketed(args) => {
                            if args.args.len() != 2 {
                                return syn::Error::new_spanned(
                                    &field.ty,
                                    "Engine must have exactly 2 type parameters: Engine<S, T>",
                                )
                                .to_compile_error();
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
                            .to_compile_error();
                        }
                    }
                } else {
                    return syn::Error::new_spanned(
                        &field.ty,
                        "Field marked with #[authkestra(engine)] must be of type Engine<S, T>, AkWebAppEngine, AkApiEngine, or AkEngine",
                    )
                    .to_compile_error();
                }
            }
            _ => {
                return syn::Error::new_spanned(
                    &field.ty,
                    "Field marked with #[authkestra(engine)] must be a valid path type",
                )
                .to_compile_error();
            }
        };

        generated_impls.push(quote! {
            impl #impl_generics #web::extract::FromRef<#struct_name #ty_generics> for #engine::Engine<#s_param, #t_param>
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
            use #engine::{SessionStoreState as _, TokenManagerState as _};
        });

        let s_param_str = quote!(#s_param).to_string();
        if !s_param_str.contains("Missing") {
            generated_impls.push(quote! {
                impl #impl_generics #web::extract::FromRef<#struct_name #ty_generics>
                    for ::std::result::Result<::std::sync::Arc<dyn #engine::auth::SessionStore>, #anchor::AxumError>
                where
                    #s_param: #engine::SessionStoreState,
                    #where_clause
                {
                    fn from_ref(state: &#struct_name #ty_generics) -> Self {
                        Ok(state.#field_name.session_store.get_store())
                    }
                }
            });
        }

        generated_impls.push(quote! {
            impl #impl_generics #web::extract::FromRef<#struct_name #ty_generics> for #engine::SessionConfig
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
                impl #impl_generics #web::extract::FromRef<#struct_name #ty_generics>
                    for ::std::result::Result<::std::sync::Arc<#engine::TokenManager>, #anchor::AxumError>
                where
                    #t_param: #engine::TokenManagerState,
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
            impl #impl_generics #web::extract::FromRef<#struct_name #ty_generics> for #field_ty
            #where_clause
            {
                fn from_ref(state: &#struct_name #ty_generics) -> Self {
                    state.#field_name.clone()
                }
            }

            impl #impl_generics #web::extract::FromRef<#struct_name #ty_generics> for ::std::result::Result<#field_ty, #anchor::AxumError>
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
        .to_compile_error();
    }

    let expanded = quote! {
        #(#generated_impls)*
    };

    expanded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand(container_attrs: TokenStream) -> String {
        let input = quote! {
            #container_attrs
            struct AppState {
                #[authkestra(engine)]
                auth: AkEngine,
                #[authkestra(store)]
                clients: ::std::sync::Arc<dyn ClientStore>,
            }
        };
        derive_authkestra_state_impl(input).to_string()
    }

    /// #332: every `authkestra_engine` path must be anchored. A bare one only
    /// resolves if the caller happens to have that exact crate as a direct
    /// dependency, which someone depending on the `authkestra` facade does
    /// not — and the resulting error names a crate they never wrote down.
    #[test]
    fn every_engine_path_is_anchored() {
        let expanded = expand(quote!());

        assert!(
            expanded.contains("authkestra_engine"),
            "expansion should reference the engine at all"
        );
        assert_eq!(
            expanded.matches("authkestra_engine").count(),
            expanded
                .matches(":: __private :: authkestra_engine")
                .count(),
            "some engine path is not routed through the anchor: {expanded}"
        );
    }

    /// The same applies to `axum` itself: the expansion names
    /// `axum::extract::FromRef`, so a facade-only caller without `axum` as a
    /// direct dependency fails there too.
    #[test]
    fn every_axum_path_is_anchored() {
        let expanded = expand(quote!());

        assert!(expanded.contains("extract :: FromRef"));
        assert_eq!(
            expanded.matches("extract :: FromRef").count(),
            expanded
                .matches(":: __private :: axum :: extract :: FromRef")
                .count(),
            "some axum path is not routed through the anchor: {expanded}"
        );
    }

    #[test]
    fn the_error_type_is_anchored_too() {
        let expanded = expand(quote!());

        assert!(expanded.contains("AxumError"));
        assert_eq!(
            expanded.matches("AxumError").count(),
            expanded.matches(":: authkestra_axum :: AxumError").count(),
            "some AxumError path is not routed through the anchor: {expanded}"
        );
    }

    /// A caller reaching this crate under another name — `authkestra::axum`
    /// through the facade — redirects the anchor rather than being stuck with
    /// a crate name they cannot use.
    #[test]
    fn the_anchor_can_be_redirected_at_the_struct() {
        let expanded = expand(quote!(#[authkestra(crate = ::authkestra::axum)]));

        assert!(
            expanded.contains(":: authkestra :: axum :: __private :: authkestra_engine"),
            "the `crate = ...` override was ignored: {expanded}"
        );
        assert!(
            !expanded.contains(":: authkestra_axum ::"),
            "the default anchor leaked through despite the override: {expanded}"
        );
    }
}
