//! # Actix state derive
//!
//! Generates `configure_authkestra`, registering the engine's pieces as
//! `actix_web` app data.
//!
//! ## Reaching the adapter under another name
//!
//! Every emitted path hangs off `::authkestra_actix`. A caller reaching this
//! adapter by a different name — the facade's `authkestra::actix` re-export,
//! say — redirects the anchor on the struct:
//!
//! ```rust,ignore
//! #[derive(Clone, ActixState)]
//! #[authkestra(crate = ::authkestra::actix)]
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
    let anchor = match crate::anchor::resolve(&input.attrs, "::authkestra_actix") {
        Ok(anchor) => anchor,
        Err(err) => return err.to_compile_error(),
    };
    let engine = quote!(#anchor::__private::authkestra_engine);
    let web = quote!(#anchor::__private::actix_web);

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
                .to_compile_error();
            }
        },
        _ => {
            return syn::Error::new_spanned(&input, "State can only be derived for structs")
                .to_compile_error();
        }
    };

    let mut config_statements = Vec::new();

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

        config_statements.push(quote! {
            cfg.app_data(#web::web::Data::new(self.#field_name.clone()));
        });

        let s_param_str = quote!(#s_param).to_string();
        if !s_param_str.contains("Missing") {
            config_statements.push(quote! {
                cfg.app_data(#web::web::Data::new(
                    #engine::SessionStoreState::get_store(&self.#field_name.session_store)
                ));
            });
        }

        config_statements.push(quote! {
            cfg.app_data(#web::web::Data::new(
                self.#field_name.session_config.clone()
            ));
        });

        let t_param_str = quote!(#t_param).to_string();
        if !t_param_str.contains("Missing") {
            config_statements.push(quote! {
                cfg.app_data(#web::web::Data::new(
                    #engine::TokenManagerState::get_manager(&self.#field_name.token_manager)
                ));
            });
        }
    }

    for field in store_fields {
        let field_name = field.ident.as_ref().unwrap();
        config_statements.push(quote! {
            cfg.app_data(#web::web::Data::new(self.#field_name.clone()));
        });
    }

    if engine_field.is_none() && config_statements.is_empty() {
        return syn::Error::new_spanned(
            &input,
            "No field marked with #[authkestra(engine)] found. Add #[authkestra(engine)] to your Engine field."
        )
        .to_compile_error();
    }

    let expanded = quote! {
        impl #impl_generics #struct_name #ty_generics #where_clause {
            pub fn configure_authkestra(&self, cfg: &mut #web::web::ServiceConfig) {
                #(#config_statements)*
            }
        }
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

    /// #332, actix half. The bug was identical in both derives, so the fix and
    /// its tests are too — covering only one would recreate exactly the
    /// adapter asymmetry #320/#327/#329 are about.
    #[test]
    fn every_engine_path_is_anchored() {
        let expanded = expand(quote!());

        assert!(expanded.contains("authkestra_engine"));
        assert_eq!(
            expanded.matches("authkestra_engine").count(),
            expanded
                .matches(":: __private :: authkestra_engine")
                .count(),
            "some engine path is not routed through the anchor: {expanded}"
        );
    }

    #[test]
    fn every_actix_web_path_is_anchored() {
        let expanded = expand(quote!());

        assert!(expanded.contains("web :: Data"));
        assert_eq!(
            expanded.matches("web :: Data").count(),
            expanded
                .matches(":: __private :: actix_web :: web :: Data")
                .count(),
            "some actix-web path is not routed through the anchor: {expanded}"
        );
    }

    #[test]
    fn the_anchor_can_be_redirected_at_the_struct() {
        let expanded = expand(quote!(#[authkestra(crate = ::authkestra::actix)]));

        assert!(
            expanded.contains(":: authkestra :: actix :: __private :: authkestra_engine"),
            "the `crate = ...` override was ignored: {expanded}"
        );
        assert!(
            !expanded.contains(":: authkestra_actix ::"),
            "the default anchor leaked through despite the override: {expanded}"
        );
    }
}
