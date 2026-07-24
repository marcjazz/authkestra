use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Type};

pub(crate) fn derive_authkestra_state_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

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
            return syn::Error::new_spanned(&input, "State can only be derived for structs")
                .to_compile_error()
                .into();
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
                } else if ident_str == "Engine" {
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

        config_statements.push(quote! {
            cfg.app_data(actix_web::web::Data::new(self.#field_name.clone()));
        });

        let s_param_str = quote!(#s_param).to_string();
        if !s_param_str.contains("Missing") {
            config_statements.push(quote! {
                cfg.app_data(actix_web::web::Data::new(
                    authkestra_engine::SessionStoreState::get_store(&self.#field_name.session_store)
                ));
            });
        }

        config_statements.push(quote! {
            cfg.app_data(actix_web::web::Data::new(
                self.#field_name.session_config.clone()
            ));
        });

        let t_param_str = quote!(#t_param).to_string();
        if !t_param_str.contains("Missing") {
            config_statements.push(quote! {
                cfg.app_data(actix_web::web::Data::new(
                    authkestra_engine::TokenManagerState::get_manager(&self.#field_name.token_manager)
                ));
            });
        }
    }

    for field in store_fields {
        let field_name = field.ident.as_ref().unwrap();
        config_statements.push(quote! {
            cfg.app_data(actix_web::web::Data::new(self.#field_name.clone()));
        });
    }

    if engine_field.is_none() && config_statements.is_empty() {
        return syn::Error::new_spanned(
            &input,
            "No field marked with #[authkestra(engine)] found. Add #[authkestra(engine)] to your Engine field."
        )
        .to_compile_error()
        .into();
    }

    let expanded = quote! {
        impl #impl_generics #struct_name #ty_generics #where_clause {
            pub fn configure_authkestra(&self, cfg: &mut actix_web::web::ServiceConfig) {
                #(#config_statements)*
            }
        }
    };

    TokenStream::from(expanded)
}
