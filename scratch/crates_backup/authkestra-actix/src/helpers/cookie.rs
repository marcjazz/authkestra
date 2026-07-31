#[cfg(any(feature = "session", feature = "token"))]
use actix_web::cookie::Cookie;
#[cfg(feature = "session")]
pub use authkestra_engine::auth::SessionConfig;

#[cfg(feature = "session")]
pub fn to_actix_same_site(ss: authkestra_engine::SameSite) -> actix_web::cookie::SameSite {
    match ss {
        authkestra_engine::SameSite::Lax => actix_web::cookie::SameSite::Lax,
        authkestra_engine::SameSite::Strict => actix_web::cookie::SameSite::Strict,
        authkestra_engine::SameSite::None => actix_web::cookie::SameSite::None,
    }
}

#[cfg(feature = "session")]
pub fn create_actix_cookie<'a>(config: &SessionConfig, value: String) -> Cookie<'a> {
    let mut builder = Cookie::build(config.cookie_name.clone(), value)
        .path(config.path.clone())
        .secure(config.secure)
        .http_only(config.http_only)
        .same_site(to_actix_same_site(config.same_site));

    if let Some(max_age) = config.max_age {
        builder = builder.max_age(actix_web::cookie::time::Duration::seconds(
            max_age.num_seconds(),
        ));
    }
    builder.finish()
}
