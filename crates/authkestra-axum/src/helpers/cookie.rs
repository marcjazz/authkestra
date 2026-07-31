#[cfg(feature = "session")]
use authkestra_engine::auth::SessionConfig;
#[cfg(feature = "session")]
use tower_cookies::cookie::SameSite;
#[cfg(feature = "session")]
use tower_cookies::Cookie;

#[cfg(feature = "session")]
pub fn to_axum_same_site(ss: authkestra_engine::SameSite) -> SameSite {
    match ss {
        authkestra_engine::SameSite::Lax => SameSite::Lax,
        authkestra_engine::SameSite::Strict => SameSite::Strict,
        authkestra_engine::SameSite::None => SameSite::None,
    }
}

#[cfg(feature = "session")]
pub fn create_axum_cookie<'a>(config: &SessionConfig, value: String) -> Cookie<'a> {
    let mut cookie = Cookie::new(config.cookie_name.clone(), value);
    cookie.set_path(config.path.clone());
    cookie.set_secure(config.secure);
    cookie.set_http_only(config.http_only);
    cookie.set_same_site(to_axum_same_site(config.same_site));
    if let Some(max_age) = config.max_age {
        cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::seconds(
            max_age.num_seconds(),
        )));
    }
    cookie
}
