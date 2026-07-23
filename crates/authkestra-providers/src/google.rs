crate::define_oauth_provider! {
    GoogleProvider,
    "google",
    "Google",
    "https://accounts.google.com/o/oauth2/v2/auth",
    "https://oauth2.googleapis.com/token",
    "https://www.googleapis.com/oauth2/v3/userinfo",
    vec!["openid", "email", "profile"],
    GoogleUserResponse {
        sub: String,
        email: Option<String>,
        name: Option<String>,
        picture: Option<String>,
        email_verified: Option<bool>,
        locale: Option<String>,
    },
    |user| {
        let mut attributes = std::collections::HashMap::new();
        if let Some(picture) = user.picture {
            attributes.insert("picture".to_string(), picture);
        }
        if let Some(verified) = user.email_verified {
            attributes.insert("email_verified".to_string(), verified.to_string());
        }
        if let Some(locale) = user.locale {
            attributes.insert("locale".to_string(), locale);
        }

        authkestra_engine::state::Identity {
            provider_id: "google".to_string(),
            external_id: user.sub,
            email: user.email,
            username: user.name,
            attributes,
        }
    }
}
