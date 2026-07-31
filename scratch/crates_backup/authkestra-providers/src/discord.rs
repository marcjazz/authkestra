crate::define_oauth_provider! {
    DiscordProvider,
    "discord",
    "Discord",
    "https://discord.com/api/oauth2/authorize",
    "https://discord.com/api/oauth2/token",
    "https://discord.com/api/users/@me",
    vec!["identify", "email"],
    DiscordUserResponse {
        id: String,
        username: String,
        discriminator: String,
        email: Option<String>,
    },
    |user| {
        authkestra_engine::state::Identity {
            provider_id: "discord".to_string(),
            external_id: user.id,
            email: user.email,
            username: Some(format!("{}#{}", user.username, user.discriminator)),
            attributes: std::collections::HashMap::new(),
        }
    }
}
