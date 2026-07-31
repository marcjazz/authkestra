crate::define_oauth_provider! {
    GithubProvider,
    "github",
    "GitHub",
    "https://github.com/login/oauth/authorize",
    "https://github.com/login/oauth/access_token",
    "https://api.github.com/user",
    vec!["user:email"],
    GithubUserResponse {
        id: u64,
        login: String,
        email: Option<String>,
    },
    |user| {
        authkestra_engine::state::Identity {
            provider_id: "github".to_string(),
            external_id: user.id.to_string(),
            email: user.email,
            username: Some(user.login),
            attributes: std::collections::HashMap::new(),
        }
    }
}
