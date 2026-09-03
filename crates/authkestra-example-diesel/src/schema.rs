//! Diesel table definitions. JSON-shaped fields (`Vec<String>`, `Identity`,
//! `DeviceCodeStatus`, ...) are stored as `Text` columns holding a
//! serde_json-encoded string and (de)serialized by hand in `models.rs` —
//! Diesel has no built-in `Json` column type for SQLite, unlike Postgres.

diesel::table! {
    oauth_clients (client_id) {
        client_id -> Text,
        client_secret_hash -> Nullable<Text>,
        require_pkce -> Bool,
        redirect_uris -> Text,
        grant_types -> Text,
        scopes -> Text,
        allowed_audiences -> Text,
        token_endpoint_auth_method -> Nullable<Text>,
        jwks -> Nullable<Text>,
    }
}

diesel::table! {
    oauth_codes (code) {
        code -> Text,
        client_id -> Text,
        redirect_uri -> Text,
        scope -> Text,
        code_challenge -> Nullable<Text>,
        code_challenge_method -> Nullable<Text>,
        nonce -> Nullable<Text>,
        identity -> Text,
        expires_at -> Timestamp,
        used -> Bool,
    }
}

diesel::table! {
    oauth_refresh_tokens (token) {
        token -> Text,
        client_id -> Text,
        identity -> Text,
        scope -> Text,
        expires_at -> Timestamp,
        jkt -> Nullable<Text>,
    }
}

diesel::table! {
    oauth_device_codes (device_code) {
        device_code -> Text,
        user_code -> Text,
        client_id -> Text,
        scope -> Text,
        expires_at -> Timestamp,
        status -> Text,
        last_polled_at -> Nullable<Timestamp>,
    }
}
