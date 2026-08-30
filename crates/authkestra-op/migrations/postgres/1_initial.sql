-- Initial schema, matching the CREATE TABLE IF NOT EXISTS statements this
-- crate used to run directly (pre-authkestra#287). Kept byte-for-byte
-- identical on purpose: a fresh install and a deployment upgrading from the
-- old raw-execute `migrate()` end up at the exact same schema either way,
-- and the historical migration record stays honest about what actually
-- shipped when.
CREATE SCHEMA IF NOT EXISTS authkestra;

CREATE TABLE IF NOT EXISTS authkestra.oauth_clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_secret_hash VARCHAR(255),
    require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
    redirect_uris JSONB NOT NULL,
    grant_types JSONB NOT NULL,
    scopes JSONB NOT NULL,
    allowed_audiences JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS authkestra.oauth_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL REFERENCES authkestra.oauth_clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    nonce VARCHAR(255),
    identity JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS authkestra.oauth_refresh_tokens (
    token VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL REFERENCES authkestra.oauth_clients(client_id) ON DELETE CASCADE,
    identity JSONB NOT NULL,
    scope TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS authkestra.oauth_device_codes (
    device_code VARCHAR(255) PRIMARY KEY,
    user_code VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL REFERENCES authkestra.oauth_clients(client_id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    status JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_polled_at TIMESTAMPTZ
);
