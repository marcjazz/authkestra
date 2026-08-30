-- Initial schema, matching the CREATE TABLE IF NOT EXISTS statements this
-- crate used to run directly (pre-authkestra#287). Kept byte-for-byte
-- identical on purpose: a fresh install and a deployment upgrading from the
-- old raw-execute `migrate()` end up at the exact same schema either way,
-- and the historical migration record stays honest about what actually
-- shipped when.
CREATE TABLE IF NOT EXISTS authkestra_oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_secret_hash TEXT,
    require_pkce BOOLEAN NOT NULL DEFAULT 1,
    redirect_uris TEXT NOT NULL,
    grant_types TEXT NOT NULL,
    scopes TEXT NOT NULL,
    allowed_audiences TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authkestra_oauth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    code_challenge TEXT,
    code_challenge_method TEXT,
    nonce TEXT,
    identity TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS authkestra_oauth_refresh_tokens (
    token TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE,
    identity TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME
);

CREATE TABLE IF NOT EXISTS authkestra_oauth_device_codes (
    device_code TEXT PRIMARY KEY,
    user_code TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    last_polled_at DATETIME
);
