-- Initial schema, matching the CREATE TABLE IF NOT EXISTS statements this
-- crate used to run directly (pre-authkestra#287). Kept byte-for-byte
-- identical on purpose: a fresh install and a deployment upgrading from the
-- old raw-execute `migrate()` end up at the exact same schema either way,
-- and the historical migration record stays honest about what actually
-- shipped when.
CREATE TABLE IF NOT EXISTS authkestra_oauth_clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_secret_hash VARCHAR(255),
    require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
    redirect_uris JSON NOT NULL,
    grant_types JSON NOT NULL,
    scopes JSON NOT NULL,
    allowed_audiences JSON NOT NULL
);

CREATE TABLE IF NOT EXISTS authkestra_oauth_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    nonce VARCHAR(255),
    identity JSON NOT NULL,
    expires_at DATETIME NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (client_id) REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS authkestra_oauth_refresh_tokens (
    token VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    identity JSON NOT NULL,
    scope TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME,
    FOREIGN KEY (client_id) REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS authkestra_oauth_device_codes (
    device_code VARCHAR(255) PRIMARY KEY,
    user_code VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    scope TEXT NOT NULL,
    status JSON NOT NULL,
    expires_at DATETIME NOT NULL,
    last_polled_at DATETIME,
    FOREIGN KEY (client_id) REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE
);
