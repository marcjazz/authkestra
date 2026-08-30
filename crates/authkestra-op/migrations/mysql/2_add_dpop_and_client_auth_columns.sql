-- authkestra#287: unblocks RFC 9449 DPoP refresh-token key continuity and
-- RFC 7523 private_key_jwt for SQL-backed deployments. See the Postgres
-- migration of the same name for the full reasoning on why no defensive
-- IF NOT EXISTS/introspection is needed here.
ALTER TABLE authkestra_oauth_refresh_tokens ADD COLUMN jkt VARCHAR(255);

ALTER TABLE authkestra_oauth_clients ADD COLUMN token_endpoint_auth_method JSON;
ALTER TABLE authkestra_oauth_clients ADD COLUMN jwks JSON;
