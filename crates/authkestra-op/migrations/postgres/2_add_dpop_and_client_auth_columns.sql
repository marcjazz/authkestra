-- authkestra#287: unblocks RFC 9449 DPoP refresh-token key continuity and
-- RFC 7523 private_key_jwt for SQL-backed deployments. Safe to run against
-- either a fresh install (migration 1 just created these tables) or an
-- existing deployment upgrading from before this column existed — sqlx's
-- own migration tracking (`_sqlx_migrations`) guarantees this file runs
-- exactly once per database, so no defensive IF NOT EXISTS/introspection
-- is needed here the way it would be if this were still a hand-rolled
-- CREATE-TABLE-IF-NOT-EXISTS-style "migration".
ALTER TABLE authkestra.oauth_refresh_tokens ADD COLUMN jkt VARCHAR(255);

ALTER TABLE authkestra.oauth_clients ADD COLUMN token_endpoint_auth_method JSONB;
ALTER TABLE authkestra.oauth_clients ADD COLUMN jwks JSONB;
