-- Fixture for sqlx_store::sqlite_tests's host-app collision regression
-- test. Stands in for a totally unrelated application table that a host
-- embedding authkestra-op might migrate with its own `sqlx::migrate!`
-- against the same connection pool.
CREATE TABLE app_widgets (id INTEGER PRIMARY KEY);
