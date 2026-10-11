//! The database the storage-contract integration tests share.
//!
//! These tests link the library *without* `cfg(test)`, and a crate cannot
//! enable its own `test-support` feature for its own `tests/` targets, so
//! `coland_storage_postgres::test_database` is not visible here. This module is
//! the one place the rules it would otherwise provide are spelled for the
//! integration tests -- shared between them rather than copied into each.
//!
//! Keep it in step with `src/test_database.rs`.

/// The migration this repository rewrites in place.
const INITIAL_MIGRATION_SQL: &str = include_str!("../../migrations/00000000000000_initial/up.sql");

/// `COLAND_TEST_DATABASE_URL` wins, `DATABASE_URL` is the fallback -- the same
/// order `test_database::configured_url` uses. Reading only `DATABASE_URL`, as
/// these tests did until 2026-09-05, made the documented way of running the
/// suite fail every storage contract with a message naming the other variable.
fn configured_url() -> String {
    for key in ["COLAND_TEST_DATABASE_URL", "DATABASE_URL"] {
        if let Ok(value) = std::env::var(key)
            && !value.trim().is_empty()
        {
            return value;
        }
    }
    panic!(
        "{}",
        concat!(
            "no test database is configured: set COLAND_TEST_DATABASE_URL or DATABASE_URL ",
            "to a PostgreSQL instance. These contract tests are the only proof the Postgres ",
            "adapters honour the storage contracts, so they fail rather than skip."
        )
    );
}

/// Eight hex characters of `sha256(up.sql)`.
///
/// This repository rewrites its single migration in place and Diesel only
/// applies migrations it has not seen, so a database built from an older
/// revision keeps that schema while reporting the migration as applied. The
/// failure reads `column "..." does not exist` and looks like a regression.
/// Naming the database for the migration removes the class: an edit renames it
/// and the next run builds it fresh.
fn schema_fingerprint() -> String {
    arkret_canonical::sha256_hex(INITIAL_MIGRATION_SQL.as_bytes())
        .chars()
        .take(8)
        .collect()
}

/// The URL these contracts connect to: the configured server, the configured
/// database name, and this migration's fingerprint.
pub fn contract_database_url() -> String {
    let url = configured_url();
    let (scheme, rest) = url.split_once("://").unwrap_or(("postgres", &url));
    let (authority, path_and_query) = rest.split_once('/').unwrap_or((rest, ""));
    let (base, query) = match path_and_query.split_once('?') {
        Some((base, query)) => (base, format!("?{query}")),
        None => (path_and_query, String::new()),
    };
    let truncated = base.chars().take(38).collect::<String>();
    let database = format!("{truncated}_s{}_contract", schema_fingerprint());
    format!("{scheme}://{authority}/{database}{query}")
}

/// Create the contract database when this is the first run on this schema.
/// `Db::connect` then applies the migration to it.
pub async fn ensure_contract_database(url: &str) {
    use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _};

    if AsyncPgConnection::establish(url).await.is_ok() {
        return;
    }
    let (head, database) = url
        .rsplit_once('/')
        .expect("contract database URL has a path");
    let database = database.split('?').next().unwrap_or(database);
    let mut admin = AsyncPgConnection::establish(&format!("{head}/postgres"))
        .await
        .expect("connecting to the maintenance database");
    // `CREATE DATABASE` takes no parameters, and the name is derived here, not
    // taken from input.
    let _ = diesel::sql_query(format!("CREATE DATABASE \"{database}\""))
        .execute(&mut admin)
        .await;
}
