use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use deadpool::Runtime;
use diesel_async::async_connection_wrapper::AsyncConnectionWrapper;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::{AsyncPgConnection, SimpleAsyncConnection};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
const SCHEMA_CONTRACT_VERSION: &str = "authority-commit-v1";

pub type PgPool = Pool<AsyncPgConnection>;

#[derive(Clone)]
pub struct Db {
    pub pool: Option<PgPool>,
}

/// Connection-pool sizing, supplied by the caller.
///
/// Operators match these to their Postgres `max_connections` and to how long a
/// request may block before failing. `None` keeps the default pool size and
/// applies a five-second checkout budget. The
/// values used to be read from `COLAND_DB_POOL_*` inside this crate, which
/// meant a storage library knew the name of the application hosting it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PoolTuning {
    pub max_size: Option<usize>,
    pub acquire_timeout_seconds: Option<u64>,
}

static MIGRATIONS_APPLIED: OnceLock<AtomicBool> = OnceLock::new();

fn migrations_applied_flag() -> &'static AtomicBool {
    MIGRATIONS_APPLIED.get_or_init(|| AtomicBool::new(true))
}

impl Db {
    /// Connect using an already-resolved URL. `None`, or a blank string, leaves
    /// the pool absent for test-only composition; the Coland executable rejects
    /// that shape before building runtime persistence.
    ///
    /// This is the only constructor. The `from_env` variant it replaced read
    /// `DATABASE_URL` itself, which put an environment read inside a storage
    /// library and gave the URL a second parser; the caller resolves it.
    pub async fn connect(database_url: Option<&str>, tuning: PoolTuning) -> anyhow::Result<Self> {
        let pool = match database_url {
            Some(url) if !url.trim().is_empty() => {
                migrations_applied_flag().store(false, Ordering::Release);
                let pool = build_pool(url, tuning)?;
                run_migrations(url).await?;
                migrations_applied_flag().store(true, Ordering::Release);
                Some(pool)
            }
            _ => None,
        };
        Ok(Self { pool })
    }

    pub fn mode(&self) -> &'static str {
        if self.pool.is_some() {
            "postgres"
        } else {
            "memory"
        }
    }

    pub fn migrations_applied(&self) -> bool {
        if self.pool.is_none() {
            return true;
        }
        migrations_applied_flag().load(Ordering::Acquire)
    }

    pub fn pool_in_use(&self) -> u32 {
        self.pool
            .as_ref()
            .map(|pool| {
                let status = pool.status();
                let in_use = status.size.saturating_sub(status.available);
                u32::try_from(in_use).unwrap_or(u32::MAX)
            })
            .unwrap_or(0)
    }
}

async fn run_migrations(database_url: &str) -> anyhow::Result<()> {
    let url = database_url.to_owned();
    tokio::task::spawn_blocking(move || {
        use diesel::{Connection, RunQueryDsl};
        let mut wrapper =
            AsyncConnectionWrapper::<AsyncPgConnection>::establish(&url).map_err(|error| {
                anyhow::anyhow!("failed to establish migration connection: {error}")
            })?;
        diesel::sql_query(
            "SELECT pg_advisory_lock(hashtextextended('coland-schema-migrations', 0))",
        )
        .execute(&mut wrapper)
        .map_err(|error| anyhow::anyhow!("failed to lock database migrations: {error}"))?;
        wrapper
            .run_pending_migrations(MIGRATIONS)
            .map_err(|error| anyhow::anyhow!("failed to run database migrations: {error}"))?;
        verify_schema_contract(&mut wrapper)?;
        Ok(())
    })
    .await
    .map_err(|error| anyhow::anyhow!("migration task panicked: {error}"))?
}

#[derive(diesel::QueryableByName)]
struct SchemaContractRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    contract_version: String,
}

fn verify_schema_contract(
    connection: &mut AsyncConnectionWrapper<AsyncPgConnection>,
) -> anyhow::Result<()> {
    use diesel::RunQueryDsl;

    let row = diesel::sql_query(
        "SELECT contract_version FROM public.coland_schema_contract WHERE singleton = TRUE",
    )
    .get_result::<SchemaContractRow>(connection)
    .map_err(|error| {
        anyhow::anyhow!(
            "database schema contract fence failed; initialize a clean database for {SCHEMA_CONTRACT_VERSION}: {error}"
        )
    })?;
    anyhow::ensure!(
        row.contract_version == SCHEMA_CONTRACT_VERSION,
        "database schema contract {:?} is incompatible; expected {SCHEMA_CONTRACT_VERSION}; initialize a clean database",
        row.contract_version
    );
    Ok(())
}

pub(crate) fn build_pool(url: &str, tuning: PoolTuning) -> anyhow::Result<PgPool> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let budget = Duration::from_secs(
        tuning
            .acquire_timeout_seconds
            .filter(|n| *n > 0)
            .unwrap_or(5),
    );
    let mut builder = Pool::builder(manager)
                    .wait_timeout(Some(budget))
                    .create_timeout(Some(budget))
                    .recycle_timeout(Some(budget))
                    .runtime(Runtime::Tokio1)
                    .post_create(diesel_async::pooled_connection::deadpool::Hook::async_fn(|conn: &mut AsyncPgConnection, _| Box::pin(async move {
                        tokio::time::timeout(Duration::from_secs(5), conn.batch_execute("SET statement_timeout = '30s'; SET lock_timeout = '5s'; SET idle_in_transaction_session_timeout = '60s';"))
                            .await.map_err(|_| diesel_async::pooled_connection::deadpool::HookError::Message("database session setup timed out".into()))?
                            .map_err(|error| diesel_async::pooled_connection::deadpool::HookError::Backend(diesel_async::pooled_connection::PoolError::QueryError(error)))?;
                        Ok(())
                    })));
    if let Some(max) = tuning.max_size.filter(|n| *n > 0) {
        builder = builder.max_size(max);
    }
    builder.build().map_err(Into::into)
}

#[cfg(test)]
mod wait_bound_tests {
    use diesel_async::RunQueryDsl;

    use super::*;

    #[tokio::test]
    async fn checkout_deadline_covers_exhaustion_and_handshake() {
        let url =
            std::env::var("COLAND_TEST_DATABASE_URL").expect("isolated test database required");
        let tuning = PoolTuning {
            max_size: Some(1),
            acquire_timeout_seconds: Some(1),
        };
        let pool = build_pool(&url, tuning).unwrap();
        let mut conn = crate::pg_conn(&pool).await.unwrap();
        #[derive(diesel::QueryableByName)]
        struct Settings {
            #[diesel(sql_type = diesel::sql_types::Bool)]
            bounded: bool,
        }
        let settings: Settings = diesel::sql_query("SELECT current_setting('statement_timeout')::interval = interval '30 seconds' AND current_setting('lock_timeout')::interval = interval '5 seconds' AS bounded").get_result(&mut *conn).await.unwrap();
        assert!(settings.bounded);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), crate::pg_conn(&pool))
                .await
                .unwrap()
                .is_err()
        );
        assert!(!crate::database_ready(Some(&pool)).await);
        drop(conn);
        assert!(crate::database_ready(Some(&pool)).await);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let blackhole = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let pool = build_pool(
            &format!("postgres://postgres@{address}/test?sslmode=disable"),
            tuning,
        )
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), crate::pg_conn(&pool))
                .await
                .unwrap()
                .is_err()
        );
        blackhole.abort();
    }
}
