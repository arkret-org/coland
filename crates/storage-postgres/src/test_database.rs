//! Leased PostgreSQL databases for tests.
//!
//! Coland persists through one adapter. A test that needs storage leases a real
//! database instead of reaching for a second, in-memory implementation, so the
//! suite exercises exactly what production runs.
//!
//! A lease is exclusive for the life of its guard. The slot is claimed with a
//! session-level advisory lock held on a dedicated connection, so a crashed or
//! killed test releases it when its session ends, and every table that carries
//! rows is emptied before the leasing test observes the database. Slots are
//! reused, which makes a run cost one migration per slot instead of one per
//! test: creating a fresh database or schema measures at 1.4-1.9 s here, while
//! emptying the handful of tables a test dirtied measures at 9 ms to probe plus
//! a few milliseconds to delete.
//!
//! There is no in-memory fallback and no skip. Without a reachable database
//! [`TestDatabase::lease`] panics, which fails the test rather than emptying it.
//!
//! # Schema freshness
//!
//! Slot names carry [`schema_fingerprint`], eight hex characters of
//! `sha256(up.sql)`. This repository rewrites its single migration in place
//! (`AGENTS.md`: "需要修改数据库结构，直接修改现有 sql 文件"), and Diesel only
//! applies migrations it has not seen -- so a slot created under an older
//! revision keeps the schema it was born with while reporting the migration as
//! applied. Every "relation does not exist" run of this suite has been that,
//! never a regression.
//!
//! Editing the migration therefore renames the whole slot family and the next
//! run creates it fresh. Leaving it alone reuses the slots, which is what keeps
//! a run at one migration per slot instead of one per test. A timestamp suffix
//! would also be correct, but it would never reuse -- every run would pay the
//! full 1.4-1.9 s per slot and the server's database list would grow without
//! bound.
//!
//! `db.rs`'s `SCHEMA_CONTRACT_VERSION` fence does not cover this: it is a
//! hand-written constant that is also spelled in a `CHECK` constraint inside
//! `up.sql`, so it only moves when someone renames it -- which an in-place edit
//! never does. It still catches a database from before the migration squash;
//! the fingerprint is what catches an edit.
//!
//! Slots from a superseded fingerprint linger until dropped. Reclaim them with
//! `scripts/drop-stale-test-databases.sh`, which never touches a database that
//! has an open connection.
//!
//! # Runtime ownership
//!
//! The advisory lock lives in a PostgreSQL session, and that session dies with
//! the tokio runtime that drives its connection. Test runtimes are short-lived,
//! so the lock connection is established on a process-wide runtime owned by
//! this module instead. [`TestDatabase::lease_blocking`] drives the acquisition
//! on that runtime from a helper thread, which lets the fixture constructors
//! stay synchronous and infallible for their callers.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Mutex, OnceLock};

use diesel::sql_types::Text;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

use crate::db::{Db, PgPool};

/// Highest slot index the lease pool will hand out.
///
/// Slots are created on demand, so a run only pays for as many databases as it
/// actually holds at once. The ceiling exists to turn "every slot is taken"
/// into a diagnosable panic instead of an unbounded database count.
///
/// # Sizing
///
/// Demand is `test threads * live AppStates per test`, not the thread count:
/// a fixture that builds a second state to model a restart holds two leases at
/// once, and the deep-stack runners give each test its own thread. A 12-thread
/// run of the current suite peaks near 50 slots. Size
/// `COLAND_TEST_DATABASE_SLOTS` against that product with headroom.
///
/// Exhaustion panics rather than waiting. One `cargo test` process is the only
/// shape in use, and for it the ceiling is reachable only by mis-sizing. Change
/// this to a blocking retry only if several test processes must ever share one
/// server -- two runs of the same suite in parallel, say, or a runner that
/// starts test binaries concurrently.
const DEFAULT_MAX_SLOTS: u32 = 64;

/// Advisory-lock namespace. Paired with the slot index it forms the two-integer
/// key `pg_try_advisory_lock` takes, which keeps these locks disjoint from any
/// the adapters themselves take.
const LOCK_NAMESPACE: i32 = 0x5013_4E44_u32 as i32;

/// Slot indices are lock keys in their own right, so database creation takes a
/// key above the slot ceiling it can never collide with.
const CREATE_LOCK_KEY: i32 = -1;

/// Tables the reset must never empty: they carry the migration ledger and the
/// schema-contract fence, not test rows.
const PRESERVED_TABLES: &[&str] = &["__diesel_schema_migrations", "coland_schema_contract"];

/// An exclusive lease on a migrated, empty PostgreSQL database.
///
/// Dropping the guard closes the session that holds the advisory lock, which
/// returns the slot to the pool. Fixtures keep the guard alive for exactly as
/// long as the `AppState` built from it.
pub struct TestDatabase {
    slot: u32,
    url: String,
    pool: PgPool,
    /// Holding this connection holds the advisory lock. It is never used for
    /// anything else, and closing it is what releases the slot.
    lock_session: Option<AsyncPgConnection>,
}

impl std::fmt::Debug for TestDatabase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TestDatabase")
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        // The connection's driver task lives on the lease runtime, so the close
        // has somewhere to run even though the test runtime is already gone.
        if let Some(session) = self.lock_session.take() {
            lease_runtime().spawn(async move { drop(session) });
        }
    }
}

impl TestDatabase {
    /// Lease a database, or panic explaining why no database could be leased.
    ///
    /// # Panics
    ///
    /// Panics when no database URL is configured, when the server is
    /// unreachable, or when every slot is already leased.
    pub async fn lease() -> Self {
        let admin_url = configured_url();
        let slot_prefix = slot_prefix(&admin_url);
        let max_slots = configured_max_slots();

        for slot in 0..max_slots {
            let slot_database = format!("{slot_prefix}{slot:02}");
            let slot_url = replace_database(&admin_url, &slot_database);
            let Some(lock_session) = try_claim(&slot_url, &slot_database, &admin_url, slot).await
            else {
                continue;
            };
            ensure_migrated(&slot_url, &slot_database).await;
            // Reset over the session that already holds the lock: a second
            // connection per lease costs more than the deletes it would run.
            let mut lock_session = lock_session;
            reset(&mut lock_session).await;
            return Self {
                slot,
                pool: build_pool(&slot_url),
                url: slot_url,
                lock_session: Some(lock_session),
            };
        }

        panic!(
            "every one of the {max_slots} test database slots named {slot_prefix}NN is leased; \
             raise COLAND_TEST_DATABASE_SLOTS above the test thread count"
        );
    }

    /// [`TestDatabase::lease`] for a synchronous caller.
    ///
    /// The acquisition runs on this module's runtime from a helper thread, so
    /// it is safe to call from inside a `#[tokio::test]` of any flavour: the
    /// helper thread carries no runtime context of its own, and the resulting
    /// lock connection outlives the caller's runtime.
    ///
    /// # Panics
    ///
    /// Panics for the same reasons as [`TestDatabase::lease`].
    #[must_use]
    pub fn lease_blocking() -> Self {
        let handle = lease_runtime().clone();
        std::thread::spawn(move || handle.block_on(Self::lease()))
            .join()
            .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
    }

    /// The `Db` handle a runtime `AppState` is built from.
    #[must_use]
    pub fn db(&self) -> Db {
        Db {
            pool: Some(self.pool.clone()),
        }
    }

    #[must_use]
    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub fn slot(&self) -> u32 {
        self.slot
    }

    /// Bind the leased database's device inventory to `station_id`: the
    /// effect a production Station gets from persisting its serving service
    /// identity before any device row is written.
    ///
    /// # Panics
    ///
    /// Panics if the binding cannot be written.
    pub fn bind_device_inventory_station(&self, station_id: &str) {
        let pool = self.pool.clone();
        let station_id = station_id.to_owned();
        block_on_lease_runtime(async move {
            let mut conn = crate::pg_conn(&pool)
                .await
                .expect("leased database connection");
            diesel::sql_query(
                "INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)",
            )
            .bind::<Text, _>(station_id)
            .execute(&mut *conn)
            .await
            .expect("bind the fixture device inventory Station");
        });
    }
}

/// Run one setup future to completion from a synchronous fixture.
///
/// Fixtures that build an `AppState` are synchronous and infallible for their
/// callers, but seeding a real database is asynchronous. The work runs on this
/// module's runtime from a helper thread, so it is safe to call from inside a
/// `#[tokio::test]` of any flavour.
///
/// # Panics
///
/// Propagates any panic raised by `future`.
pub fn block_on_lease_runtime<F>(future: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let handle = lease_runtime().clone();
    std::thread::spawn(move || handle.block_on(future))
        .join()
        .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

/// Empty every table that carries rows.
///
/// Deletes run children-before-parents so the `ON DELETE RESTRICT` foreign keys
/// in the schema stay satisfied. A dirty set the ordering cannot linearise -- a
/// foreign-key cycle -- falls back to `TRUNCATE ... CASCADE`, which resolves
/// order itself at roughly ten times the cost.
async fn reset(connection: &mut AsyncPgConnection) {
    // The lease is exclusive. A crashed native HTTP test can leave its named
    // injectors behind; remove only these test objects before reusing the slot.
    // Production authentication and immutable-ledger triggers stay installed.
    execute(
        connection,
        "DO $native_faults$ BEGIN
        DROP TRIGGER IF EXISTS fail_native_membership ON public.member_state_current_results;
        DROP FUNCTION IF EXISTS public.fail_native_membership();
        DROP TRIGGER IF EXISTS fail_native_profile ON public.actor_profile_current_results;
        DROP FUNCTION IF EXISTS public.fail_native_profile();
        DROP TRIGGER IF EXISTS fail_native_profile_source ON public.agent_producer_signer_keys;
        DROP FUNCTION IF EXISTS public.fail_native_profile_source();
        DROP TRIGGER IF EXISTS fail_native_message ON public.message_revision_current_results;
        DROP FUNCTION IF EXISTS public.fail_native_message();
        DROP TRIGGER IF EXISTS fail_native_circle ON public.circle_member_state_current_results;
        DROP FUNCTION IF EXISTS public.fail_native_circle();
        DROP TRIGGER IF EXISTS fail_native_keypackage_insert ON public.mls_key_packages;
        DROP FUNCTION IF EXISTS public.fail_native_keypackage_insert();
        DROP TRIGGER IF EXISTS fail_native_keypackage_claim ON public.peer_keypackage_claims;
        DROP FUNCTION IF EXISTS public.fail_native_keypackage_claim();
        DROP TRIGGER IF EXISTS fail_native_keypackage_revoke ON public.mls_key_packages;
        DROP FUNCTION IF EXISTS public.fail_native_keypackage_revoke();
        DROP TRIGGER IF EXISTS reject_departing_current ON public.member_state_current_results;
        DROP FUNCTION IF EXISTS public.reject_departing_current();
        DROP TRIGGER IF EXISTS reject_terminal_intent ON public.federation_outbox;
        DROP FUNCTION IF EXISTS public.reject_terminal_intent();
        DROP TRIGGER IF EXISTS reject_terminal_fence ON public.realm_bootstrap_current_results;
        DROP FUNCTION IF EXISTS public.reject_terminal_fence();
        DROP TRIGGER IF EXISTS fail_receipt_response ON public.idempotency_keys;
        DROP FUNCTION IF EXISTS public.fail_receipt_response();
        END $native_faults$",
    )
    .await;
    let plan = reset_plan(connection).await;
    let dirty = non_empty_tables(connection, &plan.probe).await;
    if dirty.is_empty() {
        restore_sync_singletons(connection).await;
        return;
    }
    // A dirty table whose triggers reject `DELETE` forces the whole reset onto
    // `TRUNCATE`, which is the only statement that can empty it.
    let ordered = if dirty
        .iter()
        .any(|table| plan.delete_rejecting.contains(table))
    {
        None
    } else {
        plan.ordered_subset(&dirty)
    };
    match ordered {
        Some(ordered) => {
            // One `DO` block rather than one statement per table: the extended
            // query protocol diesel uses refuses a multi-statement string, and
            // a round trip per table would cost more than the deletes.
            let statements = ordered
                .iter()
                .map(|table| format!("DELETE FROM public.{};", quote_ident(table)))
                .collect::<Vec<_>>()
                .join(" ");
            execute(
                connection,
                &format!("DO $reset$ BEGIN {statements} END $reset$"),
            )
            .await;
        }
        None => {
            let list = dirty
                .iter()
                .map(|table| format!("public.{}", quote_ident(table)))
                .collect::<Vec<_>>()
                .join(", ");
            execute(
                connection,
                &format!("TRUNCATE {list} RESTART IDENTITY CASCADE"),
            )
            .await;
        }
    }
    restore_sync_singletons(connection).await;
}

async fn restore_sync_singletons(connection: &mut AsyncPgConnection) {
    // Reset mutable counters rather than preserving a previous test's cuts.
    // These empty-state roots are inserted by the production initial migration.
    execute(connection, "DO $sync_roots$ BEGIN INSERT INTO account_summary_clock(singleton,revision) VALUES(TRUE,0) ON CONFLICT DO NOTHING;
        INSERT INTO account_global_clock(singleton,revision) VALUES(TRUE,0) ON CONFLICT DO NOTHING;
        INSERT INTO account_sync_retention(singleton,summary_floor,global_floor) VALUES(TRUE,0,0) ON CONFLICT DO NOTHING; END $sync_roots$").await;
}

/// The runtime that owns every lock connection for the life of the process.
///
/// Every concurrent `lease_blocking` / `block_on_lease_runtime` caller drives
/// its future through this one runtime, and the futures they drive spawn work
/// of their own (the connection pool's background tasks, the timer and IO
/// drivers). Sizing it at one worker therefore deadlocks under the test
/// harness's own parallelism: `crates/server/tests/extensions_smoke.rs` stopped
/// dead with four tests in flight, zero process CPU, and every one of its
/// Postgres connections `idle`, while `--test-threads=1` ran the same nine
/// cases green in 16 seconds. Track the harness's thread count instead, with a
/// floor so a single-core machine still has room for a spawned task to run
/// while its parent is parked.
fn lease_runtime() -> &'static tokio::runtime::Handle {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            let workers = std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(4)
                .clamp(4, 16);
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .enable_all()
                .thread_name("coland-test-database-lease")
                .build()
                .expect("building the test database lease runtime")
        })
        .handle()
}

/// The database URL every test storage lease is derived from.
///
/// `COLAND_TEST_DATABASE_URL` wins so a developer can point the suite at a
/// throwaway server while `DATABASE_URL` still names the one their tools use.
fn configured_url() -> String {
    for key in ["COLAND_TEST_DATABASE_URL", "DATABASE_URL"] {
        if let Ok(value) = std::env::var(key)
            && !value.trim().is_empty()
        {
            return value;
        }
    }
    panic!(
        "no test database is configured: set COLAND_TEST_DATABASE_URL or DATABASE_URL to a \
         PostgreSQL instance. Coland has one storage implementation, so a test without a \
         database proves nothing and fails here instead of silently passing."
    );
}

/// Slot ceiling, raised for a run with more test threads than the default.
fn configured_max_slots() -> u32 {
    std::env::var("COLAND_TEST_DATABASE_SLOTS")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|slots| *slots > 0)
        .unwrap_or(DEFAULT_MAX_SLOTS)
}

/// A migrated pool on the *base* database, for the storage-contract tests.
///
/// These differ from [`TestDatabase`]: they assert the PostgreSQL adapters
/// honour the storage contracts, share one database, and each claims fresh
/// identifiers instead of leasing a slot. Four copies of this function used to
/// live in `store_contracts.rs`, `durable_plane_restart.rs`, `account_status.rs`
/// and the former threshold-signature store tests, and all four read `DATABASE_URL` alone -- so
/// running the suite the way this module documents (`COLAND_TEST_DATABASE_URL`, which
/// [`configured_url`] prefers) produced 48 hard failures whose message told you
/// to set the other variable. One resolver, both variables, one message.
///
/// # Panics
///
/// Panics for the same reasons as [`TestDatabase::lease`] when no database is
/// configured, and when the configured database cannot be migrated.
pub async fn contract_pool() -> crate::db::PgPool {
    let admin_url = configured_url();
    let database = contract_database(&admin_url);
    let url = replace_database(&admin_url, &database);
    if AsyncPgConnection::establish(&url).await.is_err() {
        ensure_database(&admin_url, &database).await;
    }
    Db::connect(Some(&url), crate::db::PoolTuning::default())
        .await
        .unwrap_or_else(|error| {
            panic!("migrating the contract test database {url} failed: {error}")
        })
        .pool
        .expect("Db::connect with a URL always yields a pool")
}

/// The database [`contract_pool`] shares, named for the migration it was built
/// from.
///
/// It carries [`schema_fingerprint`] for the same reason the slots do, and the
/// omission was real: the first version of this module fingerprinted only the
/// slots, so the contract tests kept sharing a database built from an older
/// `up.sql`. The next migration edit surfaced it as
/// `column "requester_actor_id" does not exist` in a contract test -- exactly
/// the failure shape the fingerprint exists to remove, one layer down.
fn contract_database(url: &str) -> String {
    let base = database_name(url);
    let truncated = base.chars().take(38).collect::<String>();
    format!("{truncated}_s{}_contract", schema_fingerprint())
}

/// The migration this repository rewrites in place, embedded so its bytes can
/// be fingerprinted.
const INITIAL_MIGRATION_SQL: &str = include_str!("../migrations/00000000000000_initial/up.sql");

/// Eight hex characters of `sha256(up.sql)` -- see the module docs.
fn schema_fingerprint() -> &'static str {
    static FINGERPRINT: OnceLock<String> = OnceLock::new();
    FINGERPRINT.get_or_init(|| fingerprint_of(INITIAL_MIGRATION_SQL))
}

/// The fingerprint of one migration body. Split out so the property that
/// matters -- different SQL, different name -- is testable without editing the
/// real migration.
fn fingerprint_of(sql: &str) -> String {
    arkret_canonical::sha256_hex(sql.as_bytes())
        .chars()
        .take(8)
        .collect()
}

/// The prefix leased slots take, derived from the configured database so two
/// checkouts pointed at different databases on one server never share slots,
/// and from the migration body so a slot never outlives the schema it was
/// created under.
///
/// The base name is truncated to 40 characters: with `_s` + 8 + `_slot` + two
/// digits the longest slot name is 57, inside PostgreSQL's 63-byte identifier
/// ceiling.
fn slot_prefix(url: &str) -> String {
    let base = database_name(url);
    let truncated = base.chars().take(40).collect::<String>();
    format!("{truncated}_s{}_slot", schema_fingerprint())
}

fn database_name(url: &str) -> String {
    let after_authority = url
        .split_once("://")
        .map_or(url, |(_, rest)| rest)
        .split_once('/')
        .map_or("", |(_, rest)| rest);
    let name = after_authority
        .split(['?', '#'])
        .next()
        .unwrap_or(after_authority);
    assert!(
        !name.is_empty(),
        "the configured test database URL names no database: {url}"
    );
    name.to_owned()
}

fn replace_database(url: &str, database: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("postgres", url));
    let (authority, path_and_query) = rest.split_once('/').unwrap_or((rest, ""));
    let query = path_and_query
        .split_once('?')
        .map(|(_, query)| format!("?{query}"))
        .unwrap_or_default();
    format!("{scheme}://{authority}/{database}{query}")
}

/// Claim one slot, creating its database the first time it is used.
///
/// The advisory lock is taken on the slot database itself, so the lock and the
/// rows it protects live in the same place and a lost session cannot leave the
/// slot claimed.
async fn try_claim(
    slot_url: &str,
    slot_database: &str,
    admin_url: &str,
    slot: u32,
) -> Option<AsyncPgConnection> {
    let mut session = match AsyncPgConnection::establish(slot_url).await {
        Ok(session) => session,
        Err(_) => {
            ensure_database(admin_url, slot_database).await;
            connect(slot_url).await
        }
    };

    #[derive(diesel::QueryableByName)]
    struct ClaimRow {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        claimed: bool,
    }

    let claimed = diesel::sql_query("SELECT pg_try_advisory_lock($1, $2) AS claimed")
        .bind::<diesel::sql_types::Integer, _>(LOCK_NAMESPACE)
        .bind::<diesel::sql_types::Integer, _>(i32::try_from(slot).unwrap_or(i32::MAX))
        .get_result::<ClaimRow>(&mut session)
        .await
        .unwrap_or_else(|error| panic!("claiming test database slot {slot} failed: {error}"))
        .claimed;

    claimed.then_some(session)
}

/// Create the slot database if it is missing.
///
/// Creation is serialized across every leaser on the server by an advisory
/// lock taken on the maintenance database, and the existence check runs under
/// that lock. Racing on `CREATE DATABASE` and inspecting the failure instead
/// would have to read the server's error text, which is localized.
async fn ensure_database(admin_url: &str, database: &str) {
    #[derive(diesel::QueryableByName)]
    struct ExistsRow {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        present: bool,
    }

    let mut admin = connect(admin_url).await;
    diesel::sql_query("SELECT pg_advisory_lock($1, $2)")
        .bind::<diesel::sql_types::Integer, _>(LOCK_NAMESPACE)
        .bind::<diesel::sql_types::Integer, _>(CREATE_LOCK_KEY)
        .execute(&mut admin)
        .await
        .unwrap_or_else(|error| panic!("locking test database creation failed: {error}"));

    let present = diesel::sql_query(
        "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1) AS present",
    )
    .bind::<Text, _>(database)
    .get_result::<ExistsRow>(&mut admin)
    .await
    .unwrap_or_else(|error| panic!("checking for test database {database} failed: {error}"))
    .present;

    if !present {
        let statement = format!("CREATE DATABASE {}", quote_ident(database));
        diesel::sql_query(statement)
            .execute(&mut admin)
            .await
            .unwrap_or_else(|error| panic!("creating test database {database} failed: {error}"));
    }
    // Dropping the connection ends the session and releases the advisory lock.
}

/// Run migrations once per slot per process.
async fn ensure_migrated(slot_url: &str, slot_database: &str) {
    if migrated_slots()
        .lock()
        .expect("migrated slot registry is poisoned")
        .contains(slot_database)
    {
        return;
    }
    Db::connect(Some(slot_url), crate::db::PoolTuning::default())
        .await
        .unwrap_or_else(|error| panic!("migrating test database {slot_database} failed: {error}"));
    migrated_slots()
        .lock()
        .expect("migrated slot registry is poisoned")
        .insert(slot_database.to_owned());
}

fn migrated_slots() -> &'static Mutex<BTreeSet<String>> {
    static MIGRATED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    MIGRATED.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// Connections a leased pool may open.
///
/// deadpool defaults to `cpu_count * 4`, which a dozen concurrent leases turns
/// into several hundred sessions and exhausts a stock `max_connections = 100`
/// server. One test drives its database sequentially, so a handful is enough:
/// the ceiling is what keeps a parallel run inside the server's budget.
const POOL_MAX_CONNECTIONS: usize = 4;

fn build_pool(url: &str) -> PgPool {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    Pool::builder(manager)
        .max_size(POOL_MAX_CONNECTIONS)
        .build()
        .unwrap_or_else(|error| panic!("building the test connection pool failed: {error}"))
}

async fn connect(url: &str) -> AsyncPgConnection {
    AsyncPgConnection::establish(url)
        .await
        .unwrap_or_else(|error| panic!("connecting to the test database failed: {error}"))
}

async fn execute(connection: &mut AsyncPgConnection, statement: &str) {
    diesel::sql_query(statement)
        .execute(connection)
        .await
        .unwrap_or_else(|error| panic!("test database reset failed: {error}"));
}

/// The table list, the foreign-key order, and the probe query, computed once
/// per process because the schema is fixed by migrations.
struct ResetPlan {
    /// Delete order: children before the parents they reference.
    order: Vec<String>,
    probe: String,
    /// Tables whose row triggers reject `DELETE`. The schema makes some ledgers
    /// immutable that way, and `TRUNCATE` is the only statement that empties
    /// them because it does not fire per-row triggers.
    delete_rejecting: BTreeSet<String>,
}

impl ResetPlan {
    /// Restrict the plan's order to the tables that carry rows, or `None` when
    /// the schema's foreign keys could not be linearised at all.
    fn ordered_subset(&self, dirty: &BTreeSet<String>) -> Option<Vec<String>> {
        if self.order.is_empty() {
            return None;
        }
        Some(
            self.order
                .iter()
                .filter(|table| dirty.contains(*table))
                .cloned()
                .collect(),
        )
    }
}

async fn reset_plan(connection: &mut AsyncPgConnection) -> &'static ResetPlan {
    static PLAN: OnceLock<ResetPlan> = OnceLock::new();
    if let Some(plan) = PLAN.get() {
        return plan;
    }

    #[derive(diesel::QueryableByName)]
    struct TableRow {
        #[diesel(sql_type = Text)]
        table_name: String,
    }

    #[derive(diesel::QueryableByName)]
    struct EdgeRow {
        #[diesel(sql_type = Text)]
        child: String,
        #[diesel(sql_type = Text)]
        parent: String,
    }

    let tables = diesel::sql_query(
        "SELECT c.relname AS table_name \
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind = 'r' \
         ORDER BY c.relname",
    )
    .get_results::<TableRow>(connection)
    .await
    .unwrap_or_else(|error| panic!("reading the test schema table list failed: {error}"))
    .into_iter()
    .map(|row| row.table_name)
    .filter(|table| !PRESERVED_TABLES.contains(&table.as_str()))
    .collect::<Vec<_>>();

    let edges = diesel::sql_query(
        "SELECT child.relname AS child, parent.relname AS parent \
         FROM pg_constraint k \
         JOIN pg_class child ON child.oid = k.conrelid \
         JOIN pg_class parent ON parent.oid = k.confrelid \
         JOIN pg_namespace n ON n.oid = child.relnamespace \
         WHERE k.contype = 'f' AND n.nspname = 'public'",
    )
    .get_results::<EdgeRow>(connection)
    .await
    .unwrap_or_else(|error| panic!("reading the test schema foreign keys failed: {error}"))
    .into_iter()
    .filter(|edge| edge.child != edge.parent)
    .map(|edge| (edge.child, edge.parent))
    .collect::<Vec<_>>();

    let probe = tables
        .iter()
        .map(|table| {
            format!(
                "SELECT '{table}' AS table_name WHERE EXISTS (SELECT 1 FROM public.{})",
                quote_ident(table)
            )
        })
        .collect::<Vec<_>>()
        .join(" UNION ALL ");

    let delete_rejecting = diesel::sql_query(
        "SELECT c.relname AS table_name          FROM pg_trigger t          JOIN pg_class c ON c.oid = t.tgrelid          JOIN pg_namespace n ON n.oid = c.relnamespace          WHERE NOT t.tgisinternal AND n.nspname = 'public' AND (t.tgtype & 8) <> 0",
    )
    .get_results::<TableRow>(connection)
    .await
    .unwrap_or_else(|error| panic!("reading the test schema delete triggers failed: {error}"))
    .into_iter()
    .map(|row| row.table_name)
    .collect::<BTreeSet<_>>();

    let plan = ResetPlan {
        order: delete_order(&tables, &edges),
        probe,
        delete_rejecting,
    };
    PLAN.get_or_init(|| plan)
}

/// Order tables so that every referencing table precedes the table it
/// references. Returns an empty vector when the graph has a cycle, which the
/// caller answers with `TRUNCATE ... CASCADE`.
fn delete_order(tables: &[String], edges: &[(String, String)]) -> Vec<String> {
    let present = tables.iter().cloned().collect::<BTreeSet<_>>();
    let mut parents = BTreeMap::<String, BTreeSet<String>>::new();
    let mut remaining_children = BTreeMap::<String, usize>::new();
    for table in tables {
        parents.entry(table.clone()).or_default();
        remaining_children.entry(table.clone()).or_insert(0);
    }
    for (child, parent) in edges {
        if !present.contains(child) || !present.contains(parent) {
            continue;
        }
        if parents
            .get_mut(child)
            .expect("every table has a parent set")
            .insert(parent.clone())
        {
            *remaining_children
                .get_mut(parent)
                .expect("every table has a child count") += 1;
        }
    }

    // A table no remaining table references can be emptied now; peeling those
    // off in turn yields children before parents.
    let mut ready = remaining_children
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(table, _)| table.clone())
        .collect::<Vec<_>>();
    let mut order = Vec::with_capacity(tables.len());
    while let Some(table) = ready.pop() {
        order.push(table.clone());
        for parent in parents
            .get(&table)
            .expect("every table has a parent set")
            .clone()
        {
            let count = remaining_children
                .get_mut(&parent)
                .expect("every table has a child count");
            *count -= 1;
            if *count == 0 {
                ready.push(parent);
            }
        }
    }

    if order.len() == tables.len() {
        order
    } else {
        Vec::new()
    }
}

async fn non_empty_tables(connection: &mut AsyncPgConnection, probe: &str) -> BTreeSet<String> {
    #[derive(diesel::QueryableByName)]
    struct TableRow {
        #[diesel(sql_type = Text)]
        table_name: String,
    }

    if probe.is_empty() {
        return BTreeSet::new();
    }
    diesel::sql_query(probe)
        .get_results::<TableRow>(connection)
        .await
        .unwrap_or_else(|error| panic!("probing the test database for rows failed: {error}"))
        .into_iter()
        .map(|row| row.table_name)
        .collect()
}

fn quote_ident(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::{database_name, delete_order, fingerprint_of, replace_database, slot_prefix};

    #[test]
    fn slot_urls_keep_the_authority_and_query_of_the_configured_url() {
        assert_eq!(
            replace_database(
                "postgres://u:p@host:5432/base?sslmode=require",
                "base_slot00"
            ),
            "postgres://u:p@host:5432/base_slot00?sslmode=require"
        );
        assert_eq!(database_name("postgres://u:p@host:5432/base"), "base");
        assert_eq!(
            database_name("postgres://u:p@host:5432/base?sslmode=require"),
            "base"
        );
        assert_eq!(
            slot_prefix("postgres://u:p@host:5432/base"),
            format!("base_s{}_slot", super::schema_fingerprint())
        );
    }

    #[test]
    fn a_migration_edit_renames_the_whole_slot_family() {
        // The property the fingerprint exists for: a slot created under one
        // revision of `up.sql` can never be leased by a run carrying another,
        // because it is not even a candidate name.
        assert_ne!(
            fingerprint_of("CREATE TABLE a (id text);"),
            fingerprint_of("CREATE TABLE a (id text, extra text);")
        );
        assert_eq!(
            fingerprint_of("CREATE TABLE a (id text);"),
            fingerprint_of("CREATE TABLE a (id text);")
        );
    }

    #[test]
    fn a_fingerprint_is_eight_lowercase_hex_characters() {
        let fingerprint = super::schema_fingerprint();
        assert_eq!(fingerprint.len(), 8, "{fingerprint}");
        assert!(
            fingerprint
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "{fingerprint}"
        );
    }

    #[test]
    fn the_longest_slot_name_fits_a_postgresql_identifier() {
        let base = "b".repeat(80);
        let name = format!(
            "{}63",
            slot_prefix(&format!("postgres://u:p@host:5432/{base}"))
        );
        assert!(name.len() <= 63, "{} chars: {name}", name.len());
    }

    #[test]
    fn delete_order_puts_referencing_tables_first() {
        let tables = vec!["child".to_owned(), "parent".to_owned()];
        let edges = vec![("child".to_owned(), "parent".to_owned())];
        assert_eq!(delete_order(&tables, &edges), vec!["child", "parent"]);
    }

    /// Two leases held at once must be different databases, and a lease must
    /// never observe rows written under a previous one.
    #[tokio::test]
    async fn concurrent_leases_are_isolated_and_reset_between_holders() {
        use diesel_async::RunQueryDsl;

        #[derive(diesel::QueryableByName)]
        struct CountRow {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total: i64,
        }

        let first = super::TestDatabase::lease().await;
        let second = super::TestDatabase::lease().await;
        assert_ne!(
            first.slot(),
            second.slot(),
            "two live leases must not share a database"
        );

        let mut connection = super::connect(first.url()).await;
        diesel::sql_query(
            "INSERT INTO public.server_settings (key, value, updated_by)              VALUES ('lease.probe', '1'::jsonb, '{}'::jsonb)",
        )
        .execute(&mut connection)
        .await
        .expect("write a row under the first lease");

        let mut other = super::connect(second.url()).await;
        let seen = diesel::sql_query("SELECT count(*) AS total FROM public.server_settings")
            .get_result::<CountRow>(&mut other)
            .await
            .expect("read the second lease")
            .total;
        assert_eq!(
            seen, 0,
            "a concurrent lease must not observe another's rows"
        );

        let slot = first.slot();
        drop(connection);
        drop(first);

        // Reclaiming is racy against other tests in this process, so assert the
        // reset property on whichever slot comes back rather than on the id.
        let reclaimed = super::TestDatabase::lease().await;
        let mut fresh = super::connect(reclaimed.url()).await;
        let total = diesel::sql_query("SELECT count(*) AS total FROM public.server_settings")
            .get_result::<CountRow>(&mut fresh)
            .await
            .expect("read the reclaimed lease")
            .total;
        assert_eq!(
            total, 0,
            "slot {slot} was not emptied before the next holder saw it"
        );
    }

    #[tokio::test]
    async fn reset_clears_abandoned_http_faults_and_preserves_production_triggers() {
        use diesel_async::RunQueryDsl;

        #[derive(diesel::QueryableByName)]
        struct TriggerDefinitions {
            #[diesel(sql_type = diesel::sql_types::Jsonb)]
            value: serde_json::Value,
        }
        let leased = super::TestDatabase::lease().await;
        let mut connection = super::connect(leased.url()).await;
        let production = "SELECT coalesce(jsonb_agg(jsonb_build_object('table',c.relname,'name',t.tgname,'definition',pg_get_triggerdef(t.oid)) ORDER BY c.relname,t.tgname),'[]'::jsonb) AS value FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal";
        let before = diesel::sql_query(production)
            .get_result::<TriggerDefinitions>(&mut connection)
            .await
            .unwrap()
            .value;
        assert!(!before.as_array().unwrap().is_empty());
        super::execute(
            &mut connection,
            "DO $owned_faults$ BEGIN
            CREATE FUNCTION public.reject_departing_current() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
            CREATE TRIGGER reject_departing_current BEFORE UPDATE ON public.member_state_current_results FOR EACH ROW EXECUTE FUNCTION public.reject_departing_current();
            CREATE FUNCTION public.reject_terminal_intent() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
            CREATE TRIGGER reject_terminal_intent BEFORE INSERT ON public.federation_outbox FOR EACH ROW EXECUTE FUNCTION public.reject_terminal_intent();
            CREATE FUNCTION public.reject_terminal_fence() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
            CREATE TRIGGER reject_terminal_fence BEFORE INSERT OR UPDATE ON public.realm_bootstrap_current_results FOR EACH ROW EXECUTE FUNCTION public.reject_terminal_fence();
            CREATE FUNCTION public.fail_receipt_response() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
            CREATE TRIGGER fail_receipt_response BEFORE INSERT ON public.idempotency_keys FOR EACH ROW EXECUTE FUNCTION public.fail_receipt_response();
            END $owned_faults$",
        )
        .await;
        super::reset(&mut connection).await;
        let after = diesel::sql_query(production)
            .get_result::<TriggerDefinitions>(&mut connection)
            .await
            .unwrap()
            .value;
        assert_eq!(after, before, "slot reset changed production triggers");

        #[derive(diesel::QueryableByName)]
        struct FaultFunctions {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total: i64,
        }
        let remaining = diesel::sql_query("SELECT count(*) AS total FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN ('reject_departing_current','reject_terminal_intent','reject_terminal_fence','fail_receipt_response')")
            .get_result::<FaultFunctions>(&mut connection)
            .await
            .unwrap();
        assert_eq!(remaining.total, 0, "abandoned HTTP faults survived reset");
    }

    /// The synchronous entry point must work from inside a test runtime, which
    /// is what lets `AppState` fixtures stay synchronous.
    #[tokio::test]
    async fn lease_blocking_works_inside_a_test_runtime() {
        let leased = super::TestDatabase::lease_blocking();
        assert!(leased.db().pool.is_some());
    }

    #[test]
    fn a_foreign_key_cycle_reports_no_order() {
        let tables = vec!["a".to_owned(), "b".to_owned()];
        let edges = vec![
            ("a".to_owned(), "b".to_owned()),
            ("b".to_owned(), "a".to_owned()),
        ];
        assert!(delete_order(&tables, &edges).is_empty());
    }
}
