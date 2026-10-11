//! Operator CLI for the durable federation outbox.
//!
//! ```text
//! coland-federation-outbox list [--state pending|pending_route|leased|delivered|cancelled_authority_lost|policy_suppressed|dead_lettered|superseded] [--limit N]
//! coland-federation-outbox list --dead-letters [--limit N]
//! coland-federation-outbox inspect <outbox-id|dead-letter-id>
//! coland-federation-outbox requeue <dead-letter-id> --operator <did> --reason <text>
//! ```
//!
//! `requeue` never resurrects the terminal row: it re-validates the peer, the
//! egress policy and the stored request, then mints a fresh intent under a new
//! `Idempotency-Key` and stamps the operator audit onto the dead letter — all
//! in one transaction. See `routing::federation::outbox_operator`.

use coland::process_config::arg_value;
use coland_http::config::{AppConfig, StartupOverrides};
use coland_http::routing::federation::outbox_operator::{self, DEFAULT_LIST_LIMIT};
use coland_storage::FederationOutboxState;
use coland_storage_postgres::Db;

const USAGE: &str = "usage:\n  \
    coland-federation-outbox list [--state <state>] [--limit N]\n  \
    coland-federation-outbox list --dead-letters [--limit N]\n  \
    coland-federation-outbox inspect <outbox-id|dead-letter-id>\n  \
    coland-federation-outbox requeue <dead-letter-id> --operator <did> --reason <text>";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();
    let args: Vec<String> = raw_args.iter().skip(1).cloned().collect();
    let Some(command) = args.first().cloned() else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };
    let values = coland::process_config::load(&raw_args)?;
    let config = AppConfig::from_values(&values, StartupOverrides::default())?;
    let db = Db::connect(
        config.database_url.as_deref(),
        coland_storage_postgres::PoolTuning {
            max_size: config.db_pool_max_size,
            acquire_timeout_seconds: config.db_pool_acquire_timeout_seconds,
        },
    )
    .await?;
    if db.pool.is_none() {
        eprintln!(
            "coland-federation-outbox: DATABASE_URL is required; runtime persistence is \
             PostgreSQL-only"
        );
        std::process::exit(2);
    }
    let bootstrap = coland::bootstrap::resolve_and_build_persistence(&config, &db).await?;
    let resolution_commitment = bootstrap
        .resolution_commitment
        .clone()
        .ok_or_else(|| anyhow::anyhow!("serving service identity has no resolution commitment"))?;
    let state = coland::runtime::build_app_state(
        config,
        db,
        bootstrap.persistence,
        bootstrap.state,
        resolution_commitment,
        bootstrap.signing_seed,
    )?;

    let limit = arg_value(&args, "--limit")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_LIST_LIMIT);

    let report = match command.as_str() {
        "list" if args.iter().any(|arg| arg == "--dead-letters") => {
            let rows = outbox_operator::list_dead_letters(&state, limit)
                .await
                .map_err(anyhow::Error::msg)?;
            serde_json::json!({ "dead_letters": rows })
        }
        "list" => {
            let lifecycle = match arg_value(&args, "--state") {
                Some(value) => parse_state(&value)?,
                None => FederationOutboxState::Pending,
            };
            let rows = outbox_operator::list_by_state(&state, lifecycle, limit)
                .await
                .map_err(anyhow::Error::msg)?;
            serde_json::json!({ "state": lifecycle.as_str(), "rows": rows })
        }
        "inspect" => {
            let id = positional(&args).ok_or_else(|| anyhow::anyhow!("{USAGE}"))?;
            let detail = outbox_operator::inspect(&state, &id)
                .await
                .map_err(anyhow::Error::msg)?;
            serde_json::to_value(detail)?
        }
        "requeue" => {
            let id = positional(&args).ok_or_else(|| anyhow::anyhow!("{USAGE}"))?;
            let operator = arg_value(&args, "--operator")
                .ok_or_else(|| anyhow::anyhow!("requeue requires --operator <did>"))?;
            let reason = arg_value(&args, "--reason")
                .ok_or_else(|| anyhow::anyhow!("requeue requires --reason <text>"))?;
            let outcome = outbox_operator::requeue_dead_letter(&state, &id, &operator, &reason)
                .await
                .map_err(anyhow::Error::msg)?;
            serde_json::to_value(outcome)?
        }
        other => {
            eprintln!("coland-federation-outbox: unknown command {other}\n{USAGE}");
            std::process::exit(2);
        }
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn parse_state(value: &str) -> anyhow::Result<FederationOutboxState> {
    FederationOutboxState::parse(value.trim()).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown --state {value}; expected pending, pending_route, leased, delivered, \
             cancelled_authority_lost, policy_suppressed, dead_lettered or superseded"
        )
    })
}

/// The first argument after the subcommand that is not a flag or a flag value.
fn positional(args: &[String]) -> Option<String> {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg.starts_with("--") {
            if !arg.contains('=') {
                iter.next();
            }
            continue;
        }
        return Some(arg.clone());
    }
    None
}
