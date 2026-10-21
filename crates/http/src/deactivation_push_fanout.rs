//! Reconcile account deactivation through the formal opaque push-registration handoff.
//!
//! A local tombstone stops delivery immediately. Completion additionally requires
//! the existing verified Gateway revoke receipt; an enqueued request is incomplete.
//! No AccountId or principal DID is sent to a Gateway.

use std::sync::Arc;
use std::time::Duration;

use crate::state::AppState;

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const FANOUT_LIFECYCLE_STATES: [&str; 2] = ["deactivated", "erasure_pending"];

async fn reconcile_account(state: &AppState, did: &str) -> bool {
    let result = async {
        let principal = arkret_wire::DidCoreId::new(did.to_owned())
            .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
        let account = arkret_wire::AccountId::new(principal, state.service_core_id());
        crate::routing::interop::confirm_deactivated_account_push_revocations(state, &account).await
    }
    .await;
    let complete = match result {
        Ok(complete) => complete,
        Err(error) => {
            tracing::warn!(%error, "account push revocation remains incomplete");
            false
        }
    };
    state.set_deactivation_push_partial(did, !complete);
    complete
}

/// Preserve the lifecycle result while reporting unavailable or unverified
/// Gateway receipts as partial. Durable opaque tombstones remain retryable.
pub async fn ensure_fanout(state: &AppState, did: &str) {
    let _ = reconcile_account(state, did).await;
}

/// Recover terminal accounts from durable lifecycle state after restart.
/// The registration handoff ledger, rather than a legacy broadcast marker,
/// determines completion on every pass.
pub struct Worker {
    state: AppState,
}

impl Worker {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn run_once(&self) -> usize {
        let mut completed = 0;
        for (did, lifecycle) in self.state.identities().account_lifecycles_snapshot() {
            if FANOUT_LIFECYCLE_STATES.contains(&lifecycle.state.as_str()) {
                let was_partial = self.state.deactivation_push_partial(&did);
                if reconcile_account(&self.state, &did).await && was_partial {
                    completed += 1;
                }
            }
        }
        completed
    }

    pub fn spawn(self) -> Arc<tokio::task::JoinHandle<()>> {
        Arc::new(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(POLL_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut drain = self.state.subscribe_connection_drain();
            loop {
                tokio::select! {
                    _ = ticker.tick() => { let _ = self.run_once().await; }
                    changed = drain.changed() => {
                        if changed.is_err() || drain.borrow().is_some() { break; }
                    }
                }
            }
        }))
    }
}

pub fn spawn(state: AppState) -> Option<Arc<tokio::task::JoinHandle<()>>> {
    Some(Worker::new(state).spawn())
}
