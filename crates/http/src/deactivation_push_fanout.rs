//! Push-gateway deactivation fanout producer (`account-lifecycle.md` §7.1).
//!
//! The spec's Push-route fanout row completes only when the push gateway side
//! stops delivering: when a gateway independently owns registration endpoints
//! or delivery state, the Principal Server must notify it through the registered
//! internal channel and obtain the outcome; a local purge alone is insufficient
//! (§7.1, Push-route completion criterion). This module is
//! that registered internal channel's producer side:
//!
//! - the wire contract is the audited `floria-contracts` crate (shared with the floria gateway,
//!   `POST /_floria/internal/account_deactivate_fanout`, bearer-protected by floria's
//!   `http.internal_auth` profile);
//! - [`ensure_fanout`] runs inline in both legal deactivation transitions (admin
//!   `set_account_lifecycle_state` and account-status erasure execution) and never fails the
//!   deactivation itself — a gateway failure raises the `deactivation_partial` service-side flag
//!   instead;
//! - [`Worker`] is the durable reconciliation loop: pending work is derived from the durable
//!   account-lifecycle registry minus the completion markers in the jobs idempotency ledger, so a
//!   crash or restart loses nothing and the flag re-converges on the first pass.
//!
//! **Unconfigured gateway** (`deactivation_push_gateway_url = None`): the
//! §7.1 criterion is conditional on a gateway *independently holding*
//! registration/delivery state reachable over a *registered* internal
//! channel. A deployment that configures no such channel (dev single-box, no
//! floria) has declared that no independent gateway holds delivery state, so
//! the local push-route purge already performed by the fanout IS the complete
//! Push-route action; we neither raise `deactivation_partial` nor invent an
//! unreachable retry loop that could never succeed. Deployments running
//! floria MUST set `COLAND_DEACTIVATION_PUSH_GATEWAY_URL` (and the bearer) —
//! see the config docs.
//!
//! **Idempotency / retry identity**: the first broadcast for an account uses
//! the deterministic [`base_fanout_id`]. floria records the first-seen result
//! per `fanout_id` and replays it on retry, so after an ack with outcome
//! `partially_completed` a retry MUST mint a fresh id (the recorded partial
//! result would otherwise replay forever); transport failures keep the same
//! id so a lost response resolves to the recorded outcome. Double-unbinding
//! is prevented by floria's per-actor/per-device ledger, not by the id.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use floria_contracts::{
    ACCOUNT_DEACTIVATE_FANOUT_PATH, AccountDeactivateFanoutAck, AccountDeactivateFanoutBroadcast,
    DeactivateFanoutOutcome,
};
use parking_lot::Mutex;

use crate::state::AppState;

/// How often the reconciliation worker polls for incomplete fanouts.
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Per-request full-response timeout against the gateway.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Exponential backoff base/cap for bounded gateway retries (§7.1).
const BACKOFF_BASE_SECS: u64 = 5;
const BACKOFF_CAP_SECS: u64 = 300;

/// Lifecycle states whose accounts require the push-gateway fanout leg.
/// `erasure_pending` is included because erasure execution runs the same
/// deactivation fanout before erasing.
const FANOUT_LIFECYCLE_STATES: [&str; 2] = ["deactivated", "erasure_pending"];

fn completion_principal_id(state: &AppState) -> arkret_wire::DidCoreId {
    state.service_core_id()
}

fn completion_key(did: &str) -> String {
    format!("deactivation-push-fanout:{did}:completed")
}

/// Deterministic first-attempt fanout id: stable across process restarts so a
/// replay after a lost response deduplicates on the gateway ledger.
pub fn base_fanout_id(service_id: &str, did: &str) -> String {
    let mut input = Vec::with_capacity(service_id.len() + did.len() + 1);
    input.extend_from_slice(service_id.as_bytes());
    input.push(0);
    input.extend_from_slice(did.as_bytes());
    format!(
        "coland:deactivation:{}",
        arkret_canonical::sha256_digest(&input)
    )
}

/// The configured gateway target, or `None` in the no-gateway posture.
fn gateway_fanout_url(state: &AppState) -> Option<String> {
    let base = state.config().deactivation_push_gateway_url.as_deref()?;
    let base = base.trim().trim_end_matches('/');
    if base.is_empty() {
        return None;
    }
    Some(format!("{base}{ACCOUNT_DEACTIVATE_FANOUT_PATH}"))
}

/// Whether the durable completion marker for `did` exists.
async fn fanout_completed(state: &AppState, did: &str) -> Result<bool, String> {
    state
        .jobs()
        .idempotency_record(&completion_principal_id(state), &completion_key(did))
        .await
        .map(|record| record.is_some())
        .map_err(|error| format!("fanout completion lookup: {error}"))
}

/// Persist the durable completion marker for `did` with the gateway's ack.
async fn store_completion(
    state: &AppState,
    did: &str,
    ack: &AccountDeactivateFanoutAck,
) -> Result<(), String> {
    let created_at = Utc::now();
    state
        .jobs()
        .store_idempotency_record(coland_services::jobs::IdempotencyState {
            authenticated_actor: arkret_wire::ActorId::service(completion_principal_id(state)),
            operation_id: coland_services::jobs::INTERNAL_IDEMPOTENCY_OPERATION.to_owned(),
            idempotency_key: completion_key(did),
            request_hash: base_fanout_id(state.service_id(), did),
            response_status: 200,
            response_body: serde_json::to_value(ack)
                .map_err(|error| format!("fanout ack encode: {error}"))?,
            created_at,
            expires_at: created_at + chrono::Duration::days(36_500),
        })
        .await
        .map_err(|error| format!("fanout completion store: {error}"))
}

/// One POST to the gateway. `Ok(ack)` means the gateway processed the
/// broadcast and answered; the ack's `outcome` still decides completion.
async fn post_broadcast(
    state: &AppState,
    url: &str,
    broadcast: &AccountDeactivateFanoutBroadcast,
) -> Result<AccountDeactivateFanoutAck, String> {
    let (parsed_url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        url,
        "deactivation push fanout",
        state.config().development_mode,
        REQUEST_TIMEOUT,
    )?;
    let mut request = client.post(parsed_url).json(broadcast);
    if let Some(bearer) = state
        .config()
        .deactivation_push_gateway_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.bearer_auth(bearer);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("gateway transport error: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("gateway returned HTTP {status}"));
    }
    let ack = response
        .json::<AccountDeactivateFanoutAck>()
        .await
        .map_err(|error| format!("gateway ack decode failed: {error}"))?;
    if ack.fanout_id != broadcast.fanout_id {
        return Err(format!(
            "gateway ack fanout_id mismatch: sent {}, got {}",
            broadcast.fanout_id, ack.fanout_id
        ));
    }
    Ok(ack)
}

/// Attempt the gateway broadcast once and record the result.
///
/// Returns `true` when the fanout leg is complete (marker stored). On any
/// failure the `deactivation_partial` projection is raised and `false`
/// returned — the caller (inline path or worker) retries later.
async fn attempt_fanout(state: &AppState, did: &str, fanout_id: String) -> bool {
    let Some(url) = gateway_fanout_url(state) else {
        return true;
    };
    let broadcast = AccountDeactivateFanoutBroadcast {
        fanout_id,
        actor_id: did.to_owned(),
        // Empty devices = "every device for this actor" on the gateway
        // ledger. The local device rows may already be revoked or erased by
        // the time this runs (worker retries, erasure), so the actor-scoped
        // form is the only one that is always faithful.
        devices: Vec::new(),
        reason: Some("account_deactivated".to_owned()),
    };
    match post_broadcast(state, &url, &broadcast).await {
        Ok(ack) => match ack.outcome {
            DeactivateFanoutOutcome::Completed | DeactivateFanoutOutcome::NoOp => {
                if let Err(error) = store_completion(state, did, &ack).await {
                    // The gateway side is done; only the local marker failed.
                    // Keep partial raised so the worker replays (idempotent on
                    // the gateway ledger) until the marker persists.
                    tracing::error!(%error, %did, "deactivation push fanout ack could not be persisted");
                    state.set_deactivation_push_partial(did, true);
                    return false;
                }
                state.set_deactivation_push_partial(did, false);
                tracing::info!(
                    %did,
                    outcome = ack.outcome.as_str(),
                    actor_bindings_unbound = ack.actor_bindings_unbound,
                    device_bindings_unbound = ack.device_bindings_unbound,
                    messages_drained = ack.messages_drained,
                    "deactivation push fanout completed on gateway"
                );
                true
            }
            DeactivateFanoutOutcome::PartiallyCompleted => {
                tracing::warn!(
                    %did,
                    fanout_id = %ack.fanout_id,
                    "gateway reported partially_completed deactivation fanout; will retry with a fresh fanout_id"
                );
                state.set_deactivation_push_partial(did, true);
                false
            }
        },
        Err(error) => {
            tracing::warn!(
                %error,
                %did,
                "deactivation push fanout attempt failed; deactivation_partial raised"
            );
            state.set_deactivation_push_partial(did, true);
            false
        }
    }
}

/// Inline producer hook — called from `run_account_deactivation_fanout` on
/// both legal deactivation transitions. Never returns an error: per §7.1 a
/// gateway failure marks `deactivation_partial` and retries; it does not
/// fail the deactivation.
pub async fn ensure_fanout(state: &AppState, did: &str) {
    if gateway_fanout_url(state).is_none() {
        // No registered internal channel — the local push-route purge is the
        // complete Push-route action for this deployment posture (see module
        // docs for the §7.1 reading).
        tracing::debug!(
            %did,
            "no deactivation push gateway configured; local push-route purge completes the Push-route fanout row"
        );
        return;
    }
    match fanout_completed(state, did).await {
        Ok(true) => {
            state.set_deactivation_push_partial(did, false);
            return;
        }
        Ok(false) => {}
        Err(error) => {
            tracing::warn!(%error, %did, "deactivation push fanout completion lookup failed; attempting broadcast anyway");
        }
    }
    let _ = attempt_fanout(state, did, base_fanout_id(state.service_id(), did)).await;
}

/// Per-account in-memory retry bookkeeping (attempt count for backoff and the
/// fresh fanout id minted after a `partially_completed` ack). Losing it on
/// restart is safe: the first pass falls back to the deterministic base id
/// and zero backoff.
#[derive(Default)]
struct RetryState {
    attempts: u32,
    next_attempt_at: i64,
    retry_fanout_id: Option<String>,
}

/// Durable reconciliation worker. Pending work = accounts whose lifecycle
/// state requires the fanout leg minus those with a completion marker.
pub struct Worker {
    state: AppState,
    retries: Mutex<std::collections::BTreeMap<String, RetryState>>,
}

impl Worker {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            retries: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    /// Run one reconciliation pass. Returns how many accounts completed the
    /// gateway leg during this pass.
    pub async fn run_once(&self) -> usize {
        if gateway_fanout_url(&self.state).is_none() {
            return 0;
        }
        let now = Utc::now().timestamp();
        let mut completed = 0_usize;
        for (did, lifecycle) in self.state.identities().account_lifecycles_snapshot() {
            if !FANOUT_LIFECYCLE_STATES.contains(&lifecycle.state.as_str()) {
                continue;
            }
            match fanout_completed(&self.state, &did).await {
                Ok(true) => {
                    self.state.set_deactivation_push_partial(&did, false);
                    self.retries.lock().remove(&did);
                    continue;
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(%error, %did, "deactivation push fanout completion lookup failed in worker pass");
                    continue;
                }
            }
            // Incomplete: converge the projection even before the attempt so
            // a restart restores `deactivation_partial` on the first pass.
            self.state.set_deactivation_push_partial(&did, true);
            let fanout_id = {
                let retries = self.retries.lock();
                match retries.get(&did) {
                    Some(retry) if retry.next_attempt_at > now => continue,
                    Some(retry) => retry
                        .retry_fanout_id
                        .clone()
                        .unwrap_or_else(|| base_fanout_id(self.state.service_id(), &did)),
                    None => base_fanout_id(self.state.service_id(), &did),
                }
            };
            if attempt_fanout(&self.state, &did, fanout_id).await {
                completed += 1;
                self.retries.lock().remove(&did);
            } else {
                let mut retries = self.retries.lock();
                let retry = retries.entry(did.clone()).or_default();
                retry.attempts = retry.attempts.saturating_add(1);
                let shift = retry.attempts.min(20);
                let delay = BACKOFF_BASE_SECS
                    .saturating_mul(1_u64 << shift)
                    .min(BACKOFF_CAP_SECS);
                retry.next_attempt_at = now + delay as i64;
                // After a `partially_completed` ack the recorded gateway
                // result replays on the same id; mint a fresh retry id.
                // (Harmless for transport failures too — the gateway ledger,
                // not the id, prevents double-unbinding.)
                retry.retry_fanout_id = Some(format!(
                    "{}:r{}",
                    base_fanout_id(self.state.service_id(), &did),
                    uuid::Uuid::new_v4()
                ));
            }
        }
        completed
    }

    /// Spawn the reconciliation loop on the current tokio runtime.
    pub fn spawn(self) -> Arc<tokio::task::JoinHandle<()>> {
        Arc::new(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(POLL_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let _ = self.run_once().await;
            }
        }))
    }
}

/// Spawn the reconciliation worker when a gateway is configured; no-op
/// (returns `None`) in the no-gateway posture.
pub fn spawn(state: AppState) -> Option<Arc<tokio::task::JoinHandle<()>>> {
    state.config().deactivation_push_gateway_url.as_ref()?;
    Some(Worker::new(state).spawn())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_fanout_id_is_deterministic_and_actor_scoped() {
        let a1 = base_fanout_id("did:web:server.example", "did:web:alice.example");
        let a2 = base_fanout_id("did:web:server.example", "did:web:alice.example");
        let b = base_fanout_id("did:web:server.example", "did:web:bob.example");
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert!(a1.starts_with("coland:deactivation:"));
    }
}
