//! Operator surface for the durable federation outbox.
//!
//! Terminal failures land in `federation_outbox_dead_letter`. Restarting the
//! server does **not** replay them — by design: a dead letter means the peer
//! rejected the request or the retry budget ran out, and re-sending blindly
//! would just repeat the failure. Replay is a deliberate operator act, which is
//! what this module provides:
//!
//! ```text
//! coland-federation-outbox list [--state <state>] [--dead-letters] [--limit N]
//! coland-federation-outbox inspect <outbox-id|dead-letter-id>
//! coland-federation-outbox requeue <dead-letter-id> --operator <did> --reason <text>
//! ```
//!
//! A requeue never resurrects the old row. It re-validates the target, mints a
//! **new** intent with a **new** `Idempotency-Key` (`sync/federation.md` §8.5 —
//! a response was received, so the old transport identity is spent), and stamps
//! the operator, reason, time and request digest onto the dead letter as the
//! audit record. There is deliberately no way to clear a terminal row's
//! `completed_at` and let it be picked up again.
//!
//! No HTTP surface is exposed. Adding one would require a canonical operation
//! and an `/_arkret/...` binding in `arkret-spec` first; a private
//! `/_coland/...` admin route is not permitted.

use coland_services::federation::{
    FederationDeadLetter, FederationDeliveryRecord, PendingFederationDelivery,
    RequeueFederationDeadLetterCommand,
};
use coland_storage::FederationOutboxState;
use serde::Serialize;
use uuid::Uuid;

use crate::state::AppState;

/// Default page size for the listing commands.
pub const DEFAULT_LIST_LIMIT: usize = 50;

/// One row as the operator sees it. Deliberately omits `payload_json`: a
/// listing should not spray federated Event bodies across a terminal.
#[derive(Debug, Serialize)]
pub struct OutboxSummary {
    pub id: String,
    pub state: String,
    pub peer_id: arkret_wire::DidCoreId,
    pub endpoint: String,
    pub idempotency_key: String,
    pub attempts: i32,
    pub semantic_attempts: i32,
    pub next_attempt_at: i64,
    pub last_http_status: Option<i32>,
    pub last_error_code: Option<String>,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<i64>,
    pub policy_version: Option<String>,
    pub supersedes_outbox_id: Option<String>,
    pub created_at: i64,
    pub completed_at: Option<i64>,
}

impl From<PendingFederationDelivery> for OutboxSummary {
    fn from(row: PendingFederationDelivery) -> Self {
        Self {
            id: row.delivery.id,
            state: row.state.as_str().to_owned(),
            peer_id: row.delivery.peer_id,
            endpoint: row.delivery.endpoint,
            idempotency_key: row.delivery.idempotency_key,
            attempts: row.attempts,
            semantic_attempts: row.semantic_attempts,
            next_attempt_at: row.next_attempt_at,
            last_http_status: row.last_http_status,
            last_error_code: row.last_error_code,
            lease_owner: row.lease_owner,
            lease_expires_at: row.lease_expires_at,
            policy_version: row.policy_version,
            supersedes_outbox_id: row.supersedes_outbox_id,
            created_at: row.delivery.created_at,
            completed_at: row.completed_at,
        }
    }
}

/// Full detail for one row, including the response excerpt that explains why it
/// stopped. The request body is reported by digest, not verbatim.
#[derive(Debug, Serialize)]
pub struct OutboxDetail {
    #[serde(flatten)]
    pub summary: OutboxSummary,
    pub peer_url: Option<String>,
    pub payload_digest: String,
    pub payload_bytes: usize,
    pub last_response_excerpt: Option<String>,
    pub dead_letters: Vec<DeadLetterDetail>,
}

#[derive(Debug, Serialize)]
pub struct DeadLetterDetail {
    pub id: String,
    pub outbox_id: String,
    pub peer_id: arkret_wire::DidCoreId,
    pub endpoint: String,
    pub idempotency_key: String,
    pub reason: String,
    pub last_http_status: Option<i32>,
    pub attempts: i32,
    pub response_excerpt: Option<String>,
    pub failed_at: i64,
    pub requeued_outbox_id: Option<String>,
    pub requeued_by: Option<String>,
    pub requeue_reason: Option<String>,
    pub requeue_request_digest: Option<String>,
    pub requeued_at: Option<i64>,
}

impl From<FederationDeadLetter> for DeadLetterDetail {
    fn from(record: FederationDeadLetter) -> Self {
        Self {
            id: record.id,
            outbox_id: record.outbox_id,
            peer_id: record.peer_id,
            endpoint: record.endpoint,
            idempotency_key: record.idempotency_key,
            reason: record.reason,
            last_http_status: record.last_http_status,
            attempts: record.attempts,
            response_excerpt: record.response_excerpt,
            failed_at: record.failed_at,
            requeued_outbox_id: record.requeued_outbox_id,
            requeued_by: record.requeued_by,
            requeue_reason: record.requeue_reason,
            requeue_request_digest: record.requeue_request_digest,
            requeued_at: record.requeued_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RequeueOutcome {
    pub dead_letter_id: String,
    pub original_outbox_id: String,
    pub requeued_outbox_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub operator: String,
    pub reason: String,
    pub requeued_at: i64,
}

/// Rows in one lifecycle state, newest first.
pub async fn list_by_state(
    state: &AppState,
    lifecycle: FederationOutboxState,
    limit: usize,
) -> Result<Vec<OutboxSummary>, String> {
    Ok(state
        .federation()
        .deliveries_by_state(lifecycle, limit)
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(OutboxSummary::from)
        .collect())
}

pub async fn list_dead_letters(
    state: &AppState,
    limit: usize,
) -> Result<Vec<DeadLetterDetail>, String> {
    let mut records = state
        .federation()
        .dead_letters()
        .await
        .map_err(|error| error.to_string())?;
    records.sort_by(|left, right| {
        (right.failed_at, right.id.as_str()).cmp(&(left.failed_at, left.id.as_str()))
    });
    records.truncate(limit);
    Ok(records.into_iter().map(DeadLetterDetail::from).collect())
}

/// Resolve one id as either an outbox row or a dead letter and report the full
/// picture, including every dead letter recorded against that row.
pub async fn inspect(state: &AppState, id: &str) -> Result<OutboxDetail, String> {
    let dead_letter = state
        .federation()
        .dead_letter(id)
        .await
        .map_err(|error| error.to_string())?;
    let outbox_id = dead_letter
        .as_ref()
        .map_or_else(|| id.to_owned(), |record| record.outbox_id.clone());
    let row = state
        .federation()
        .delivery(&outbox_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("no federation outbox row or dead letter with id {id}"))?;
    let mut dead_letters = state
        .federation()
        .dead_letters()
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|record| record.outbox_id == outbox_id)
        .map(DeadLetterDetail::from)
        .collect::<Vec<_>>();
    dead_letters.sort_by_key(|record| record.failed_at);
    Ok(OutboxDetail {
        peer_url: row.delivery.peer_url.clone(),
        payload_digest: arkret_canonical::sha256_digest(row.delivery.payload_json.as_bytes()),
        payload_bytes: row.delivery.payload_json.len(),
        last_response_excerpt: row.last_response_excerpt.clone(),
        dead_letters,
        summary: OutboxSummary::from(row),
    })
}

/// Replay one dead letter as a fresh delivery intent.
///
/// Revalidation happens before anything is written: the peer must still be
/// configured, the deployment egress policy must still allow it, and the stored
/// request must still satisfy the federation transport contract (which is what
/// carries the Event dependency closure and the service binding). Only then is
/// a new row minted, in the same transaction that stamps the audit.
pub async fn requeue_dead_letter(
    state: &AppState,
    dead_letter_id: &str,
    operator: &str,
    reason: &str,
) -> Result<RequeueOutcome, String> {
    let operator = operator.trim();
    let reason = reason.trim();
    if operator.is_empty() {
        return Err("requeue requires --operator".to_owned());
    }
    if reason.is_empty() {
        return Err("requeue requires --reason".to_owned());
    }
    let dead_letter = state
        .federation()
        .dead_letter(dead_letter_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("no federation dead letter with id {dead_letter_id}"))?;
    if let Some(existing) = &dead_letter.requeued_outbox_id {
        return Err(format!(
            "dead letter {dead_letter_id} was already requeued as {existing}"
        ));
    }
    let original = state
        .federation()
        .delivery(&dead_letter.outbox_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "dead letter {dead_letter_id} references missing outbox row {}",
                dead_letter.outbox_id
            )
        })?;

    // (1) The stable service core must still resolve through the verified
    // record→describe chain. The historical peer_url is diagnostic only and
    // intentionally does not pin a handover-era route.
    let peer_target =
        super::resolved_peer_target(state, original.delivery.peer_id.as_str(), "station", true)
            .await?;
    if let Some(reason) = crate::security::federation_outbound_trust_domain_denial(
        original.delivery.peer_id.as_str(),
        Some(&peer_target.trust_domain),
    ) {
        return Err(format!(
            "sovereign policy still denies verified destination trust_domain: {reason}"
        ));
    }
    let peer_url = peer_target.base_url;

    // (2) The deployment egress policy must allow the target today. Requeuing
    // past a still-denying policy is exactly what §4.4 forbids.
    let target = format!("{peer_url}{}", original.delivery.endpoint);
    crate::security::validate_http_url_for_egress(
        &target,
        "federation outbox requeue",
        state.config().development_mode,
    )
    .map_err(|error| format!("egress policy still denies {target}: {error}"))?;

    // (3) The stored request must still satisfy the transport contract, which
    // is what binds the service binding ref and the Event dependency closure.
    revalidate_transport(&original.delivery)?;

    let request_digest = arkret_canonical::sha256_digest(original.delivery.payload_json.as_bytes());
    // Derived from the dead-letter id, so a retried CLI invocation recomputes
    // the same key and the unique index collapses it instead of double-sending.
    let idempotency_key = format!(
        "ak:outbox:requeue:{}",
        arkret_canonical::sha256_digest(format!("{dead_letter_id}\0{request_digest}").as_bytes())
    );
    let requeued_at = chrono::Utc::now().timestamp();
    let requeued_outbox_id = Uuid::new_v4().to_string();
    let applied = state
        .federation()
        .requeue_dead_letter(RequeueFederationDeadLetterCommand {
            dead_letter_id: dead_letter_id.to_owned(),
            delivery: FederationDeliveryRecord {
                id: requeued_outbox_id.clone(),
                peer_id: original.delivery.peer_id.clone(),
                peer_url: Some(peer_url),
                endpoint: original.delivery.endpoint.clone(),
                idempotency_key: idempotency_key.clone(),
                payload_json: original.delivery.payload_json.clone(),
                coalescing_key: original.delivery.coalescing_key.clone(),
                coalescing_position: original.delivery.coalescing_position,
                realm_fanout: None,
                created_at: requeued_at,
            },
            supersedes_outbox_id: original.delivery.id.clone(),
            operator: operator.to_owned(),
            reason: reason.to_owned(),
            request_digest: request_digest.clone(),
            requeued_at,
        })
        .await
        .map_err(|error| error.to_string())?;
    if !applied {
        return Err(format!(
            "dead letter {dead_letter_id} was requeued concurrently"
        ));
    }
    tracing::warn!(
        target = "federation_outbox",
        dead_letter_id,
        outbox_id = %original.delivery.id,
        requeued_outbox_id = %requeued_outbox_id,
        operator,
        reason,
        request_digest = %request_digest,
        "operator requeued a federation dead letter as a fresh delivery intent"
    );
    Ok(RequeueOutcome {
        dead_letter_id: dead_letter_id.to_owned(),
        original_outbox_id: original.delivery.id,
        requeued_outbox_id,
        idempotency_key,
        request_digest,
        operator: operator.to_owned(),
        reason: reason.to_owned(),
        requeued_at,
    })
}

/// Re-run the wire contract over the stored request body.
///
/// The peer-Event and peer-invite rails carry typed federation transport
/// contracts; the private operations rail carries its own envelope, so there is
/// nothing to re-derive for it beyond it still being parseable JSON.
fn revalidate_transport(delivery: &FederationDeliveryRecord) -> Result<(), String> {
    if delivery.endpoint == "/_arkret/peer/invites" {
        let body: arkret_models_collaboration::governance::invite_addressing::InviteDeliveryRequestBody =
            serde_json::from_str(&delivery.payload_json)
                .map_err(|error| format!("stored federation request no longer parses: {error}"))?;
        return body
            .validate_minimal()
            .map_err(|error| format!("stored federation request is no longer valid: {error}"));
    }
    if delivery.endpoint == "/_arkret/peer/events" {
        let body: arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest =
            serde_json::from_str(&delivery.payload_json)
                .map_err(|error| format!("stored federation request no longer parses: {error}"))?;
        return body
            .validate()
            .map_err(|error| format!("stored federation request is no longer valid: {error}"));
    }
    serde_json::from_str::<serde_json::Value>(&delivery.payload_json)
        .map(|_| ())
        .map_err(|error| format!("stored federation request no longer parses: {error}"))
}
