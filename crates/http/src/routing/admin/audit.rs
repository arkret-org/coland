//! Audit-log surface.
//!
//! Two disjoint mounts (no double-mounting; SOL-NAME-02):
//!
//! - Operator queries ([`ops_router`], mounted inside the `RequireAdmin` gated `/_coland/admin/*`
//!   branch): `GET audit/events`, `GET audit/erasure-receipts`.
//!
//! `append_audit_log` — internal helper used everywhere a side-effect needs
//! to be recorded (auth, Realm lifecycle, message send, federation, etc.).
//!
//! All persistence access is mediated by `GovernanceService`.

use arkret_models_collaboration::governance::erasure::{
    ErasureAttemptOutcome, ErasureFanoutStatus, ErasureReceipt, ErasureStorageBoundary,
    ErasureSubjectKind,
};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_http::util::query_param;
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{AdminAuth, now, realm_has_member};
use crate::ids;
use crate::state::AppState;

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AuditErasureReceiptsOutcome {
    receipts: Vec<AuditErasureReceiptItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AuditErasureReceiptItem {
    receipt_id: Option<String>,
    issuer_id: Option<arkret_wire::DidCoreId>,
    subject_kind: Option<ErasureSubjectKind>,
    subject_ref: Option<String>,
    outcome: ErasureAttemptOutcome,
    storage_boundary: Option<ErasureStorageBoundary>,
    scope_realm_id: Option<String>,
    fanout_status: ErasureFanoutStatus,
    peer_receipts: Vec<arkret_models_collaboration::governance::erasure::ErasurePeerReceipt>,
    recorded_at: String,
    payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AuditEventsOutcome {
    events: Vec<Value>,
    next_cursor: Option<String>,
}

/// Operator audit queries, mounted inside the admin-gated
/// `/_coland/admin/*` branch.
pub(super) fn ops_router() -> Router {
    Router::new()
        // D14 — production typed audit query at the collection root.
        .push(Router::with_path("audit").get(super::queries::admin_query_audit))
        .push(Router::with_path("audit/events").get(audit_events))
        .push(Router::with_path("audit/erasure-receipts").get(audit_erasure_receipts))
}

/// Operator view over durable `ak.audit.erasure_receipt` Events, including
/// the canonical `fanout_status`. Receipts deliberately have no current-state
/// projection, so this endpoint derives its list from the immutable Event log.
///
/// The endpoint is authentication-gated; reading the receipt list does
/// not leak any post-erasure payload (the durable Events hold canonical
/// receipt envelopes — issuer / subject / outcome / scope — which are
/// the auditable surface by design).
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.audit.erasure_receipts.list",
    tags("coland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.audit.erasure_receipts.list"))]
async fn audit_erasure_receipts(
    admin: AdminAuth,
    depot: &mut Depot,
) -> JsonResult<AuditErasureReceiptsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    // Authenticate the session so the endpoint isn't usable
    // unauthenticated; we don't restrict cross-actor reads because the
    // receipt list is the auditable surface (see method doc above).
    let _session = admin.session()?;
    let mut receipts = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("erasure receipt query failed: {error}")))?
        .into_iter()
        .filter(|record| record.kind == arkret_wire::EventKind::AuditErasureReceipt.as_str())
        .map(|record| audit_erasure_receipt_item(&record))
        .collect::<Result<Vec<_>, _>>()?;
    for receipt in &mut receipts {
        if receipt.issuer_id.as_ref() == Some(&state.service_core_id())
            && let Some(id) = &receipt.receipt_id
        {
            (receipt.fanout_status, receipt.peer_receipts) =
                crate::routing::federation::erasure_receipts::fanout_progress(state, id).await?;
        }
    }
    json_ok(AuditErasureReceiptsOutcome { receipts })
}

fn audit_erasure_receipt_item(
    record: &coland_services::events::AcceptedEvent,
) -> Result<AuditErasureReceiptItem, AppError> {
    let payload = record
        .envelope
        .get("payload")
        .cloned()
        .ok_or_else(|| AppError::internal("erasure receipt Event has no payload"))?;
    let receipt: ErasureReceipt = serde_json::from_value(payload.clone()).map_err(|error| {
        AppError::internal(format!("accepted erasure receipt is not typed: {error}"))
    })?;
    receipt.validate_minimal().map_err(|error| {
        AppError::internal(format!("accepted erasure receipt is invalid: {error}"))
    })?;
    Ok(AuditErasureReceiptItem {
        peer_receipts: receipt.peer_receipts.clone(),
        receipt_id: Some(receipt.receipt_id),
        issuer_id: Some(receipt.issuer_id),
        subject_kind: Some(receipt.subject.kind),
        subject_ref: Some(receipt.subject.subject_ref),
        outcome: receipt.outcome,
        storage_boundary: Some(receipt.scope.storage_boundary),
        scope_realm_id: receipt.scope.realm_id.map(|realm_id| realm_id.to_string()),
        fanout_status: receipt
            .fanout_status
            .unwrap_or(ErasureFanoutStatus::Pending),
        recorded_at: arkret_canonical::format_timestamp_canonical(record.received_at),
        payload,
    })
}

#[salvo::oapi::endpoint(operation_id = "org.arkret.coland.audit.events", tags("coland_admin"))]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.audit.events"))]
async fn audit_events(
    admin: AdminAuth,
    actor: QueryParam<String, false>,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AuditEventsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = admin.session()?;
    let realm_id_filter = query_param(req, "realm_id");
    let kind_filter = query_param(req, "kind");
    let limit = limit.into_inner().unwrap_or(100).clamp(1, 500);
    let cursor = query_param(req, "cursor").or_else(|| cursor.into_inner());
    let mut events = if let Some(realm_id) = realm_id_filter.as_deref() {
        if !realm_has_member(
            state,
            realm_id,
            &crate::routing::identity::session_actor::session_actor_from_credential(
                state, &session,
            )?
            .to_string(),
        )
        .await
        {
            return Err(AppError::not_found("audit realm not found"));
        }
        state
            .governance()
            .audit_entries()
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to read audit log");
                AppError::internal("audit store unavailable")
            })?
            .into_iter()
            .filter(|event| audit_event_matches_realm(event, realm_id))
            .collect()
    } else {
        let actor = query_param(req, "actor")
            .or_else(|| actor.into_inner())
            .unwrap_or_else(|| session.actor.clone());
        if actor != session.actor {
            return Err(AppError::capability_denied(
                "audit queries are limited to the authenticated actor",
            ));
        }
        state
            .governance()
            .audit_entries_for_actor(&actor)
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to read audit log");
                AppError::internal("audit store unavailable")
            })?
    };
    if let Some(kind) = kind_filter.as_deref() {
        events.retain(|event| audit_event_matches_kind(event, kind));
    }
    let start = cursor
        .as_deref()
        .and_then(|cursor| {
            events
                .iter()
                .position(|event| event["audit_id"].as_str() == Some(cursor))
                .map(|index| index + 1)
        })
        .unwrap_or(0);
    if start > 0 {
        events.drain(..start);
    }
    let has_more = events.len() > limit;
    if has_more {
        events.truncate(limit);
    }
    let next_cursor = has_more
        .then(|| {
            events
                .last()
                .and_then(|event| event["audit_id"].as_str())
                .map(ToOwned::to_owned)
        })
        .flatten();
    json_ok(AuditEventsOutcome {
        events,
        next_cursor,
    })
}

fn audit_event_matches_realm(event: &Value, realm_id: &str) -> bool {
    [event.pointer("/payload/realm_id"), event.get("realm_id")]
        .into_iter()
        .flatten()
        .any(|value| value.as_str() == Some(realm_id))
}

fn audit_event_matches_kind(event: &Value, kind: &str) -> bool {
    [
        event.get("action"),
        event.get("kind"),
        event.pointer("/payload/kind"),
        event.pointer("/payload/type"),
    ]
    .into_iter()
    .flatten()
    .any(|value| value.as_str() == Some(kind))
}

pub async fn append_audit_log(
    state: &AppState,
    actor: Option<&str>,
    action: &str,
    payload: Value,
    outcome: &str,
) {
    let device_id = payload
        .get("device_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let realm_id = payload
        .get("realm_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let operation_id = payload
        .get("operation_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let entry = json!({
        "audit_id": ids::generate("audit"),
        "request_id": ids::generate_request_id(),
        "actor": actor,
        "device_id": device_id,
        "realm_id": realm_id,
        "operation_id": operation_id,
        "action": action,
        "payload": payload.clone(),
        "outcome": outcome,
        "created_at": now(),
    });
    if let Err(error) = state
        .governance()
        .append_audit_entry(coland_services::governance::AppendAuditEntryCommand { entry })
        .await
    {
        // Spec: C.3.7 — every audit-append failure MUST surface to
        // operators. We escalate to ERROR (was previously implicit
        // here) and bump the `coland_audit_append_failures_total`
        // metric so on-call can alert on durable-audit drops without
        // tailing the trace stream.
        tracing::error!(%error, action, outcome, "failed to append audit log entry");
        crate::metrics::record_audit_append_failure();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_models_collaboration::events_payloads::event_wire::ErasureTrigger;
    use arkret_models_collaboration::governance::erasure::{
        ErasedClass, ErasureReceiptProof, ErasureScope, ErasureSubject,
    };

    use super::*;

    #[test]
    fn erasure_receipt_audit_item_is_derived_from_the_durable_event_payload() {
        let recorded_at = chrono::DateTime::parse_from_rfc3339("2026-09-19T12:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let receipt = ErasureReceipt {
            receipt_id: "ak:receipt:019b5c20-0000-7000-8000-000000000030".to_owned(),
            trigger: ErasureTrigger::AccountStatusRecord {
                account_status_record_id: arkret_wire::AccountStatusRecordId::new(
                    "ak:account_status_record:AUPhm9XGSn2ah7YYExswNu0yaccqupAufE2bFvqEoD5N",
                )
                .unwrap(),
            },
            schema: ErasureReceipt::SCHEMA.to_owned(),
            issuer_id: arkret_identifiers::DidCoreId::new(
                "ak:did_core:webvh:z6mkfixtureissuerstation".to_owned(),
            )
            .unwrap(),
            subject: ErasureSubject {
                kind: ErasureSubjectKind::Space,
                subject_ref: "ak:space:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb".to_owned(),
            },
            scope: ErasureScope {
                storage_boundary: ErasureStorageBoundary::ProjectionStore,
                realm_id: Some(
                    arkret_identifiers::RealmId::new(
                        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb".to_owned(),
                    )
                    .unwrap(),
                ),
                target_refs: Vec::new(),
                retention_policy_id: None,
                service_scope: None,
            },
            outcome: ErasureAttemptOutcome::Completed,
            erased_classes: vec![ErasedClass::ProjectionRows],
            retained_stub_digest: arkret_identifiers::Hash::new(
                "sha256:aa67f34cd4e055246b8a73abe15734c39945b5c0e2e5693c00cada4e13d93e59",
            )
            .unwrap(),
            retained_stub: None,
            legal_hold_ref: None,
            completed_at: recorded_at,
            issued_at: Some(recorded_at),
            proofs: vec![ErasureReceiptProof {
                verification_method: arkret_wire::DidUrl::new(
                    "did:webvh:z6mkfixtureissuerstation:issuer.example#key-1".to_owned(),
                )
                .unwrap(),
                payload_digest: arkret_identifiers::Hash::new(
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )
                .unwrap(),
                signature: "receipt-signature-base64url-placeholder".to_owned(),
                extra: BTreeMap::new(),
            }],
            fanout_status: None,
            peer_receipts: Vec::new(),
        };
        let payload = serde_json::to_value(receipt).unwrap();
        let record = coland_services::events::AcceptedEvent {
            event_id: "ak:event:Adpb76fsaup_4Y_cV39of-L1_k6Nv1kSoCzXa9TM4szu".to_owned(),
            actor_id: "service".to_owned(),
            realm_id: None,
            kind: arkret_wire::EventKind::AuditErasureReceipt
                .as_str()
                .to_owned(),
            schema_id: "schemas/event-payload.schema.json#/$defs/erasure_receipt_payload"
                .to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
            canonical_bytes: Vec::new(),
            envelope: json!({"payload": payload}),
            received_at: recorded_at,
        };

        let item = audit_erasure_receipt_item(&record).unwrap();
        assert_eq!(item.outcome, ErasureAttemptOutcome::Completed);
        assert_eq!(item.subject_kind, Some(ErasureSubjectKind::Space));
        assert_eq!(
            item.storage_boundary,
            Some(ErasureStorageBoundary::ProjectionStore)
        );
        assert_eq!(item.fanout_status, ErasureFanoutStatus::Pending);
        assert_eq!(item.payload, record.envelope["payload"]);
    }
}
