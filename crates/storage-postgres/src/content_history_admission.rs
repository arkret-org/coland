//! Native history requests use current read authority, not an issuer's grant.

use arkret_event_draft::EventPayloadExt as _;
use arkret_wire::{CommitStreamRef, EventKind, ScopeRef};
use coland_storage::{AuthorityCommitTransaction, PersistenceError, PersistenceResult};

use crate::AsyncPgConnection;

fn refused(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {}", detail.into()))
}

/// Called under the Realm lock after the producer's native signature/current
/// guard, and before installing a fresh Commit. Exact accepted replays bypass
/// this check without issuing another request or changing its original bytes.
pub(crate) async fn require_request_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> PersistenceResult<()> {
    let event = &transaction.event;
    if event.kind != EventKind::MlsHistoryRequest {
        return Ok(());
    }
    if event.executed_by.is_some() || event.authorization_ref.is_some() {
        return Err(refused(
            "history request requires its exact endpoint's self-authored proof",
        ));
    }
    let request = event
        .as_mls_history_request()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let at = chrono::Utc::now().max(transaction.commit.committed_at);
    request
        .validate_at(event.created_at, at)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    arkret_crypto::hpke::validate_x25519_recipient_key(
        &arkret_canonical::base64url_decode(&request.recipient_hpke_key_base64url)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;

    let group = crate::mls_group_current_states::locked_group(
        conn,
        &crate::mls_group_current_states::scope_key(&event.scope_ref)?,
    )
    .await?
    .ok_or_else(|| refused("history request has no accepted current MLS group"))?;
    let endpoint = crate::content_endpoint_bindings::current_producer_in_connection(
        conn,
        transaction,
        &group.value,
    )
    .await?;
    if endpoint != request.recipient || event.actor_id != endpoint.actor_id {
        return Err(refused(
            "history request differs from its native current endpoint",
        ));
    }
    let cut = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &request.history_cut.event_id,
    )
    .await?
    .ok_or_else(|| refused("history cut is not an accepted original"))?;
    if cut.commit.commit_id != request.history_cut.commit_id
        || cut.commit.stream_ref != request.history_cut.stream_ref
        || cut.commit.stream_position != request.history_cut.stream_position
        || cut.commit.stream_ref
            != CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
        || cut.event.realm_id != event.realm_id
    {
        return Err(refused(
            "history cut differs from the exact requested scope or original",
        ));
    }

    // This proves current resource readability; selectors and their Actor
    // floor are independently checked when granting actual historical keys.
    let floor = match &event.scope_ref {
        ScopeRef::Realm { realm_id } => {
            crate::account_stream_scan::caller_realm_floor_in_connection(
                conn,
                realm_id,
                &event.actor_id,
            )
            .await?
        }
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => {
            crate::account_stream_scan::caller_circle_floor_in_connection(
                conn,
                realm_id,
                circle_id,
                &event.actor_id,
            )
            .await?
        }
        _ => {
            return Err(refused(
                "native history requests for this scope are not yet qualified",
            ));
        }
    };
    if floor.is_none() {
        return Err(refused(
            "history request has no current readable resource interval",
        ));
    }
    let read =
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event).await?;
    read.require_open_content_read()?;
    read.require_membership_read_constraints_in_connection(conn, event, at)
        .await?;
    Ok(())
}
