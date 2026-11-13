//! Native history requests and grants recheck independent same-cut authority.

use arkret_event_draft::{EventContentEnvelopesExt as _, EventPayloadExt as _};
use arkret_wire::{CommitStreamRef, EventKind, ScopeRef};
use coland_storage::{AuthorityCommitTransaction, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use horme::RunQueryDsl as _;

use crate::AsyncPgConnection;

fn refused(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {}", detail.into()))
}

/// Called under the Realm lock after the producer's native signature/current
/// guard, and before installing a fresh Commit. Exact accepted replays bypass
/// this check without issuing another request or changing its original bytes.
async fn require_request_in_connection(
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
    let floor = crate::account_content_delivery::export_floor_in_connection(
        conn,
        &request.history_cut.stream_ref,
        &event.actor_id,
        true,
    )
    .await?;
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

pub(crate) async fn require_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> PersistenceResult<()> {
    match transaction.event.kind {
        EventKind::MlsHistoryRequest => require_request_in_connection(conn, transaction).await,
        EventKind::MlsHistoryGrant => require_grant_in_connection(conn, transaction).await,
        _ => Ok(()),
    }
}

fn exact_reference(
    full: &arkret_wire::CommittedEventFullView,
    reference: &arkret_wire::CommittedEventRef,
) -> bool {
    full.event.event_id == reference.event_id
        && full.commit.commit_id == reference.commit_id
        && full.commit.stream_ref == reference.stream_ref
        && full.commit.stream_position == reference.stream_position
}

async fn require_source_read(
    conn: &mut AsyncPgConnection,
    source: &arkret_wire::CommittedEventFullView,
    scope: &ScopeRef,
    cut: &arkret_wire::CommittedEventRef,
    readers: &[&arkret_wire::ActorId],
) -> PersistenceResult<()> {
    if &source.event.scope_ref != scope
        || source.commit.stream_ref != cut.stream_ref
        || source.commit.stream_position > cut.stream_position
    {
        return Err(refused(
            "history source differs from its exact scope or exceeds the request cut",
        ));
    }
    for reader in readers {
        let floor = crate::account_content_delivery::export_floor_in_connection(
            conn,
            &cut.stream_ref,
            reader,
            true,
        )
        .await?
        .ok_or_else(|| refused("history source has no current readable interval"))?;
        if source.commit.stream_position < floor {
            return Err(refused(
                "history source precedes the Actor's current history floor",
            ));
        }
        let rows = crate::committed_disclosure::disclose_to_member_in_connection(
            conn,
            vec![source.clone()],
            reader,
        )
        .await?;
        if !matches!(rows.as_slice(), [arkret_wire::CommittedEventView::Full(_)]) {
            return Err(refused(
                "history source is not currently disclosed to issuer and recipient",
            ));
        }
    }
    // Independently reverify any retained original producer fact and signature;
    // this never promotes a request's endpoint key into content-read authority.
    crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
        conn,
        &source.event,
        &source.commit,
    )
    .await?;
    Ok(())
}

async fn require_grant_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> PersistenceResult<()> {
    use arkret_models_crypto::HistoryKeySelector;
    let event = &transaction.event;
    let grant = event
        .as_mls_history_grant()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let original = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &grant.recipient_key_event_ref,
    )
    .await?
    .ok_or_else(|| refused("history grant has no accepted original request"))?;
    if original.event.kind != EventKind::MlsHistoryRequest
        || original.event.scope_ref != event.scope_ref
        || original.event.realm_id != event.realm_id
        || original.event.executed_by.is_some()
        || original.event.authorization_ref.is_some()
        || event.created_at < original.event.created_at
    {
        return Err(refused(
            "history grant request source or self-authored endpoint proof differs",
        ));
    }
    let request = original
        .event
        .as_mls_history_request()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    grant
        .validate_for_request(&original.event.event_id, &request)
        .map_err(|error| refused(error.to_string()))?;
    request
        .validate_at(
            original.event.created_at,
            chrono::Utc::now().max(transaction.commit.committed_at),
        )
        .map_err(|error| refused(error.to_string()))?;
    let cut = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &grant.history_cut.event_id,
    )
    .await?
    .ok_or_else(|| refused("history grant cut has no accepted original"))?;
    if !exact_reference(&cut, &grant.history_cut)
        || cut.commit.stream_ref
            != CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
                .map_err(|error| refused(error.to_string()))?
    {
        return Err(refused(
            "history grant cut differs from its scope's accepted original",
        ));
    }
    let group = crate::mls_group_current_states::locked_group(
        conn,
        &crate::mls_group_current_states::scope_key(&event.scope_ref)?,
    )
    .await?
    .ok_or_else(|| refused("history grant has no accepted current MLS group"))?;
    let station = sql_query(
        "SELECT to_jsonb(station_id) AS payload FROM device_inventory_station WHERE singleton",
    )
    .get_result::<crate::JsonPayloadRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let station: arkret_wire::DidCoreId =
        serde_json::from_value(station.payload).map_err(PersistenceError::database)?;
    crate::content_endpoint_bindings::current_history_recipient_in_connection(
        conn,
        &original,
        &group.value,
        &station,
    )
    .await?;
    let readers = [&event.actor_id, &grant.recipient.actor_id];
    for entry in &grant.entries {
        match &entry.selector {
            HistoryKeySelector::ContentKey {
                source_event_ref,
                content_path,
            } => {
                let source = crate::committed_disclosure::accepted_full_event_in_connection(
                    conn,
                    source_event_ref,
                )
                .await?
                .ok_or_else(|| refused("history selected source is not an accepted original"))?;
                require_source_read(
                    conn,
                    &source,
                    &event.scope_ref,
                    &grant.history_cut,
                    &readers,
                )
                .await?;
                let width =
                    arkret_event_draft::history_content_key_width(&source.event, content_path)
                        .map_err(|error| refused(error.to_string()))?;
                let packed = arkret_canonical::base64url_decode(&entry.sealed_key_base64url)
                    .map_err(|error| refused(error.to_string()))?;
                if packed.len() != width + 48 {
                    return Err(refused(
                        "history selected key width differs from its registered source slot",
                    ));
                }
            }
            HistoryKeySelector::EpochRoot {
                root_context,
                root_ref,
                closed_epoch_cut,
            } => {
                require_closed_epoch(
                    conn,
                    &group.value,
                    root_context,
                    root_ref,
                    closed_epoch_cut,
                    &grant.history_cut,
                    &readers,
                )
                .await?;
            }
        }
    }
    request
        .validate_at(
            original.event.created_at,
            chrono::Utc::now().max(transaction.commit.committed_at),
        )
        .map_err(|error| refused(error.to_string()))?;
    Ok(())
}

async fn require_closed_epoch(
    conn: &mut AsyncPgConnection,
    group: &arkret_wire::MlsGroupValue,
    context: &arkret_models_crypto::ContentRootContext,
    root: &arkret_wire::Hash,
    closed: &arkret_wire::CommittedEventRef,
    cut: &arkret_wire::CommittedEventRef,
    readers: &[&arkret_wire::ActorId],
) -> PersistenceResult<()> {
    if context.effective_scope != group.effective_scope
        || context.genesis_event_ref != group.genesis_event_ref
        || context.cipher_suite != group.cipher_suite.as_str()
        || context.epoch >= group.epoch
        || closed.stream_ref != cut.stream_ref
        || closed.stream_position > cut.stream_position
    {
        return Err(refused(
            "history root requires an entirely authorized closed original epoch",
        ));
    }
    let base = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &context.group_state_ref,
    )
    .await?
    .ok_or_else(|| refused("history epoch original is unavailable"))?;
    let closure =
        crate::committed_disclosure::accepted_full_event_in_connection(conn, &closed.event_id)
            .await?
            .ok_or_else(|| refused("history epoch closure original is unavailable"))?;
    let transition = closure
        .event
        .as_mls_commit()
        .map_err(|error| refused(error.to_string()))?;
    if !exact_reference(&closure, closed)
        || closure.event.scope_ref != context.effective_scope
        || transition.base_group_state_ref() != &context.group_state_ref
        || transition.base_epoch() != context.epoch
        || transition.next_epoch()
            != context
                .epoch
                .checked_add(1)
                .ok_or_else(|| refused("history epoch overflow"))?
        || base.commit.stream_ref != cut.stream_ref
        || base.commit.stream_position >= closed.stream_position
    {
        return Err(refused(
            "history closure does not close the selected exact epoch",
        ));
    }
    if (context.epoch == 0
        && (base.event.kind != EventKind::MlsGenesis
            || base.event.event_id != context.genesis_event_ref))
        || (context.epoch != 0
            && base
                .event
                .as_mls_commit()
                .map_err(|error| refused(error.to_string()))?
                .next_epoch()
                != context.epoch)
    {
        return Err(refused(
            "history epoch base differs from its public original",
        ));
    }
    let strategy = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &context.backup_strategy_ref,
    )
    .await?
    .ok_or_else(|| refused("history epoch backup strategy original is unavailable"))?;
    if strategy.event.realm_id != *context.effective_scope.realm_id()
        || strategy
            .event
            .as_realm_create()
            .map_err(|error| refused(error.to_string()))?
            .object
            .initial_encryption_backup_strategy
            != context.encryption_backup_strategy
    {
        return Err(refused(
            "history epoch backup strategy differs from its original",
        ));
    }
    for reader in readers {
        let floor = crate::account_content_delivery::export_floor_in_connection(
            conn,
            &cut.stream_ref,
            reader,
            true,
        )
        .await?
        .ok_or_else(|| refused("history epoch reader has no current interval"))?;
        if floor > base.commit.stream_position {
            return Err(refused(
                "a partial epoch may receive only selected content keys",
            ));
        }
    }
    #[derive(QueryableByName)]
    struct SourceRow {
        #[diesel(sql_type = Jsonb)]
        envelope: serde_json::Value,
        #[diesel(sql_type = Jsonb)]
        commit_json: serde_json::Value,
    }
    // Read the complete retained interval, not a presentation page. A later
    // original still using this epoch prevents proving that it was closed.
    let rows = sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.stream_key=$1 AND c.stream_position >= $2 AND e.state='committed' ORDER BY c.stream_position")
        .bind::<Text,_>(crate::authority_commit::stream_key(&cut.stream_ref)?)
        .bind::<BigInt,_>(i64::try_from(base.commit.stream_position).map_err(PersistenceError::database)?)
        .get_results::<SourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut referenced = false;
    for row in rows {
        let source = arkret_wire::CommittedEventFullView {
            event: serde_json::from_value(row.envelope).map_err(PersistenceError::database)?,
            commit: serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?,
        };
        let slots = source
            .event
            .event_content_envelopes()
            .map_err(|error| refused(error.to_string()))?;
        let mut protected = false;
        for slot in slots {
            let arkret_models_crypto::EncryptedEnvelopeEncryptionContext::EpochContent {
                epoch,
                group_state_ref,
                root_ref,
                protection,
                ..
            } = slot.envelope.encryption_context;
            if epoch == context.epoch && group_state_ref == context.group_state_ref {
                protected = true;
                referenced |= root_ref == *root || protection.root_refs.contains(root);
            }
        }
        for (path, block) in arkret_event_draft::event_plain_content_blocks(&source.event)
            .map_err(|error| refused(error.to_string()))?
        {
            for (_, descriptor) in arkret_event_draft::history_attachment_slots(&block, &path)
                .map_err(|error| refused(error.to_string()))?
            {
                if descriptor
                    .key_ref()
                    .group_state_ref
                    .event_id()
                    .map_err(|error| refused(error.to_string()))?
                    == context.group_state_ref
                {
                    protected = true;
                }
            }
        }
        if protected {
            if source.commit.stream_position >= closed.stream_position {
                return Err(refused(
                    "history epoch has a source after its claimed closure",
                ));
            }
            require_source_read(conn, &source, &context.effective_scope, cut, readers).await?;
        }
    }
    if !referenced {
        return Err(refused(
            "history root has no authenticated original content reference",
        ));
    }
    Ok(())
}
