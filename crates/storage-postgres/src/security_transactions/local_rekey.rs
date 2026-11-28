//! Atomic admission of a local Human replacement's two RFC transitions.
use arkret_models_crypto::ContentRecoveryInventory;
use arkret_wire::{MlsWelcomeRecipientEndpoint, ScopeRef};
use coland_storage::{
    AuthorityCommitTransaction, MlsStateInstallation, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Binary, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension as _, RunQueryDsl as _};
use serde_json::json;

use super::{content_recovery_preparation, content_recovery_source};
use crate::{AsyncPgConnection, JsonPayloadRow};

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: local recovery {detail}"))
}

#[derive(QueryableByName)]
struct Inventory {
    #[diesel(sql_type=Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type=Text)]
    blob_ref: String,
}

/// Called in the winning Event transaction, after original Device signature
/// verification and before changing the current public tree or leaf bindings.
pub(crate) async fn accept(
    conn: &mut AsyncPgConnection,
    tx: &AuthorityCommitTransaction,
    state: &MlsStateInstallation,
) -> PersistenceResult<()> {
    let event = &tx.event;
    let source = state
        .recovery_source
        .as_ref()
        .ok_or_else(|| invalid("requires the original native source"))?;
    let a = &source.attestation;
    let fact = tx
        .producer_signer_fact
        .as_ref()
        .ok_or_else(|| invalid("has no original Device fact"))?;
    source
        .validate_original_binding(event, tx.commit.committed_at, fact)
        .map_err(invalid)?;
    arkret_identity::content_scope_cleanup::verify_mls_recovery_source(source).map_err(invalid)?;
    arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
        event,
        fact,
        event.realm_id.digest_suite_code().digest_suite(),
    )
    .map_err(invalid)?;
    let account = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("requires a Human"))?;
    let MlsWelcomeRecipientEndpoint::Device { device_id } = &a.replacement.endpoint else {
        return Err(invalid("requires a Device"));
    };
    if event.executed_by.is_some()
        || event.authorization_ref.is_some()
        || tx.expected_authority.service_id != account.station_id
        || !matches!(event.scope_ref, ScopeRef::Realm { .. })
        || !crate::content_recovery_fence::locked_active(conn, &event.actor_id).await?
    {
        return Err(invalid("has no local recovery obligation"));
    }
    let auth = &a.replacement.authorization_event_ref;
    let active = sql_query(
        "SELECT i.canonical_bytes,i.blob_ref
         FROM content_recovery_episodes e
         JOIN content_recovery_inventory_blobs i ON i.blob_ref=e.inventory_blob_ref
         AND i.authorization_event_ref=e.authorization_event_ref
         WHERE e.authorization_event_ref=$1
         AND e.actor_id=$2
         AND e.replacement=$3
         AND e.state='prepared'
         AND e.security_completed_at IS NULL
         AND i.inventory_digest=$4
         AND NOT EXISTS(SELECT 1
         FROM content_recovery_census_sources p
         WHERE p.authorization_event_ref=e.authorization_event_ref
         AND p.source_kind='predecessor')
         FOR UPDATE OF e",
    )
    .bind::<Text, _>(auth.as_str())
    .bind::<Jsonb, _>(json!(event.actor_id))
    .bind::<Jsonb, _>(json!(a.replacement))
    .bind::<Text, _>(a.inventory_digest.as_str())
    .get_result::<Inventory>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| invalid("has no exact prepared inventory"))?;
    let inv: ContentRecoveryInventory =
        serde_json::from_slice(&active.canonical_bytes).map_err(invalid)?;
    if inv.actor_id != event.actor_id
        || inv.replacement != a.replacement
        || &inv.authorization_event_ref != auth
        || arkret_crypto::content_history::recovery_inventory_digest(&inv).map_err(invalid)?
            != a.inventory_digest
        || arkret_canonical::canonical_json_bytes(&inv).map_err(invalid)? != active.canonical_bytes
        || active.blob_ref
            != format!(
                "ak:blob:sha256:{}",
                arkret_canonical::sha256_hex(&active.canonical_bytes)
            )
    {
        return Err(invalid("private inventory original differs"));
    }
    let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        account,
        device_id,
        chrono::Utc::now(),
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?
    .ok_or_else(|| invalid("missing current Device"))?;
    if cut.admission() != arkret_wire::AccountDeviceRevocationAdmissionDecision::Allow
        || cut
            .authority
            .authorization
            .as_ref()
            .is_none_or(|grant| grant.event_id != *auth)
    {
        return Err(invalid("replacement no longer current"));
    }
    let pcr = cut.authority.realm_id.clone();
    let completion =
        content_recovery_source::native_completion(conn, account, device_id, cut).await?;
    if completion.device_authorization_event_ref != inv.pcr_cut {
        return Err(invalid("changed native completion"));
    }
    let (original, authorization_commit) =
        content_recovery_source::original_in_scope(conn, auth, &ScopeRef::realm(pcr.clone()))
            .await?;
    if fact
        .as_account_device()
        .is_none_or(|f| f.accepted_at != authorization_commit.committed_at)
        || a.attested_at < authorization_commit.committed_at
        || content_recovery_preparation::replacement(account, &original)? != a.replacement
    {
        return Err(invalid("changed replacement"));
    }
    if event.realm_id == pcr {
        crate::content_endpoint_bindings::home_human_device_producer(conn, tx, None).await?;
    } else if !crate::scope_access::scope_member_in_connection(
        conn,
        &event.realm_id,
        &event.scope_ref,
        &event.actor_id,
    )
    .await?
    {
        return Err(invalid("Actor is no longer joined"));
    }
    let entry = inv
        .entries
        .iter()
        .find(|entry| entry.effective_scope == event.scope_ref)
        .ok_or_else(|| invalid("scope absent from inventory"))?;
    let key = crate::mls_group_current_states::scope_key(&event.scope_ref)?;
    let group = crate::mls_group_current_states::locked_group(conn, &key)
        .await?
        .ok_or_else(|| invalid("missing accepted group"))?;
    if group.value.genesis_event_ref != entry.genesis_event_ref
        || group.value.epoch != a.previous_epoch
        || group.value.current_mls_commit_event_ref != a.base_group_state_ref
    {
        return Err(invalid("accepted base differs"));
    }
    let group_id = event.scope_ref.canonical_mls_group_id().map_err(invalid)?;
    let previous = arkret_mls::MlsPublicGroupTracker::restore(
        &group.public_state,
        group_id.as_str(),
        group.value.epoch,
    )
    .map_err(invalid)?
    .leaves()
    .map_err(invalid)?;
    let next = arkret_mls::MlsPublicGroupTracker::restore(
        &state.public_state,
        group_id.as_str(),
        state.epoch,
    )
    .map_err(invalid)?
    .leaves()
    .map_err(invalid)?;
    let replacement = |leaf: &arkret_mls::MlsPublicEndpointLeaf| {
        leaf.actor_id == event.actor_id
            && leaf.signature_key.as_str() == a.replacement.signature_key_base64url
    };
    let mut retained = previous.clone();
    let step = if a.base_group_state_ref == entry.base_group_state_ref
        && a.previous_epoch == entry.epoch
    {
        if previous.iter().any(replacement)
            || !next.iter().any(replacement)
            || next.len() != previous.len() + 1
            || !previous.iter().all(|leaf| next.contains(leaf))
            || !state.consumed_proposals.is_empty()
        {
            return Err(invalid("External Commit changed existing leaves"));
        }
        "external"
    } else {
        let winner = sql_query(
            "SELECT to_jsonb(event_ref) AS payload
         FROM content_recovery_group_commits
         WHERE authorization_event_ref=$1
         AND scope_key=$2
         AND step='external'",
        )
        .bind::<Text, _>(auth.as_str())
        .bind::<Text, _>(&key)
        .get_result::<JsonPayloadRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if winner
            .and_then(|row| row.payload.as_str().map(str::to_owned))
            .as_deref()
            != Some(a.base_group_state_ref.as_str())
            || entry.epoch.checked_add(1) != Some(a.previous_epoch)
            || !previous.iter().any(replacement)
            || state
                .consumed_proposals
                .iter()
                .any(|p| !matches!(p.proposal_type, 3 | 7))
        {
            return Err(invalid("cleanup differs from the accepted External Commit"));
        }
        for old in &entry.old_leaves {
            let binding = sql_query(
                "SELECT binding AS payload
         FROM mls_endpoint_current_bindings
         WHERE scope_key=$1
         AND leaf_index=$2
         AND current_event_ref=$3
         AND binding=$4
         FOR SHARE",
            )
            .bind::<Text, _>(&key)
            .bind::<diesel::sql_types::BigInt, _>(i64::from(old.leaf_index))
            .bind::<Text, _>(a.base_group_state_ref.as_str())
            .bind::<Jsonb, _>(json!(old.endpoint))
            .get_result::<JsonPayloadRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            if binding.is_none()
                || !previous.iter().any(|l| {
                    l.leaf_index == old.leaf_index
                        && l.actor_id == event.actor_id
                        && l.signature_key.as_str() == old.endpoint.signature_key_base64url
                })
            {
                return Err(invalid(
                    "inventory leaf differs from accepted endpoint provenance",
                ));
            }
            retained.retain(|l| l.leaf_index != old.leaf_index);
        }
        if next != retained || !next.iter().any(replacement) {
            return Err(invalid(
                "cleanup did not remove exactly the inventoried leaves",
            ));
        }
        "remove"
    };
    sql_query(
        "INSERT INTO content_recovery_group_commits(authorization_event_ref,scope_key,step,event_ref,commit_id,recovery_source,producer_signer_fact)
         VALUES($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind::<Text, _>(auth.as_str())
    .bind::<Text, _>(&key)
    .bind::<Text, _>(step)
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(tx.commit.commit_id.as_str())
    .bind::<Binary, _>(arkret_canonical::canonical_json_bytes(source).map_err(invalid)?)
    .bind::<Binary, _>(arkret_canonical::canonical_json_bytes(fact).map_err(invalid)?)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn is_accepted_replacement(
    conn: &mut AsyncPgConnection,
    source: &arkret_wire::EventId,
    endpoint: &arkret_models_crypto::ContentEndpoint,
) -> PersistenceResult<bool> {
    let row = sql_query(
        "SELECT to_jsonb(c.event_ref) AS payload
         FROM content_recovery_group_commits c
         JOIN content_recovery_episodes e USING(authorization_event_ref)
         WHERE c.event_ref=$1
         AND c.step='external'
         AND e.replacement=$2
         AND e.security_completed_at IS NULL",
    )
    .bind::<Text, _>(source.as_str())
    .bind::<Jsonb, _>(json!(endpoint))
    .get_result::<JsonPayloadRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    Ok(row.is_some())
}

/// A confirmed scope remains closed to application traffic until its own
/// accepted removal has an adequate, independently admitted root package.
pub(crate) async fn require_sendable(
    conn: &mut AsyncPgConnection,
    scope: &ScopeRef,
) -> PersistenceResult<()> {
    let key = crate::mls_group_current_states::scope_key(scope)?;
    let row = sql_query(
        "SELECT to_jsonb(e.authorization_event_ref) AS payload
         FROM content_recovery_episodes e
         JOIN content_recovery_census_sources s USING(authorization_event_ref)
         WHERE s.effective_scope=$1
         AND e.security_completed_at IS NULL
         AND NOT EXISTS(SELECT 1
         FROM content_recovery_group_commits c
         WHERE c.authorization_event_ref=e.authorization_event_ref
         AND c.scope_key=$2
         AND c.scope_cleanup IS NOT NULL)
         LIMIT 1
         FOR SHARE OF e",
    )
    .bind::<Jsonb, _>(json!(scope))
    .bind::<Text, _>(&key)
    .get_result::<JsonPayloadRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if row.is_some() {
        return Err(coland_storage::MlsSendGateRefusal::EpochUpdateRequired.into_conflict());
    }
    Ok(())
}

pub(crate) async fn finish_root(
    conn: &mut AsyncPgConnection,
    backup: &arkret_models_crypto::KeyBackup,
) -> PersistenceResult<()> {
    let Some(auth) = &backup.signature_proof.device_authorize_event_id else {
        return Ok(());
    };
    if backup.encryption.recipient_method
        != arkret_models_crypto::KeyBackupRecipientMethod::RecoveryPublicKey
        || backup.expires_at.flatten().is_some()
    {
        return Ok(());
    }
    for item in &backup.contents {
        let (Some(root), Some(ctx)) = (&item.root_ref, &item.root_context) else {
            continue;
        };
        let key = crate::mls_group_current_states::scope_key(&ctx.effective_scope)?;
        let row = sql_query(
            "SELECT c.commit_json AS payload
         FROM content_recovery_group_commits r
         JOIN realm_commits c USING(commit_id)
         JOIN content_recovery_episodes e USING(authorization_event_ref)
         WHERE r.step='remove'
         AND r.scope_cleanup IS NULL
         AND r.event_ref=$1
         AND r.scope_key=$2
         AND e.authorization_event_ref=$3
         AND e.actor_id=$4
         AND e.security_completed_at IS NULL
         FOR UPDATE OF r",
        )
        .bind::<Text, _>(ctx.group_state_ref.as_str())
        .bind::<Text, _>(&key)
        .bind::<Text, _>(auth.as_str())
        .bind::<Jsonb, _>(json!(backup.actor_id))
        .get_result::<JsonPayloadRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        let Some(row) = row else { continue };
        crate::key_backup_history::recipient(conn, backup).await?;
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(row.payload).map_err(invalid)?;
        let group = crate::mls_group_current_states::locked_group(conn, &key)
            .await?
            .ok_or_else(|| invalid("missing root base"))?;
        if group.value.epoch != ctx.epoch
            || group.value.current_mls_commit_event_ref != commit.event_ref
        {
            continue;
        }
        let declaration = crate::content_dependencies::original_event(
            conn,
            &ctx.effective_scope.realm_id().event_id(),
        )
        .await?;
        crate::content_dependencies::validate_root_basis(conn, ctx, &group.value, &declaration)
            .await?;
        let tr = arkret_mls::MlsPublicGroupTracker::restore(
            &group.public_state,
            ctx.effective_scope
                .canonical_mls_group_id()
                .map_err(invalid)?
                .as_str(),
            ctx.epoch,
        )
        .map_err(invalid)?;
        if !matches!(tr.leaves().map_err(invalid)?.as_slice(),[leaf] if leaf.actor_id==backup.actor_id)
        {
            continue;
        }
        let cleanup = arkret_models_crypto::ContentScopeCleanup::Rekeyed {
            effective_scope: ctx.effective_scope.clone(),
            genesis_event_ref: ctx.genesis_event_ref.clone(),
            winning_commit: arkret_wire::CommittedEventRef {
                event_id: commit.event_ref,
                commit_id: commit.commit_id,
                stream_ref: commit.stream_ref,
                stream_position: commit.stream_position,
            },
            remaining_old_leaf_count: 0,
            root_refs: vec![root.clone()],
            backup_refs: vec![backup.backup_id.clone()],
        };
        sql_query(
            "UPDATE content_recovery_group_commits SET scope_cleanup=$1
             WHERE event_ref=$2 AND scope_cleanup IS NULL",
        )
        .bind::<Jsonb, _>(json!(cleanup))
        .bind::<Text, _>(ctx.group_state_ref.as_str())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    }
    Ok(())
}

/// Limit the Human PCR fact to its private MLS recovery originals. Ordinary
/// private history retains its own signer contract. The accepting unit repeats
/// the complete inventory, native source, actual RFC and final authority checks.
pub(crate) async fn prepared_pcr_signer(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> PersistenceResult<bool> {
    use arkret_event_draft::EventPayloadExt as _;
    if event.kind != arkret_wire::EventKind::MlsCommit
        || event.executed_by.is_some()
        || event.authorization_ref.is_some()
        || event.scope_ref != ScopeRef::realm(event.realm_id.clone())
    {
        return Ok(false);
    }
    let payload = event.as_mls_commit().map_err(invalid)?;
    let Some(binding) = payload.recovery_binding() else {
        return Ok(false);
    };
    if binding.replacement.actor_id != event.actor_id {
        return Ok(false);
    }
    let row = sql_query(
        "SELECT i.canonical_bytes,i.blob_ref
        FROM content_recovery_episodes e JOIN content_recovery_inventory_blobs i
          ON i.blob_ref=e.inventory_blob_ref AND i.authorization_event_ref=e.authorization_event_ref
        WHERE e.state='prepared' AND e.security_completed_at IS NULL AND e.authorization_event_ref=$1
          AND e.actor_id=$2 AND e.replacement=$3 AND i.inventory_digest=$4",
    )
    .bind::<Text, _>(binding.authorization_event_ref.as_str())
    .bind::<Jsonb, _>(json!(event.actor_id))
    .bind::<Jsonb, _>(json!(binding.replacement))
    .bind::<Text, _>(binding.inventory_digest.as_str())
    .get_result::<Inventory>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(row) = row else { return Ok(false) };
    let inventory: ContentRecoveryInventory =
        serde_json::from_slice(&row.canonical_bytes).map_err(invalid)?;
    Ok(inventory.pcr_cut.stream_ref
        == (arkret_wire::CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        && inventory.replacement == binding.replacement
        && inventory
            .entries
            .iter()
            .any(|e| e.effective_scope == event.scope_ref)
        && arkret_crypto::content_history::recovery_inventory_digest(&inventory)
            .map_err(invalid)?
            == binding.inventory_digest)
}

pub(crate) fn private_pcr_fact(
    event: &arkret_wire::Event,
    fact: &arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact,
) -> bool {
    event.kind == arkret_wire::EventKind::MlsCommit
        && event.payload.contains_key("recovery_binding")
        && fact.key.authorization_ref.stream_ref.realm_id() == &event.realm_id
}
