//! The `mls_group` typed current at the RealmCommit cut.
//!
//! One row per MLS effective scope (encryption-and-audit.md §2.5). The scope's
//! accepted `ak.mls.genesis` creates it (§5.1), each winning `ak.mls.commit`
//! merges its epoch, current Commit ref and covered key-access revision, and
//! every membership change of the scope advances its current key-access
//! revision (§2.4.1). The accepting transaction of an MLS Event decides here,
//! under the Realm authority row lock, everything its admission depends on:
//! the actor's same-cut authorization, the exact current group the serving
//! layer verified the RFC 9420 public transition against, the key-access
//! revision the binding names, and every Welcome's claim ledger row, recipient
//! authorization and queue capacity. Any refusal rolls the whole Commit back.
//!
//! Realm and Circle groups use their exact membership and authority cut. Sidecar
//! groups need their own scope membership basis and stay closed.

use arkret_event_draft::{EventMetadataSendGateExt as _, EventPayloadExt as _};
use arkret_models_collaboration::events_payloads::MlsGenesisPayload;
use arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody;
use arkret_models_crypto::MlsCommitPayload;
use arkret_wire::{EventKind, MlsGroupCurrent, ScopeRef};
use coland_storage::{
    AuthorityCommitTransaction, ConflictCode, MlsGroupCurrentRecord, MlsGroupCurrentStore,
    PersistenceError, PersistenceResult,
};
use diesel::sql_types::{BigInt, Binary, Integer, Jsonb, Nullable, Text, Timestamptz};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

use crate::{OptionalExtension, PgPool, QueryableByName, async_trait, ids, pg_conn, sql_query};

pub struct PgMlsGroupCurrentStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct GroupRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type = Binary)]
    public_state: Vec<u8>,
}

#[derive(QueryableByName)]
struct HistoryAccessRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct ClaimLedgerRow {
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    claim_expires_at_unix_ms: Option<i64>,
}

#[derive(QueryableByName)]
struct EventPkRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}

#[derive(QueryableByName)]
struct RosterOutboxRow {
    #[diesel(sql_type = Text)]
    attestation_digest: String,
    #[diesel(sql_type = Jsonb)]
    request_json: serde_json::Value,
}

#[derive(QueryableByName)]
struct ClaimOutcomeRow {
    #[diesel(sql_type = Nullable<Jsonb>)]
    outcome: Option<serde_json::Value>,
}

fn refused(code: ConflictCode, detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("{code}: {detail}"))
}

fn failed_precondition(detail: impl std::fmt::Display) -> PersistenceError {
    refused(ConflictCode::FailedPrecondition, detail)
}

fn binding_mismatch(detail: impl std::fmt::Display) -> PersistenceError {
    refused(ConflictCode::GovernanceBindingMismatch, detail)
}

/// The primary key of one scope: the canonical JSON of its `ScopeRef`.
pub(crate) fn scope_key(scope: &ScopeRef) -> PersistenceResult<String> {
    String::from_utf8(
        arkret_canonical::canonical_json_bytes(scope).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)
}

fn position(value: u64) -> PersistenceResult<i64> {
    i64::try_from(value).map_err(|_| {
        PersistenceError::SchemaViolation("MLS group stream position exceeds BIGINT".to_owned())
    })
}

fn decode_row(row: GroupRow) -> PersistenceResult<MlsGroupCurrentRecord> {
    let invalid = |what: &str, error: &dyn std::fmt::Display| {
        PersistenceError::Internal(format!("stored mls_group {what} is invalid: {error}"))
    };
    Ok(MlsGroupCurrentRecord {
        realm_id: arkret_wire::RealmId::new(row.realm_id)
            .map_err(|error| invalid("Realm id", &error))?,
        value: serde_json::from_value(row.value).map_err(|error| invalid("value", &error))?,
        current_commit_id: arkret_wire::RealmCommitId::new(row.current_commit_id)
            .map_err(|error| invalid("covering Commit id", &error))?,
        current_stream_position: u64::try_from(row.current_stream_position)
            .map_err(|error| invalid("covering stream position", &error))?,
        public_state: row.public_state,
    })
}

pub(crate) async fn locked_group(
    conn: &mut AsyncPgConnection,
    key: &str,
) -> PersistenceResult<Option<MlsGroupCurrentRecord>> {
    sql_query(
        "SELECT realm_id,current_commit_id,current_stream_position,value,public_state \
         FROM mls_group_current_results WHERE scope_key=$1 FOR UPDATE",
    )
    .bind::<Text, _>(key)
    .get_result::<GroupRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(decode_row)
    .transpose()
}

async fn write_group(
    conn: &mut AsyncPgConnection,
    key: &str,
    realm_id: &arkret_wire::RealmId,
    value: &MlsGroupCurrent,
    public_state: &[u8],
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let group_id = value
        .effective_scope
        .canonical_mls_group_id()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    sql_query(
        "INSERT INTO mls_group_current_results \
         (realm_id,scope_key,mls_group_id,current_commit_id,current_stream_position,value,public_state,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
         ON CONFLICT (scope_key) DO UPDATE SET \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value, public_state=EXCLUDED.public_state, updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(key)
    .bind::<Text, _>(group_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position(commit.stream_position)?)
    .bind::<Jsonb, _>(serde_json::to_value(value).map_err(PersistenceError::database)?)
    .bind::<Binary, _>(public_state)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

/// Install the transition of an accepted `ak.mls.genesis` or `ak.mls.commit`
/// and queue every Welcome it carries, after its Event and RealmCommit were
/// written in the same transaction.
pub(crate) async fn commit_mls_group_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    prepared: Option<&coland_storage::EventApprovalCommit>,
    forwarded: Option<&coland_storage::ForwardedManagedActorSource>,
) -> PersistenceResult<()> {
    let event = &transaction.event;
    if !matches!(event.kind, EventKind::MlsGenesis | EventKind::MlsCommit) {
        return Ok(());
    }
    let commit = &transaction.commit;
    let installation = transaction.mls_state.as_ref().ok_or_else(|| {
        PersistenceError::SchemaViolation(
            "an MLS Event commits only with its verified public transition".to_owned(),
        )
    })?;
    if !matches!(&event.scope_ref, ScopeRef::Realm { realm_id } | ScopeRef::Circle { realm_id, .. } | ScopeRef::Sidecar { realm_id, .. } if realm_id == &event.realm_id)
    {
        return Err(PersistenceError::Internal(
            "the MLS effective scope has no supported authority cut".to_owned(),
        ));
    }
    if !crate::moderation_report_current_results::scope_member_in_connection(
        conn,
        &event.realm_id,
        &event.scope_ref,
        &event.actor_id,
    )
    .await?
    {
        return Err(refused(
            ConflictCode::CapabilityDenied,
            "MLS author is not joined to the exact scope",
        ));
    }
    let controller_reconciliation = if let ScopeRef::Sidecar { sidecar_id, .. } = &event.scope_ref {
        crate::sidecar_access::cut_in_connection(conn, &event.realm_id, sidecar_id)
            .await?
            .is_some_and(|cut| event.actor_id.as_account_id() == Some(&cut.controller_account_id))
    } else {
        false
    };
    if !controller_reconciliation {
        crate::realm_authorization_cut::authorize_capability_gated_event_with_source(
            conn, event, commit, prepared, forwarded,
        )
        .await?;
    }
    let key = scope_key(&event.scope_ref)?;
    let current = locked_group(conn, &key).await?;
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let mut sidecar_cut = None;
    if let ScopeRef::Sidecar { sidecar_id, .. } = &event.scope_ref {
        let cut = crate::sidecar_access::cut_in_connection(conn, &event.realm_id, sidecar_id)
            .await?
            .ok_or_else(|| failed_precondition("Sidecar participant authority is unavailable"))?;
        let binding = match event.kind {
            EventKind::MlsGenesis => {
                serde_json::from_value::<MlsGenesisPayload>(payload.clone())
                    .map_err(PersistenceError::database)?
                    .governance_binding
            }
            _ => serde_json::from_value::<MlsCommitPayload>(payload.clone())
                .map_err(PersistenceError::database)?
                .governance_binding()
                .clone(),
        };
        sidecar_cut = Some(
            crate::sidecar_authority_cut::validate_mls_binding_in_connection(
                conn,
                &binding,
                &cut.controller_account_id,
            )
            .await?,
        );
    }
    let next = match event.kind {
        EventKind::MlsGenesis => {
            if current.is_some() {
                return Err(refused(
                    ConflictCode::MlsActivationIrreversible,
                    "the scope's MLS Genesis is already accepted",
                ));
            }
            require_since_join_history(conn, &event.scope_ref).await?;
            let payload: MlsGenesisPayload = serde_json::from_value(payload)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let binding = &payload.governance_binding;
            MlsGroupCurrent {
                effective_scope: event.scope_ref.clone(),
                genesis_event_ref: event.event_id.clone(),
                cipher_suite: payload.cipher_suite.clone(),
                current_mls_commit_event_ref: event.event_id.clone(),
                epoch: binding.next_epoch(),
                current_key_access_revision: binding.key_access_revision(),
                covered_key_access_revision: binding.key_access_revision(),
                public_tree_ref: payload.ratchet_tree_ref.clone(),
            }
        }
        _ => {
            let current = current
                .ok_or_else(|| failed_precondition("the scope has no accepted MLS Genesis"))?;
            let payload: MlsCommitPayload = serde_json::from_value(payload)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let binding = payload.governance_binding();
            let base = installation.base.as_ref().ok_or_else(|| {
                PersistenceError::SchemaViolation(
                    "an MLS Commit installs over one verified base".to_owned(),
                )
            })?;
            let group = &current.value;
            if group.current_mls_commit_event_ref != base.current_mls_commit_event_ref
                || group.epoch != base.epoch
                || payload.base_group_state_ref() != &group.current_mls_commit_event_ref
                || payload.base_epoch() != group.epoch
            {
                return Err(binding_mismatch(
                    "the Commit base is not the scope's current MLS group",
                ));
            }
            if binding.key_access_revision() != group.current_key_access_revision
                || payload.covers_key_access_revision() != group.current_key_access_revision
            {
                return Err(binding_mismatch(
                    "the Commit binding does not name the scope's current key-access revision",
                ));
            }
            MlsGroupCurrent {
                current_mls_commit_event_ref: event.event_id.clone(),
                epoch: payload.next_epoch(),
                covered_key_access_revision: payload.covers_key_access_revision(),
                public_tree_ref: installation
                    .public_blobs
                    .as_slice()
                    .first()
                    .ok_or_else(|| binding_mismatch("the Commit has no post-transition tree"))?
                    .blob_ref
                    .clone(),
                ..group.clone()
            }
        }
    };
    if next.epoch != installation.epoch {
        return Err(binding_mismatch(
            "the installed public state is not at the Commit's epoch",
        ));
    }
    if let Some(cut) = &sidecar_cut
        && !crate::sidecar_mls_readiness::tree_authorized_in_connection(
            conn,
            cut,
            &next,
            &installation.public_state,
            Some(transaction),
        )
        .await?
    {
        return Err(binding_mismatch(
            "the Sidecar post-transition tree retains an unauthorized endpoint",
        ));
    }
    // encryption-and-audit.md section 2.4.1: while a Circle tree holds a leaf
    // of an actor that is no longer an effective Circle member, only a Commit
    // whose post-state tree drops every such leaf proceeds with an Add
    // (RFC 9420 proposal type 1); every Add target must itself be effective.
    if event.kind == EventKind::MlsCommit
        && installation
            .consumed_proposals
            .iter()
            .any(|proposal| proposal.proposal_type == 1)
        && circle_holds_invalid_owner(conn, &event.scope_ref, &installation.member_principals)
            .await?
    {
        return Err(coland_storage::MlsSendGateRefusal::EpochUpdateRequired.into_conflict());
    }
    write_group(
        conn,
        &key,
        &event.realm_id,
        &next,
        &installation.public_state,
        commit,
    )
    .await?;
    if event.kind == EventKind::MlsCommit {
        freeze_consumed_proposals(conn, transaction, installation, &key).await?;
    }
    store_public_blobs(conn, event, &installation.public_blobs, commit).await?;
    crate::direct_conversation_admission::record_group_state_in_connection(
        conn,
        event,
        &installation.member_principals,
    )
    .await?;
    if transaction.welcomes.is_empty() {
        return Ok(());
    }
    let token = ids::parse_event_id(event.event_id.as_str()).ok_or_else(|| {
        PersistenceError::SchemaViolation("MLS Commit Event id is not canonical".to_owned())
    })?;
    let event_pk = sql_query("SELECT pk FROM canonical_events WHERE id=$1")
        .bind::<diesel::sql_types::Binary, _>(token.to_vec())
        .get_result::<EventPkRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .pk;
    for welcome in &transaction.welcomes {
        require_joined_recipient(
            conn,
            &event.realm_id,
            &event.scope_ref,
            &welcome.delivery.recipient_actor_id,
        )
        .await?;
        // A remote recipient's Welcome rides the Commit's committed
        // replication; `crate::realm_fanout` writes it into that intent.
        let Some(claim) = welcome.claim.as_ref() else {
            continue;
        };
        require_native_welcome_target(conn, welcome).await?;
        require_live_claim(conn, claim, commit.committed_at).await?;
        crate::devices::enqueue_mls_welcome_in_connection(
            conn,
            &welcome.delivery,
            event_pk,
            commit.committed_at,
            Some(transaction.recipient_queue_capacity),
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
        bind_claim_welcome_in_connection(conn, claim, &welcome.delivery).await?;
        // Storage queue fixtures can exercise a Commit without any consumed
        // Proposal. A real Add is always present in the verified transition.
        if installation.consumed_proposals.is_empty() {
            continue;
        }
        let witness = welcome.roster_witness.as_ref().ok_or_else(|| {
            failed_precondition("same-Station Add has no signed historical attestation")
        })?;
        let resolution = witness.local_attestor_resolution.as_ref().ok_or_else(|| {
            failed_precondition("same-Station Add has no historical Station resolution")
        })?;
        if witness.accepted_genesis_event_ref != next.genesis_event_ref {
            return Err(binding_mismatch("same-Station Add names another Genesis"));
        }
        let request: MlsAttestAddRequestBody =
            serde_json::from_slice(&witness.signed_attest_add_request_canonical_json)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let stored_claim = sql_query(
            "SELECT outcome FROM peer_keypackage_claims \
             WHERE source_id=$1 AND claim_request_id=$2 AND request_digest=$3 FOR UPDATE",
        )
        .bind::<Text, _>(&claim.source_id)
        .bind::<Text, _>(&claim.claim_request_id)
        .bind::<Text, _>(&claim.request_digest)
        .get_result::<ClaimOutcomeRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if stored_claim.and_then(|row| row.outcome)
            != Some(
                serde_json::to_value(&request.claim_outcome).map_err(PersistenceError::database)?,
            )
        {
            return Err(binding_mismatch(
                "same-Station Add differs from original claim outcome",
            ));
        }
        if arkret_canonical::canonical_json_bytes(&request).map_err(PersistenceError::database)?
            != witness.signed_attest_add_request_canonical_json
            || request.attestation.genesis_event_ref != next.genesis_event_ref
            || request.attestation.welcome_id != welcome.delivery.welcome_id
        {
            return Err(binding_mismatch(
                "same-Station Add witness differs from accepted facts",
            ));
        }
        crate::realm_fanout::freeze_welcomes_in_connection(
            conn,
            event,
            commit,
            &[&welcome.delivery],
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
        let verified = coland_storage::VerifiedMlsAddAuthorityAttestation {
            source_station_id: transaction.expected_authority.service_id.clone(),
            request,
            attestor_resolution: resolution.clone(),
        };
        crate::mls_roster_attest_add::install_in_connection(
            conn,
            &verified,
            &transaction.expected_authority.service_id,
        )
        .await?;
    }
    Ok(())
}

async fn freeze_consumed_proposals(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    installation: &coland_storage::MlsStateInstallation,
    key: &str,
) -> PersistenceResult<()> {
    let event = &transaction.event;
    let commit = &transaction.commit;
    for proposal in &installation.consumed_proposals {
        let before = proposal.target_before.as_ref();
        let after = proposal.target_after.as_ref();
        let before_actor = before
            .map(|leaf| serde_json::to_value(&leaf.actor_id))
            .transpose()
            .map_err(PersistenceError::database)?;
        let after_actor = after
            .map(|leaf| serde_json::to_value(&leaf.actor_id))
            .transpose()
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO mls_consumed_proposal_provenance \
             (realm_id,scope_key,commit_event_ref,commit_stream_position,epoch,consumed_proposal_ordinal,\
              proposal_type,proposal_wire,proposal_ref,sender_actor_id,sender_leaf_index,sender_signature_key,\
              target_before_actor_id,target_before_leaf_index,target_before_signature_key,\
              target_after_actor_id,target_after_leaf_index,target_after_signature_key,created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Text, _>(key)
        .bind::<Text, _>(event.event_id.as_str())
        .bind::<BigInt, _>(position(commit.stream_position)?)
        .bind::<BigInt, _>(position(installation.epoch)?)
        .bind::<BigInt, _>(position(proposal.ordinal)?)
        .bind::<Integer, _>(i32::from(proposal.proposal_type))
        .bind::<Binary, _>(&proposal.proposal_wire)
        .bind::<Binary, _>(&proposal.proposal_ref)
        .bind::<Jsonb, _>(
            serde_json::to_value(&proposal.sender_leaf.actor_id)
                .map_err(PersistenceError::database)?,
        )
        .bind::<BigInt, _>(i64::from(proposal.sender_leaf.leaf_index))
        .bind::<Text, _>(proposal.sender_leaf.signature_key.as_str())
        .bind::<Nullable<Jsonb>, _>(before_actor)
        .bind::<Nullable<BigInt>, _>(before.map(|leaf| i64::from(leaf.leaf_index)))
        .bind::<Nullable<Text>, _>(before.map(|leaf| leaf.signature_key.as_str()))
        .bind::<Nullable<Jsonb>, _>(after_actor)
        .bind::<Nullable<BigInt>, _>(after.map(|leaf| i64::from(leaf.leaf_index)))
        .bind::<Nullable<Text>, _>(after.map(|leaf| leaf.signature_key.as_str()))
        .bind::<Timestamptz, _>(commit.committed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    }
    Ok(())
}

/// encryption-and-audit.md §2.2 "跨站 recipient" and decision 0121: in the
/// replica transaction of an `ak.mls.commit`, queue each Welcome whose claim
/// the serving layer re-verified against this Station's own ledger, and bind
/// the claim to it. Each Welcome stands alone: one whose recipient is no
/// joined member here, whose claim is no longer live or already bound to
/// another Welcome, or whose endpoint cannot receive it is not queued, only
/// logged, and never blocks the replica. A Welcome already queued and bound
/// by an earlier attempt is left as it is. Replicated Welcomes count toward
/// but are never refused by the endpoint capacity.
pub(crate) async fn queue_replicated_welcomes_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    welcomes: &[coland_storage::VerifiedMlsWelcome],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if welcomes.is_empty() {
        return Ok(());
    }
    if event.kind != EventKind::MlsCommit {
        return Err(PersistenceError::SchemaViolation(
            "replicated Welcomes accompany only an ak.mls.commit".to_owned(),
        ));
    }
    let token = ids::parse_event_id(event.event_id.as_str()).ok_or_else(|| {
        PersistenceError::SchemaViolation("MLS Commit Event id is not canonical".to_owned())
    })?;
    let event_pk = sql_query("SELECT pk FROM canonical_events WHERE id=$1")
        .bind::<diesel::sql_types::Binary, _>(token.to_vec())
        .get_result::<EventPkRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| {
            PersistenceError::Internal("a replicated Commit holds no Event bytes".to_owned())
        })?
        .pk;
    for welcome in welcomes {
        // A refused Welcome must roll back its own queue/binding/outbox rows,
        // while the already accepted source Commit remains installed.
        let attempt = conn
            .transaction::<_, crate::PgTransactionError, _>(async move |conn| {
                queue_one_replicated_welcome(conn, event, commit, event_pk, welcome, at)
                    .await
                    .map_err(crate::PgTransactionError::from)
            })
            .await
            .map_err(crate::PgTransactionError::into_persistence);
        match attempt {
            Ok(()) => {}
            Err(PersistenceError::Conflict(detail) | PersistenceError::SchemaViolation(detail)) => {
                tracing::warn!(
                    welcome_id = %welcome.delivery.welcome_id.as_str(),
                    %detail,
                    "replicated MLS Welcome not queued"
                );
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn queue_one_replicated_welcome(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    event_pk: i64,
    welcome: &coland_storage::VerifiedMlsWelcome,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let delivery = &welcome.delivery;
    let claim = welcome.claim.as_ref().ok_or_else(|| {
        PersistenceError::Internal("a replicated Welcome carries its local claim".to_owned())
    })?;
    if delivery.commit_event_ref != event.event_id || delivery.realm_id != event.realm_id {
        return Err(PersistenceError::SchemaViolation(
            "a replicated Welcome names another Commit".to_owned(),
        ));
    }
    require_joined_recipient(
        conn,
        &event.realm_id,
        &event.scope_ref,
        &delivery.recipient_actor_id,
    )
    .await?;
    if claim_welcome_binding_in_connection(conn, delivery.keypackage_claim_ref.as_str())
        .await?
        .is_some()
    {
        bind_claim_welcome_in_connection(conn, claim, delivery).await?;
        return store_recipient_roster_outbox(conn, event, commit, welcome, at).await;
    }
    require_native_welcome_target(conn, welcome).await?;
    require_live_claim(conn, claim, at).await?;
    crate::devices::enqueue_mls_welcome_in_connection(conn, delivery, event_pk, at, None)
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
    bind_claim_welcome_in_connection(conn, claim, delivery).await?;
    store_recipient_roster_outbox(conn, event, commit, welcome, at).await?;
    if welcome.applet_device_scope_guard.is_some() {
        // Queue/outbox writers may wait while temporal sources expire. Refuse
        // only this delivery at the replica's existing savepoint.
        crate::boxed_future(|| require_native_welcome_target(conn, welcome)).await?;
    }
    Ok(())
}

async fn store_recipient_roster_outbox(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    welcome: &coland_storage::VerifiedMlsWelcome,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let Some(witness) = &welcome.roster_witness else {
        return Ok(());
    };
    let request: MlsAttestAddRequestBody =
        serde_json::from_slice(&witness.signed_attest_add_request_canonical_json)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    request
        .validate_claim_binding()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let exact_bytes =
        arkret_canonical::canonical_json_bytes(&request).map_err(PersistenceError::database)?;
    if exact_bytes != witness.signed_attest_add_request_canonical_json {
        return Err(PersistenceError::SchemaViolation(
            "MLS Add attestation outbox body is not canonical JSON".to_owned(),
        ));
    }
    let attestation = &request.attestation;
    let delivery = &welcome.delivery;
    let payload: MlsCommitPayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if attestation.realm_id != event.realm_id
        || attestation.effective_scope != event.scope_ref
        || attestation.mls_group_id
            != event
                .scope_ref
                .canonical_mls_group_id()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
        || attestation.genesis_event_ref != witness.accepted_genesis_event_ref
        || attestation.commit_event_ref != event.event_id
        || attestation.commit_stream_position != commit.stream_position
        || attestation.epoch != payload.next_epoch()
        || attestation.welcome_id != delivery.welcome_id
        || attestation.claim_id != delivery.keypackage_claim_ref
        || attestation.actor_id != delivery.recipient_actor_id
        || attestation.endpoint != delivery.recipient_endpoint
        || attestation.attestor_station_id != *delivery.recipient_actor_id.route_service_id()
    {
        return Err(PersistenceError::SchemaViolation(
            "MLS Add attestation differs from accepted Commit and Welcome".to_owned(),
        ));
    }
    #[derive(QueryableByName)]
    struct GenesisRefRow {
        #[diesel(sql_type = Text)]
        genesis_event_ref: String,
    }
    let key = scope_key(&event.scope_ref)?;
    let replica_genesis = sql_query(
        "SELECT genesis_event_ref FROM mls_replica_genesis_provenance \
         WHERE scope_key=$1 FOR SHARE",
    )
    .bind::<Text, _>(&key)
    .get_result::<GenesisRefRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let governance_genesis = sql_query(
        "SELECT value->>'genesis_event_ref' AS genesis_event_ref \
         FROM mls_group_current_results WHERE scope_key=$1 FOR SHARE",
    )
    .bind::<Text, _>(&key)
    .get_result::<GenesisRefRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if replica_genesis.is_none() && governance_genesis.is_none()
        || replica_genesis
            .as_ref()
            .is_some_and(|row| row.genesis_event_ref != attestation.genesis_event_ref.as_str())
        || governance_genesis
            .as_ref()
            .is_some_and(|row| row.genesis_event_ref != attestation.genesis_event_ref.as_str())
    {
        return Err(refused(
            ConflictCode::DuplicateConflict,
            "MLS Add attestation has no matching frozen group Genesis",
        ));
    }
    let digest =
        arkret_canonical::canonical_sha256(&request).map_err(PersistenceError::database)?;
    let request_json = serde_json::to_value(&request).map_err(PersistenceError::database)?;
    let existing = sql_query(
        "SELECT attestation_digest,request_json FROM mls_add_authority_attestation_outbox \
         WHERE commit_event_ref=$1 AND welcome_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(delivery.welcome_id.as_str())
    .get_result::<RosterOutboxRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if let Some(existing) = existing {
        return if existing.attestation_digest == digest && existing.request_json == request_json {
            Ok(())
        } else {
            Err(refused(
                ConflictCode::DuplicateConflict,
                "MLS Add attestation replay differs from frozen outbox",
            ))
        };
    }
    let claim = welcome.claim.as_ref().ok_or_else(|| {
        PersistenceError::SchemaViolation("MLS Add attestation lacks local claim".to_owned())
    })?;
    let Some(claim_row) = sql_query(
        "SELECT outcome FROM peer_keypackage_claims \
         WHERE source_id=$1 AND claim_request_id=$2 AND request_digest=$3 FOR UPDATE",
    )
    .bind::<Text, _>(&claim.source_id)
    .bind::<Text, _>(&claim.claim_request_id)
    .bind::<Text, _>(&claim.request_digest)
    .get_result::<ClaimOutcomeRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    else {
        return Err(failed_precondition(
            "MLS Add attestation original claim ledger row is unavailable",
        ));
    };
    if claim_row.outcome
        != Some(serde_json::to_value(&request.claim_outcome).map_err(PersistenceError::database)?)
    {
        return Err(refused(
            ConflictCode::DuplicateConflict,
            "MLS Add attestation outcome differs from original claim",
        ));
    }
    let inserted = sql_query(
        "INSERT INTO mls_add_authority_attestation_outbox \
         (attestor_station_id,realm_id,scope_key,mls_group_id,genesis_event_ref, \
          commit_event_ref,commit_stream_position,epoch,welcome_id,claim_id, \
          attestation_digest,request_json,created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(attestation.attestor_station_id.as_str())
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&key)
    .bind::<Text, _>(attestation.mls_group_id.as_str())
    .bind::<Text, _>(attestation.genesis_event_ref.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<BigInt, _>(position(commit.stream_position)?)
    .bind::<BigInt, _>(position(attestation.epoch)?)
    .bind::<Text, _>(delivery.welcome_id.as_str())
    .bind::<Text, _>(delivery.keypackage_claim_ref.as_str())
    .bind::<Text, _>(&digest)
    .bind::<Jsonb, _>(request_json)
    .bind::<Timestamptz, _>(at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(refused(
            ConflictCode::DuplicateConflict,
            "MLS Add attestation claim or Welcome is already frozen elsewhere",
        ));
    }
    Ok(())
}

/// The Welcome id a claim is bound to, if its Welcome was queued.
async fn claim_welcome_binding_in_connection(
    conn: &mut AsyncPgConnection,
    claim_id: &str,
) -> PersistenceResult<Option<String>> {
    #[derive(QueryableByName)]
    struct BoundRow {
        #[diesel(sql_type = Text)]
        welcome_id: String,
    }
    Ok(
        sql_query("SELECT welcome_id FROM keypackage_claim_welcome_bindings WHERE claim_id=$1")
            .bind::<Text, _>(claim_id)
            .get_result::<BoundRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(|row| row.welcome_id),
    )
}

/// device-lifecycle.md §9.2.3 (decision 0121): record, in the transaction
/// that queues `welcome`, the one Welcome binding of its claim on that
/// claim's ledger row. The same delivery replayed leaves the binding as it
/// is; any other delivery naming an already bound claim reuses the claim and
/// is `duplicate_conflict`.
pub(crate) async fn bind_claim_welcome_in_connection(
    conn: &mut AsyncPgConnection,
    claim: &coland_storage::MlsWelcomeClaimLedgerKey,
    welcome: &arkret_wire::MlsWelcomeDelivery,
) -> PersistenceResult<()> {
    #[derive(QueryableByName)]
    struct BindingRow {
        #[diesel(sql_type = Text)]
        source_id: String,
        #[diesel(sql_type = Text)]
        claim_request_id: String,
        #[diesel(sql_type = Text)]
        welcome_id: String,
        #[diesel(sql_type = Text)]
        welcome_digest: String,
        #[diesel(sql_type = Text)]
        commit_event_ref: String,
    }
    let digest = welcome
        .durable_receipt_digest()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    sql_query(
        "INSERT INTO keypackage_claim_welcome_bindings \
         (claim_id,source_id,claim_request_id,welcome_id,welcome_digest,commit_event_ref) \
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(welcome.keypackage_claim_ref.as_str())
    .bind::<Text, _>(&claim.source_id)
    .bind::<Text, _>(&claim.claim_request_id)
    .bind::<Text, _>(welcome.welcome_id.as_str())
    .bind::<Text, _>(digest.as_str())
    .bind::<Text, _>(welcome.commit_event_ref.as_str())
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let bound = sql_query(
        "SELECT source_id,claim_request_id,welcome_id,welcome_digest,commit_event_ref \
         FROM keypackage_claim_welcome_bindings WHERE claim_id=$1",
    )
    .bind::<Text, _>(welcome.keypackage_claim_ref.as_str())
    .get_result::<BindingRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let same = bound.is_some_and(|row| {
        row.source_id == claim.source_id
            && row.claim_request_id == claim.claim_request_id
            && row.welcome_id == welcome.welcome_id.as_str()
            && row.welcome_digest == digest.as_str()
            && row.commit_event_ref == welcome.commit_event_ref.as_str()
    });
    if !same {
        return Err(refused(
            ConflictCode::DuplicateConflict,
            "the KeyPackage claim is already bound to another Welcome",
        ));
    }
    Ok(())
}

/// Publish verified Genesis artifacts or the post-Commit tree together with
/// the accepted current. Public bytes are immutable and content-addressed;
/// updating current never rewrites the original Genesis artifacts.
async fn store_public_blobs(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    blobs: &[coland_storage::MlsPublicBlob],
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    for blob in blobs {
        sql_query(
            "INSERT INTO blobs \
             (id,sha256,media_type,filename,uploaded_by,realm_id,size_bytes, \
              storage_backend,storage_key,payload,legal_hold,redacted,visibility,created_at) \
             VALUES ($1,$2,'application/octet-stream',NULL,$3,$4,$5,$6,$7, \
                     '{\"encryption\":null}'::jsonb,FALSE,FALSE,'realm_bound',$8) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(blob.blob_ref.as_str())
        .bind::<Text, _>(&blob.sha256)
        .bind::<Text, _>(event.actor_id.signing_principal_id().as_str())
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<BigInt, _>(blob.size_bytes)
        .bind::<Text, _>(&blob.storage_backend)
        .bind::<Text, _>(&blob.storage_key)
        .bind::<Timestamptz, _>(commit.committed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    }
    Ok(())
}

/// realm-and-space.md §2.3.A: the first `ak.mls.genesis` of a Realm scope is
/// accepted only while its current `history_access` is `since_join`.
async fn require_since_join_history(
    conn: &mut AsyncPgConnection,
    scope: &ScopeRef,
) -> PersistenceResult<()> {
    // Sidecar has no editable history_access facet. Its independent MLS and
    // consumed endpoint admission establish its private security boundary.
    if matches!(scope, ScopeRef::Sidecar { .. }) {
        return Ok(());
    }
    let history = match scope {
        ScopeRef::Realm { realm_id } => sql_query("SELECT value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_history_access' FOR SHARE")
            .bind::<Text, _>(realm_id.as_str()).get_result::<HistoryAccessRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?,
        ScopeRef::Circle { realm_id, circle_id } => sql_query("SELECT value->'history_access' AS value FROM circle_current_results WHERE realm_id=$1 AND circle_id=$2 AND value->>'state'='active' FOR SHARE")
            .bind::<Text, _>(realm_id.as_str()).bind::<Text, _>(circle_id.as_str()).get_result::<HistoryAccessRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?,
        _ => None,
    };
    if history.as_ref().and_then(|row| row.value.as_str()) != Some("since_join") {
        return Err(failed_precondition(
            "MLS activation requires the scope history_access since_join",
        ));
    }
    Ok(())
}

/// A Welcome belongs to the exact scope's current membership intersection.
async fn require_joined_recipient(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    scope: &ScopeRef,
    recipient: &arkret_wire::ActorId,
) -> PersistenceResult<()> {
    if let ScopeRef::Sidecar { sidecar_id, .. } = scope {
        let Some(cut) =
            crate::sidecar_access::cut_in_connection(conn, realm_id, sidecar_id).await?
        else {
            return Err(failed_precondition(
                "Sidecar Welcome recipient authority is unavailable",
            ));
        };
        if recipient.as_account_id().is_some_and(|account| {
            account == &cut.controller_account_id
                || (account.station_id == cut.controller_account_id.station_id
                    && cut.desired_agent_ids.contains(&account.principal_id))
        }) {
            return Ok(());
        }
        return Err(failed_precondition(
            "Sidecar Welcome recipient is outside the desired roster",
        ));
    }
    if crate::moderation_report_current_results::scope_member_in_connection(
        conn, realm_id, scope, recipient,
    )
    .await?
    {
        Ok(())
    } else {
        Err(PersistenceError::Conflict(
            "failed_precondition: MLS Welcome recipient is not joined to its exact scope"
                .to_owned(),
        ))
    }
}

/// The claim ledger row a Welcome was verified against must still hold the
/// same request and a live claim (device-lifecycle.md, claim ledger rules).
/// A historical claim cannot authorize a new native Welcome after a scope
/// fence. Discover the immutable package from the original ledger, then check
/// its exact original Account/Device and all current sources at the held cut.
pub(crate) async fn require_native_welcome_target(
    conn: &mut AsyncPgConnection,
    welcome: &coland_storage::VerifiedMlsWelcome,
) -> PersistenceResult<()> {
    let claim = welcome
        .claim
        .as_ref()
        .ok_or_else(|| failed_precondition("local Welcome has no claim"))?;
    #[derive(QueryableByName)]
    struct Package {
        #[diesel(sql_type=Text)]
        keypackage_ref: String,
        #[diesel(sql_type=Nullable<Jsonb>)]
        effective_scope: Option<serde_json::Value>,
        #[diesel(sql_type=Nullable<BigInt>)]
        claim_expires_at_unix_ms: Option<i64>,
    }
    // Preserve the existing non-native verified ledger path. Native identity
    // is independent of a caller-supplied guard and survives Device revocation
    // and removal of unused material.
    let account = welcome
        .delivery
        .recipient_actor_id
        .as_account_id()
        .ok_or_else(|| failed_precondition("Welcome has no Account"))?;
    let native=sql_query("SELECT g.envelope AS value FROM principal_resolutions p JOIN canonical_events g ON g.envelope->>'event_id'=p.genesis_event_id WHERE p.principal_id=$1 AND p.station_id=$2 AND g.state='committed' AND g.envelope #>> '{payload,object,purpose}'='applet_managed_control'")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<HistoryAccessRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.is_some();
    let package=sql_query("SELECT p.keypackage_ref,p.effective_scope,l.claim_expires_at_unix_ms FROM peer_keypackage_claims l JOIN mls_key_packages p ON p.id=l.keypackage_id WHERE l.source_id=$1 AND l.claim_request_id=$2 AND l.request_digest=$3")
        .bind::<Text,_>(&claim.source_id).bind::<Text,_>(&claim.claim_request_id).bind::<Text,_>(&claim.request_digest)
        .get_result::<Package>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(package) = package else {
        if native || welcome.applet_device_scope_guard.is_some() {
            return Err(failed_precondition(
                "native Welcome original package is unavailable",
            ));
        }
        return Ok(());
    };
    let guard = match (&package.effective_scope, &welcome.applet_device_scope_guard) {
        (None, None) if !native => return Ok(()),
        (Some(_), Some(guard)) => guard,
        _ => {
            return Err(failed_precondition(
                "Welcome native package requires its exact current proof",
            ));
        }
    };
    if serde_json::to_value(&guard.effective_scope).map_err(PersistenceError::database)?
        != package.effective_scope.unwrap()
        || welcome.delivery.effective_scope != guard.effective_scope
        || welcome.delivery.recipient_actor_id
            != arkret_wire::ActorId::account(guard.authority.account_id.clone())
        || !matches!(&welcome.delivery.recipient_endpoint,arkret_wire::MlsWelcomeRecipientEndpoint::Device{device_id} if device_id==&guard.authority.device_id)
    {
        return Err(binding_mismatch(
            "Welcome differs from its native recipient proof",
        ));
    }
    // Local UOWs planned this PCR in their ordered current cut. A replica may
    // already hold its business cut: avoid an inverse-order wait and drop this
    // delivery at its savepoint if another transaction owns the PCR.
    sql_query(
        "SELECT to_jsonb(a) AS value FROM realm_authorities a WHERE realm_id=$1 FOR UPDATE NOWAIT",
    )
    .bind::<Text, _>(guard.authority.pcr_realm_id.as_str())
    .get_result::<HistoryAccessRow>(&mut *conn)
    .await
    .map_err(|error| match error {
        diesel::result::Error::DatabaseError(_, ref info)
            if info.message().contains("could not obtain lock") =>
        {
            PersistenceError::Conflict("temporarily_unavailable: native Welcome PCR is busy".into())
        }
        other => PersistenceError::database(other),
    })?;
    // All current cuts precede the package/ledger lock, as in claim and consume.
    crate::mls_keypackage_claim_admission::lock_cuts(conn, &[guard], &[]).await?;
    let row = crate::mls::key_package_for_delivery(conn, &package.keypackage_ref)
        .await?
        .ok_or_else(|| failed_precondition("Welcome original package disappeared"))?;
    let deadline = package
        .claim_expires_at_unix_ms
        .and_then(chrono::DateTime::from_timestamp_millis)
        .ok_or_else(|| failed_precondition("native Welcome has no original claim expiry"))?
        .min(guard.authority.expires_at);
    crate::boxed_future(|| {
        crate::mls_keypackage_claim_admission::require_target(conn, &row, guard, deadline)
    })
    .await
}

async fn require_live_claim(
    conn: &mut AsyncPgConnection,
    claim: &coland_storage::MlsWelcomeClaimLedgerKey,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let row = sql_query(
        "SELECT request_digest,state,claim_expires_at_unix_ms FROM peer_keypackage_claims \
         WHERE source_id=$1 AND claim_request_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(&claim.source_id)
    .bind::<Text, _>(&claim.claim_request_id)
    .get_result::<ClaimLedgerRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| failed_precondition("the Welcome's KeyPackage claim is not in the ledger"))?;
    if row.request_digest != claim.request_digest
        || !matches!(row.state.as_str(), "claimed" | "last_resort_claimed")
        || row
            .claim_expires_at_unix_ms
            .is_none_or(|expires| expires <= at.timestamp_millis())
    {
        return Err(failed_precondition(
            "the Welcome's KeyPackage claim is no longer live",
        ));
    }
    Ok(())
}

fn message_envelopes(
    content: Option<arkret_models_crypto::EncryptedEnvelope>,
    metadata: Option<arkret_models_crypto::EncryptedEnvelope>,
) -> PersistenceResult<Option<Vec<arkret_models_crypto::EncryptedEnvelope>>> {
    match (content, metadata) {
        (Some(content), metadata) => Ok(Some(std::iter::once(content).chain(metadata).collect())),
        (None, None) => Ok(None),
        (None, Some(_)) => Err(PersistenceError::SchemaViolation(
            "message encrypted_metadata requires encrypted_content".to_owned(),
        )),
    }
}

/// encryption-and-audit.md §2.5.2: the current MLS send gate of one accepted
/// `ak.message.create` / `.revise` or `ak.reaction.add` / `.remove`, decided
/// on the scope's `mls_group` row read in the accepting transaction. A
/// reaction's only encrypted carrier is its `encrypted_payload`
/// (strand-and-message.md §9.8.1). The unit already rechecked the actual
/// signer's endpoint authorization at the top of this same transaction, so a
/// revoked device or Agent is refused with its own code before any answer
/// here, and a revocation never advances the key-access revision (§2.4.1).
pub(crate) async fn require_mls_send_gate_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> PersistenceResult<()> {
    let envelopes = if let Some(metadata) = event
        .event_metadata_send_gate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
    {
        if metadata.user_metadata_present && !metadata.encrypted_metadata.is_empty() {
            return Err(PersistenceError::SchemaViolation(
                "metadata must not carry both plaintext fields and encrypted_metadata".to_owned(),
            ));
        }
        if !metadata.user_metadata_present && metadata.encrypted_metadata.is_empty() {
            return Ok(());
        }
        if metadata.encrypted_metadata.is_empty() {
            None
        } else {
            Some(metadata.encrypted_metadata)
        }
    } else {
        match event.kind {
            EventKind::MessageCreate => {
                let p = event
                    .as_message_create()
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
                message_envelopes(p.encrypted_content, p.encrypted_metadata)?
            }
            EventKind::MessageRevise => {
                let p = event
                    .as_message_revise()
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
                message_envelopes(p.encrypted_content, p.encrypted_metadata)?
            }
            EventKind::ReactionAdd => event
                .as_reaction_add()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
                .encrypted_payload
                .map(|envelope| vec![envelope]),
            EventKind::ReactionRemove => event
                .as_reaction_remove()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
                .encrypted_payload
                .map(|envelope| vec![envelope]),
            EventKind::AgentSidecarExchangeControl => Some(vec![
                event
                    .as_agent_sidecar_exchange_control()
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
                    .encrypted_payload,
            ]),
            _ => return Ok(()),
        }
    };

    let current = sql_query(
        "SELECT realm_id,current_commit_id,current_stream_position,value,public_state \
         FROM mls_group_current_results WHERE scope_key=$1 FOR SHARE",
    )
    .bind::<Text, _>(scope_key(&event.scope_ref)?)
    .get_result::<GroupRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(decode_row)
    .transpose()?;
    if let ScopeRef::Sidecar { sidecar_id, .. } = &event.scope_ref {
        let Some(current) = &current else {
            return Err(coland_storage::MlsSendGateRefusal::EpochUpdateRequired.into_conflict());
        };
        let cut = crate::sidecar_access::cut_in_connection(conn, &event.realm_id, sidecar_id)
            .await?
            .ok_or_else(|| failed_precondition("Sidecar current authority is unavailable"))?;
        let current_cut = crate::sidecar_authority_cut::locked_in_connection(
            conn,
            &event.realm_id,
            sidecar_id,
            &cut.controller_account_id,
        )
        .await?
        .ok_or_else(|| failed_precondition("Sidecar current authority is unavailable"))?;
        let source = sql_query("SELECT e.envelope AS payload FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
            WHERE e.envelope->>'event_id'=$1 AND e.state='committed' AND c.commit_id=$2")
            .bind::<Text,_>(current.value.current_mls_commit_event_ref.as_str())
            .bind::<Text,_>(current.current_commit_id.as_str())
            .get_result::<super::JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let source: arkret_wire::Event =
            serde_json::from_value(source.payload).map_err(PersistenceError::database)?;
        let binding = match source.kind {
            EventKind::MlsGenesis => {
                serde_json::from_value::<MlsGenesisPayload>(
                    serde_json::to_value(source.payload).map_err(PersistenceError::database)?,
                )
                .map_err(PersistenceError::database)?
                .governance_binding
            }
            _ => serde_json::from_value::<MlsCommitPayload>(
                serde_json::to_value(source.payload).map_err(PersistenceError::database)?,
            )
            .map_err(PersistenceError::database)?
            .governance_binding()
            .clone(),
        };
        if !crate::sidecar_mls_readiness::tree_authorized_in_connection(
            conn,
            &current_cut,
            &current.value,
            &current.public_state,
            None,
        )
        .await?
        {
            return Err(coland_storage::MlsSendGateRefusal::EpochUpdateRequired.into_conflict());
        }
        if binding.sidecar_binding().is_none_or(|binding| {
            binding.participant_authority_digest != current_cut.participant_authority_digest
                || binding.authority_stream_head != current_cut.authority_stream_head
        }) {
            return Err(coland_storage::MlsSendGateRefusal::EpochUpdateRequired.into_conflict());
        }
    }
    if envelopes.is_some()
        && let Some(current) = &current
        && circle_tree_holds_invalid_leaf(conn, &event.scope_ref, current).await?
    {
        return Err(coland_storage::MlsSendGateRefusal::EpochUpdateRequired.into_conflict());
    }
    let envelopes = envelopes
        .as_ref()
        .map(|envelopes| envelopes.iter().collect::<Vec<_>>());
    coland_storage::decide_mls_send_gate(
        current.as_ref().map(|current| &current.value),
        &event.scope_ref,
        envelopes.as_deref(),
    )
    .map_err(coland_storage::MlsSendGateRefusal::into_conflict)
}

/// encryption-and-audit.md section 2.4.1: an activated Circle whose current
/// public tree still holds a leaf of an actor that is no longer an effective
/// Circle member (`circle.md` section 9.1) is `epoch_update_required`. A
/// parent Realm leave, ban or rejoin never advances the Circle key-access
/// revision; this same-cut leaf judgment is the other, independent gate.
async fn circle_tree_holds_invalid_leaf(
    conn: &mut AsyncPgConnection,
    scope: &ScopeRef,
    current: &MlsGroupCurrentRecord,
) -> PersistenceResult<bool> {
    if !matches!(scope, ScopeRef::Circle { .. }) {
        return Ok(false);
    }
    let group_id = scope
        .canonical_mls_group_id()
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    let owners = arkret_mls::MlsPublicGroupTracker::restore(
        &current.public_state,
        group_id.as_str(),
        current.value.epoch,
    )
    .and_then(|tracker| tracker.leaves())
    .map_err(|error| {
        PersistenceError::Internal(format!("stored public MLS state is unusable: {error}"))
    })?
    .into_iter()
    .map(|leaf| leaf.actor_id)
    .collect::<std::collections::BTreeSet<_>>();
    circle_holds_invalid_owner(conn, scope, &owners).await
}

async fn circle_holds_invalid_owner(
    conn: &mut AsyncPgConnection,
    scope: &ScopeRef,
    owners: &std::collections::BTreeSet<arkret_wire::ActorId>,
) -> PersistenceResult<bool> {
    let ScopeRef::Circle {
        realm_id,
        circle_id,
    } = scope
    else {
        return Ok(false);
    };
    for owner in owners {
        if !crate::circle_current_results::effective_member_in_connection(
            conn, realm_id, circle_id, owner,
        )
        .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// encryption-and-audit.md §2.4.1: a membership change of the Realm scope
/// strictly advances its current key-access revision, so new application
/// ciphertext waits for a Commit that covers it.
pub(crate) async fn advance_key_access_revision_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if !matches!(
        event.kind,
        EventKind::MemberState | EventKind::InviteAccept | EventKind::CircleMemberState
    ) {
        return Ok(());
    }
    let scope = event.scope_ref.clone();
    let key = scope_key(&scope)?;
    let Some(current) = locked_group(conn, &key).await? else {
        return Ok(());
    };
    let mut value = current.value;
    value.current_key_access_revision = value
        .current_key_access_revision
        .checked_add(1)
        .ok_or_else(|| {
            PersistenceError::SchemaViolation("MLS key-access revision overflow".to_owned())
        })?;
    write_group(
        conn,
        &key,
        &event.realm_id,
        &value,
        &current.public_state,
        commit,
    )
    .await
}

#[async_trait]
impl MlsGroupCurrentStore for PgMlsGroupCurrentStore {
    async fn current(
        &self,
        effective_scope: &ScopeRef,
    ) -> PersistenceResult<Option<MlsGroupCurrentRecord>> {
        let key = scope_key(effective_scope)?;
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id,current_commit_id,current_stream_position,value,public_state \
             FROM mls_group_current_results WHERE scope_key=$1",
        )
        .bind::<Text, _>(key)
        .get_result::<GroupRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_row)
        .transpose()
    }

    async fn realm_currents(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<MlsGroupCurrentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id,current_commit_id,current_stream_position,value,public_state \
             FROM mls_group_current_results WHERE realm_id=$1 \
             ORDER BY (value->'effective_scope'->>'kind') <> 'realm', scope_key",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<GroupRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(decode_row)
        .collect()
    }

    #[cfg(any(test, feature = "test-support"))]
    async fn seed_test_current(&self, record: &MlsGroupCurrentRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let key = scope_key(&record.value.effective_scope)?;
        let group_id = record
            .value
            .effective_scope
            .canonical_mls_group_id()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        sql_query(
            "INSERT INTO mls_group_current_results \
             (realm_id,scope_key,mls_group_id,current_commit_id,current_stream_position,value,public_state,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,now()) \
             ON CONFLICT (scope_key) DO UPDATE SET \
               current_commit_id=EXCLUDED.current_commit_id, \
               current_stream_position=EXCLUDED.current_stream_position, \
               value=EXCLUDED.value, public_state=EXCLUDED.public_state, updated_at=now()",
        )
        .bind::<Text, _>(record.realm_id.as_str())
        .bind::<Text, _>(key)
        .bind::<Text, _>(group_id.as_str())
        .bind::<Text, _>(record.current_commit_id.as_str())
        .bind::<BigInt, _>(position(record.current_stream_position)?)
        .bind::<Jsonb, _>(serde_json::to_value(&record.value).map_err(PersistenceError::database)?)
        .bind::<Binary, _>(&record.public_state)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm_id() -> arkret_wire::RealmId {
        arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x61; 32],
        ))
    }

    fn at() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }

    fn event(kind: EventKind) -> arkret_wire::Event {
        arkret_wire::test_support::raw_event_for_actor_at(
            kind.as_str(),
            ScopeRef::Realm {
                realm_id: realm_id(),
            },
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:mls-bump-member.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:mls-bump-station.example").unwrap(),
            )),
            serde_json::json!({}),
            at(),
        )
        .unwrap()
    }

    fn commit(event: &arkret_wire::Event, position: u64) -> arkret_wire::RealmCommit {
        arkret_wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: arkret_wire::RealmCommitId::from_digest([position as u8; 32]),
            realm_id: realm_id(),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id(),
            },
            stream_position: position,
            previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest([0x09; 32])),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x61; 32],
                ),
            ),
            committed_at: at(),
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:mls-bump-station.example#authority",
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                    .unwrap(),
                created_at: at(),
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
            },
        }
    }

    /// encryption-and-audit.md §2.4.1: each membership change of the Realm
    /// scope advances its current key-access revision by exactly one at the
    /// membership Commit, leaving epoch, current MLS Commit and covered
    /// revision unchanged; other kinds and Realms without a group write
    /// nothing.
    #[tokio::test]
    async fn a_membership_change_advances_only_the_current_key_access_revision() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgMlsGroupCurrentStore { pool: pool.clone() };
        let scope = ScopeRef::Realm {
            realm_id: realm_id(),
        };
        let genesis =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x62; 32]);
        let seeded = MlsGroupCurrentRecord {
            realm_id: realm_id(),
            value: MlsGroupCurrent {
                effective_scope: scope.clone(),
                genesis_event_ref: genesis.clone(),
                cipher_suite: arkret_wire::NonEmptyString::new(
                    "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                )
                .unwrap(),
                current_mls_commit_event_ref: genesis,
                epoch: 4,
                current_key_access_revision: 2,
                covered_key_access_revision: 2,
                public_tree_ref: arkret_wire::BlobRef::new(format!(
                    "ak:blob:sha256:{}",
                    "4".repeat(64)
                ))
                .unwrap(),
            },
            current_commit_id: arkret_wire::RealmCommitId::from_digest([0x05; 32]),
            current_stream_position: 5,
            public_state: vec![7],
        };
        store.seed_test_current(&seeded).await.unwrap();
        let mut conn = pool.get().await.unwrap();

        let message = event(EventKind::MessageCreate);
        advance_key_access_revision_in_connection(&mut conn, &message, &commit(&message, 6))
            .await
            .unwrap();
        assert_eq!(store.current(&scope).await.unwrap().unwrap(), seeded);

        let policy = event(EventKind::RealmReadReceiptPolicy);
        advance_key_access_revision_in_connection(&mut conn, &policy, &commit(&policy, 6))
            .await
            .unwrap();
        assert_eq!(store.current(&scope).await.unwrap().unwrap(), seeded);

        let membership = event(EventKind::MemberState);
        let membership_commit = commit(&membership, 7);
        advance_key_access_revision_in_connection(&mut conn, &membership, &membership_commit)
            .await
            .unwrap();
        let advanced = store.current(&scope).await.unwrap().unwrap();
        assert_eq!(advanced.value.current_key_access_revision, 3);
        assert_eq!(
            MlsGroupCurrent {
                current_key_access_revision: 2,
                ..advanced.value.clone()
            },
            seeded.value
        );
        assert_eq!(advanced.current_commit_id, membership_commit.commit_id);
        assert_eq!(advanced.current_stream_position, 7);
        assert_eq!(advanced.public_state, seeded.public_state);
    }
}

#[cfg(test)]
mod typed_application_envelope_tests {
    use super::*;

    fn envelope(content_type: &str) -> arkret_models_crypto::EncryptedEnvelope {
        arkret_models_crypto::EncryptedEnvelope {
            version: "1.0".to_owned(),
            content_type: content_type.to_owned(),
            encryption_context: arkret_models_crypto::EncryptedEnvelopeEncryptionContext::standard(
                7,
                arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [7; 32]),
            ),
            ciphertext: "Y2lwaGVydGV4dA".to_owned(),
        }
    }

    fn metadata_event(
        kind: EventKind,
        plaintext_key: &str,
        plaintext: serde_json::Value,
    ) -> arkret_wire::Event {
        let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        ));
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:mixed-metadata-member.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:mixed-metadata-station.example").unwrap(),
        ));
        let mut object = match kind {
            EventKind::SpaceCreate => serde_json::to_value(
                arkret_models_collaboration::objects::space::Space::create_object(
                    realm.clone(),
                    "kanban",
                    "Title",
                    actor.clone(),
                ),
            )
            .unwrap(),
            EventKind::StrandCreate => serde_json::to_value(
                arkret_models_collaboration::objects::strand::Strand::new_create(
                    realm.clone(),
                    "Title",
                    actor.clone(),
                ),
            )
            .unwrap(),
            _ => unreachable!(),
        };
        let fields = object.as_object_mut().unwrap();
        for key in ["title", "summary", "labels", "avatar_blob_ref", "metadata"] {
            fields.remove(key);
        }
        fields.insert(plaintext_key.to_owned(), plaintext);
        fields.insert(
            "encrypted_metadata".to_owned(),
            serde_json::to_value(envelope("application/vnd.arkret.strand-metadata+json")).unwrap(),
        );
        arkret_wire::test_support::raw_event_for_actor_at(
            kind.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id: realm },
            actor,
            serde_json::json!({"object": object}),
            chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        )
        .unwrap()
    }

    #[derive(Debug, PartialEq, diesel::QueryableByName)]
    struct WriteCounts {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        events: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        commits: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        groups: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        spaces: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        strands: i64,
    }

    async fn write_counts(conn: &mut AsyncPgConnection) -> WriteCounts {
        sql_query("SELECT (SELECT COUNT(*) FROM canonical_events) AS events, (SELECT COUNT(*) FROM realm_commits) AS commits, (SELECT COUNT(*) FROM mls_group_current_results) AS groups, (SELECT COUNT(*) FROM space_current_results) AS spaces, (SELECT COUNT(*) FROM strand_current_results) AS strands")
            .get_result(conn).await.unwrap()
    }

    #[tokio::test]
    async fn postgres_send_gate_rejects_empty_or_null_plaintext_beside_ciphertext_without_writes() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let before = write_counts(&mut conn).await;
        for (kind, key, plaintext) in [
            (EventKind::SpaceCreate, "labels", serde_json::json!([])),
            (EventKind::SpaceCreate, "title", serde_json::Value::Null),
            (
                EventKind::SpaceCreate,
                "avatar_blob_ref",
                serde_json::Value::Null,
            ),
            (EventKind::StrandCreate, "metadata", serde_json::Value::Null),
        ] {
            let event = metadata_event(kind.clone(), key, plaintext);
            let projection = event.event_metadata_send_gate().unwrap().unwrap();
            assert!(projection.user_metadata_present, "{kind} {key}");
            assert_eq!(projection.encrypted_metadata.len(), 1);
            let error = require_mls_send_gate_in_connection(&mut conn, &event)
                .await
                .unwrap_err();
            assert!(
                matches!(error, PersistenceError::SchemaViolation(ref detail) if detail == "metadata must not carry both plaintext fields and encrypted_metadata"),
                "{error}"
            );
            assert_eq!(
                write_counts(&mut conn).await,
                before,
                "{kind} {key} wrote state"
            );
        }
    }

    #[test]
    fn message_projection_retains_content_before_metadata_and_exact_epoch() {
        let projected = message_envelopes(
            Some(envelope("application/vnd.arkret.message+json")),
            Some(envelope("application/vnd.arkret.message-metadata+json")),
        )
        .unwrap()
        .unwrap();
        assert_eq!(projected.len(), 2);
        assert_eq!(
            projected[0].content_type,
            "application/vnd.arkret.message+json"
        );
        assert_eq!(
            projected[1].content_type,
            "application/vnd.arkret.message-metadata+json"
        );
        assert!(
            projected
                .iter()
                .all(|envelope| envelope.encryption_context.epoch() == 7)
        );
    }

    #[test]
    fn metadata_alone_cannot_make_a_plaintext_message_pass_the_send_gate() {
        assert!(message_envelopes(None, None).unwrap().is_none());
        assert!(
            message_envelopes(
                None,
                Some(envelope("application/vnd.arkret.message-metadata+json"))
            )
            .is_err()
        );
    }
}
