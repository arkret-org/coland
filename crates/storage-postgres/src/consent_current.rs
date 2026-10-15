//! Consent admission and reads at the holder PCR authority cut.

use arkret_models_collaboration::consent_operations::{ConsentState, ConsentValue};
use arkret_models_collaboration::events_payloads::consent::{ConsentGrantPayload, ConsentPeer};
use arkret_models_collaboration::governance_payloads::ConsentRevokePayload;
use arkret_wire::{AccountId, ActorId, CurrentRevision, Event, EventKind, RealmCommit};
use coland_storage::{
    AuthorityCommitWriteOutcome, ConflictCode, ConsentAdmissionOutcome, ConsentAdmissionWrite,
    ConsentCurrentRecord, ConsentCurrentStore, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value;

use crate::actor_profiles::{PcrSelfEventCut, corrupt, rejected, verify_pcr_self_event};
use crate::{AsyncPgConnection, PgPool, PgTransactionError, pg_conn};

pub struct PgConsentCurrentStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct RootRow {
    #[diesel(sql_type = Jsonb)]
    controller_actor_id: Value,
    #[diesel(sql_type = Text)]
    authority_event_ref: String,
}

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

fn record(row: Row) -> PersistenceResult<ConsentCurrentRecord> {
    Ok(ConsentCurrentRecord {
        value: serde_json::from_value(row.value).map_err(PersistenceError::database)?,
        event: serde_json::from_value(row.envelope).map_err(PersistenceError::database)?,
        commit: serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?,
        quarantine_update: None,
    })
}

async fn version(
    conn: &mut AsyncPgConnection,
    commit_id: &str,
) -> Result<ConsentCurrentRecord, PgTransactionError> {
    let row = sql_query("SELECT v.value,e.envelope,c.commit_json FROM consent_result_versions v JOIN realm_commits c ON c.commit_id=v.commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE v.commit_id=$1")
        .bind::<Text,_>(commit_id).get_result::<Row>(conn).await?;
    record(row).map_err(Into::into)
}

/// Read the complete accepted namespace while the caller holds the PCR lock.
pub(crate) async fn records_in_connection(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
    realm: &arkret_wire::RealmId,
) -> Result<Vec<ConsentCurrentRecord>, PgTransactionError> {
    #[derive(QueryableByName)]
    struct Completeness {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        complete: bool,
    }
    let complete=sql_query("SELECT NOT EXISTS(SELECT 1 FROM realm_commits c LEFT JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND c.stream_ref->>'kind'='realm' AND (e.pk IS NULL OR e.state<>'committed')) AND NOT EXISTS(SELECT 1 FROM (SELECT DISTINCT ON(e.envelope->'payload'->>'consent_id') e.envelope->'payload'->>'consent_id' AS consent_id,c.commit_id FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND e.envelope->>'kind' IN ('ak.consent.grant','ak.consent.revoke') ORDER BY e.envelope->'payload'->>'consent_id',c.stream_position DESC) latest LEFT JOIN consent_current_results r ON r.realm_id=$1 AND r.consent_id=latest.consent_id WHERE r.current_commit_id IS DISTINCT FROM latest.commit_id) AND NOT EXISTS(SELECT 1 FROM consent_current_results r LEFT JOIN realm_commits c ON c.commit_id=r.current_commit_id AND c.realm_id=r.realm_id AND c.stream_position=r.current_stream_position LEFT JOIN canonical_events e ON e.pk=c.event_pk WHERE r.realm_id=$1 AND (c.commit_id IS NULL OR e.pk IS NULL OR e.state<>'committed')) AS complete")
                .bind::<Text,_>(realm.as_str()).get_result::<Completeness>(&mut *conn).await?;
    if !complete.complete {
        return Err(rejected(
            ConflictCode::TemporarilyUnavailable,
            "holder Consent namespace is incomplete",
        ));
    }
    let rows = sql_query("SELECT r.value,e.envelope,c.commit_json FROM consent_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id AND c.realm_id=r.realm_id AND c.stream_position=r.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk WHERE r.holder_account_id=$1 AND r.realm_id=$2 ORDER BY r.consent_id")
                .bind::<Jsonb,_>(serde_json::to_value(holder).map_err(corrupt)?)
                .bind::<Text,_>(realm.as_str()).get_results::<Row>(&mut *conn).await?;
    rows.into_iter()
        .map(record)
        .collect::<PersistenceResult<Vec<_>>>()
        .map_err(Into::into)
}

async fn admit(
    conn: &mut AsyncPgConnection,
    write: &ConsentAdmissionWrite,
) -> Result<ConsentAdmissionOutcome, PgTransactionError> {
    let tx = &write.transaction;
    let event = &tx.event;
    if !matches!(
        event.kind,
        EventKind::ConsentGrant | EventKind::ConsentRevoke
    ) {
        return Err(rejected(
            ConflictCode::SchemaViolation,
            "not a Consent Event",
        ));
    }
    event
        .validate_for_submit_structural()
        .map_err(|e| rejected(ConflictCode::SchemaViolation, &e.to_string()))?;
    let auth = event.authorization_ref.as_deref().ok_or_else(|| {
        rejected(
            ConflictCode::FailedPrecondition,
            "Consent requires current holder root authorization",
        )
    })?;
    // The shared verifier takes the PCR lock and checks the accepted device
    // signature and the exact Account-to-PCR binding before any new write.
    match verify_pcr_self_event(conn, tx, Some(auth), "Consent").await? {
        PcrSelfEventCut::Known(commit) => {
            return Ok(ConsentAdmissionOutcome::Duplicate(
                version(conn, commit.commit_id.as_str()).await?,
            ));
        }
        PcrSelfEventCut::Fresh(_) => {}
    }
    let root = sql_query("SELECT controller_actor_id,authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1 FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<RootRow>(&mut *conn).await.optional()?
        .ok_or_else(|| rejected(ConflictCode::FailedPrecondition,"holder root is unavailable"))?;
    let controller: ActorId = serde_json::from_value(root.controller_actor_id).map_err(corrupt)?;
    if controller != event.actor_id || root.authority_event_ref != auth {
        return Err(rejected(
            ConflictCode::CapabilityDenied,
            "Consent signer is not the current holder root controller",
        ));
    }
    let holder = event.actor_id.as_account_id().ok_or_else(|| {
        rejected(
            ConflictCode::SchemaViolation,
            "Consent holder is not an Account",
        )
    })?;
    let holder_json = serde_json::to_value(holder).map_err(corrupt)?;
    let payload = serde_json::to_value(&event.payload).map_err(corrupt)?;
    let (id, next) = match event.kind {
        EventKind::ConsentGrant => {
            let grant: ConsentGrantPayload = serde_json::from_value(payload)
                .map_err(|e| rejected(ConflictCode::SchemaViolation, &e.to_string()))?;
            if grant
                .not_before
                .zip(grant.expires_at)
                .is_some_and(|(start, end)| start >= end)
            {
                return Err(rejected(
                    ConflictCode::SchemaViolation,
                    "invalid Consent time window",
                ));
            }
            let existing = sql_query("SELECT r.value,e.envelope,c.commit_json FROM consent_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE r.holder_account_id=$1 AND r.consent_id=$2 FOR UPDATE OF r")
                .bind::<Jsonb,_>(&holder_json).bind::<Text,_>(grant.consent_id.as_str()).get_result::<Row>(&mut *conn).await.optional()?;
            if existing.is_some() {
                return Err(rejected(
                    ConflictCode::FailedPrecondition,
                    "consent_id already exists",
                ));
            }
            let id = grant.consent_id.clone();
            (
                id,
                ConsentValue {
                    consent_id: grant.consent_id,
                    peer: grant.peer,
                    consent_scope: grant.consent_scope,
                    not_before: grant.not_before,
                    expires_at: grant.expires_at,
                    constraints: grant.constraints,
                    evidence_ref: grant.evidence_ref,
                    reason: grant.reason,
                    status: ConsentState::Active,
                    revoked_at: None,
                    revoked_reason: None,
                },
            )
        }
        EventKind::ConsentRevoke => {
            let revoke: ConsentRevokePayload = serde_json::from_value(payload)
                .map_err(|e| rejected(ConflictCode::SchemaViolation, &e.to_string()))?;
            let row = sql_query("SELECT r.value,e.envelope,c.commit_json FROM consent_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE r.holder_account_id=$1 AND r.consent_id=$2 FOR UPDATE OF r")
                .bind::<Jsonb,_>(&holder_json).bind::<Text,_>(revoke.consent_id.as_str()).get_result::<Row>(&mut *conn).await.optional()?
                .ok_or_else(|| rejected(ConflictCode::FailedPrecondition,"unknown Consent"))?;
            let current = record(row)?;
            if current.value.status != ConsentState::Active {
                return Err(rejected(
                    ConflictCode::FailedPrecondition,
                    "Consent is already revoked",
                ));
            }
            if revoke.expected_revision
                != (CurrentRevision {
                    commit_id: current.commit.commit_id,
                    stream_position: current.commit.stream_position,
                })
            {
                return Err(rejected(
                    ConflictCode::CasConflict,
                    "Consent revision changed",
                ));
            }
            let mut value = current.value;
            value.status = ConsentState::Revoked;
            value.revoked_at = Some(event.created_at);
            value.revoked_reason = revoke.reason;
            (revoke.consent_id, value)
        }
        _ => unreachable!(),
    };
    let historical = crate::agent_producer_signer_keys::prepare_admitted_own_pcr_in_connection(
        conn, event, &tx.commit,
    )
    .await?;
    crate::authority_commit::queue_event_in_connection(conn, event, tx.commit.committed_at).await?;
    match crate::authority_commit::commit_verified_consent_in_connection(conn, tx).await? {
        AuthorityCommitWriteOutcome::Committed => {
            crate::agent_producer_signer_keys::retain_self_outcome_in_connection(
                conn, event, &tx.commit, historical,
            )
            .await?;
        }
        _ => {
            return Err(rejected(
                ConflictCode::TemporarilyUnavailable,
                "Consent PCR head changed",
            ));
        }
    }
    let position = i64::try_from(tx.commit.stream_position).map_err(corrupt)?;
    let value = serde_json::to_value(&next).map_err(corrupt)?;
    sql_query("INSERT INTO consent_current_results(holder_account_id,consent_id,realm_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(holder_account_id,consent_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
        .bind::<Jsonb,_>(&holder_json).bind::<Text,_>(id.as_str()).bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(tx.commit.commit_id.as_str()).bind::<BigInt,_>(position).bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(tx.commit.committed_at).execute(&mut *conn).await?;
    sql_query("INSERT INTO consent_result_versions(commit_id,consent_id,value) VALUES($1,$2,$3)")
        .bind::<Text, _>(tx.commit.commit_id.as_str())
        .bind::<Text, _>(id.as_str())
        .bind::<Jsonb, _>(value)
        .execute(&mut *conn)
        .await?;
    let quarantine_update = if next.status == ConsentState::Revoked {
        invalidate_quarantine(conn, holder, &next, tx.commit.committed_at).await?
    } else {
        None
    };
    if quarantine_update.is_some() {
        crate::consent_private_effects::mark_pending(conn, holder, &event.realm_id).await?;
    }
    Ok(ConsentAdmissionOutcome::Committed(ConsentCurrentRecord {
        value: next,
        event: event.clone(),
        commit: tx.commit.clone(),
        quarantine_update,
    }))
}

async fn invalidate_quarantine(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
    value: &ConsentValue,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<coland_storage::AccountDataRecord>, PgTransactionError> {
    use arkret_models_collaboration::governance::holder_quarantine::{
        HolderQuarantine, HolderQuarantineInvalidation, HolderQuarantineInvalidationReason,
        HolderQuarantineInvalidationScope,
    };
    use coland_storage::{AccountDataCasResult, AccountDataRecord};
    #[derive(QueryableByName)]
    struct Cell {
        #[diesel(sql_type=BigInt)]
        revision: i64,
        #[diesel(sql_type=Jsonb)]
        payload: Value,
    }
    let actor = ActorId::account(holder.clone()).to_string();
    let key = arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE;
    let Some(row) = sql_query("SELECT revision,payload FROM account_datas WHERE actor_id=$1 AND account_data_key=$2 AND NOT tombstone AND account_data_source_current(actor_id,account_data_key) FOR UPDATE")
        .bind::<Text,_>(&actor).bind::<Text,_>(key).get_result::<Cell>(&mut *conn).await.optional()? else {return Ok(None)};
    let ConsentPeer::Actor { actor_id: peer } = &value.peer;
    // A Service Actor has no Account-principal quarantine selector.
    // Its exact Actor consent is never aggregated onto an Account.
    let Some(peer_account) = peer.as_account_id() else {
        return Ok(None);
    };
    let mut cell: HolderQuarantine = serde_json::from_value(row.payload).map_err(corrupt)?;
    cell.validate_holder(holder).map_err(corrupt)?;
    let before = cell.quarantine_entries.len();
    cell.quarantine_entries.retain(|entry| {
        !(entry.source_peer_principal_id == peer_account.principal_id
            && entry.source_id == peer_account.station_id
            && (value.consent_scope == arkret_wire::ConsentScope::Any
                || entry.surface.consent_scope() == value.consent_scope))
    });
    if cell.quarantine_entries.len() == before {
        return Ok(None);
    }
    cell.updated_at = at;
    if matches!(
        value.consent_scope,
        arkret_wire::ConsentScope::Invite | arkret_wire::ConsentScope::Any
    ) {
        cell.last_invalidation = Some(HolderQuarantineInvalidation {
            reason: HolderQuarantineInvalidationReason::ConsentRevoke,
            peer_principal_id: peer_account.principal_id.clone(),
            consent_scope: if value.consent_scope == arkret_wire::ConsentScope::Any {
                HolderQuarantineInvalidationScope::Any
            } else {
                HolderQuarantineInvalidationScope::Invite
            },
            revoked_at: value.revoked_at.unwrap_or(at),
            removed_entries: (before - cell.quarantine_entries.len()) as u64,
        });
    }
    let revision = u64::try_from(row.revision).map_err(corrupt)?;
    let record = AccountDataRecord {
        actor,
        account_data_key: key.to_owned(),
        revision: revision
            .checked_add(1)
            .ok_or_else(|| corrupt("quarantine revision exhausted"))?,
        payload: serde_json::to_value(cell).map_err(corrupt)?,
        tombstone: false,
        updated_at: at,
    };
    match crate::accounts::compare_account_data_in_transaction(conn, &record, revision, None)
        .await?
    {
        AccountDataCasResult::Applied(record) => Ok(Some(record)),
        _ => Err(rejected(ConflictCode::CasConflict, "quarantine changed")),
    }
}

#[async_trait::async_trait]
impl ConsentCurrentStore for PgConsentCurrentStore {
    async fn historical_basis(
        &self,
        holder: &AccountId,
        id: &arkret_wire::ConsentId,
        revision: &arkret_wire::CurrentRevision,
    ) -> PersistenceResult<Option<coland_storage::CommittedEventRecord>> {
        #[derive(diesel::QueryableByName)]
        struct Basis {
            #[diesel(sql_type=Jsonb)]
            commit_json: Value,
            #[diesel(sql_type=Jsonb)]
            envelope: Value,
        }
        let mut conn = pg_conn(&self.pool).await?;
        let rows=sql_query("SELECT c.commit_json,e.envelope FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1 UNION ALL SELECT f.accepted_commit_json AS commit_json,e.envelope FROM authority_forward_attempts f JOIN canonical_events e ON e.pk=f.event_pk WHERE f.original_submission_json IS NOT NULL AND f.accepted_commit_json->>'commit_id'=$1")
            .bind::<Text,_>(revision.commit_id.as_str()).get_results::<Basis>(&mut conn).await.map_err(PersistenceError::database)?;
        let mut result: Option<coland_storage::CommittedEventRecord> = None;
        for row in rows {
            let commit: RealmCommit =
                serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
            let event: Event =
                serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
            if commit.commit_id != revision.commit_id
                || commit.stream_position != revision.stream_position
                || commit.event_ref != event.event_id
                || event.actor_id.as_account_id() != Some(holder)
                || event.kind != EventKind::ConsentGrant
            {
                continue;
            }
            let payload: ConsentGrantPayload = serde_json::from_value(
                serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
            )
            .map_err(PersistenceError::database)?;
            if &payload.consent_id != id {
                continue;
            }
            let pair = coland_storage::CommittedEventRecord { commit, event };
            if result.as_ref().is_some_and(|old| old != &pair) {
                return Err(PersistenceError::Conflict(
                    "immutable Consent acceptance witness fork".into(),
                ));
            }
            result = Some(pair);
        }
        Ok(result)
    }
    async fn pending_effect_holders(
        &self,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Vec<AccountId>> {
        crate::consent_private_effects::pending(&self.pool, issuer).await
    }
    async fn prepare_effect_publication(
        &self,
        holder: &AccountId,
        issuer: &arkret_wire::DidCoreId,
        nonce: String,
    ) -> PersistenceResult<Option<coland_storage::PrivateEffectsPublication>> {
        crate::consent_private_effects::prepare(&self.pool, holder, issuer, nonce).await
    }
    async fn acknowledge_effect_publication(
        &self,
        holder: &AccountId,
        issuer: &arkret_wire::DidCoreId,
        sequence: u64,
    ) -> PersistenceResult<()> {
        crate::consent_private_effects::acknowledge(&self.pool, holder, issuer, sequence).await
    }
    async fn project_effect_publication(
        &self,
        request: &arkret_models_collaboration::consent_private::ConsentPrivateEffectsPublishRequest,
        source: &arkret_wire::DidCoreId,
        receiver: &arkret_wire::DidCoreId,
        authority: &coland_storage::CurrentRealmAuthority,
        known_head: &arkret_wire::CommitStreamHead,
    ) -> PersistenceResult<coland_storage::PrivateEffectsProjection> {
        crate::consent_private_effects_projection::project(
            &self.pool, request, source, receiver, authority, known_head,
        )
        .await
    }
    async fn observe_private_cut(
        &self,
        request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
        outcome: &arkret_models_collaboration::consent_private::ConsentPrivateProxyOutcome,
    ) -> PersistenceResult<()> {
        crate::consent_private_cuts::observe(self, request, outcome).await
    }
    async fn private_command_prepared(
        &self,
        request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
        source: &arkret_wire::DidCoreId,
        acceptor: &arkret_wire::DidCoreId,
        quota: &arkret_wire::NewSourceQuotaConstraints,
        prepared: Option<&coland_storage::PreparedPrivateInviteDelivery>,
    ) -> PersistenceResult<arkret_models_collaboration::consent_private::ConsentPrivateProxyOutcome>
    {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            crate::consent_private_commands::execute(
                conn, request, source, acceptor, quota, prepared,
            )
            .await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn private_command(
        &self,
        request: &arkret_models_collaboration::consent_private::ConsentPrivateProxyRequest,
        source_service: &arkret_wire::DidCoreId,
        acceptor_service: &arkret_wire::DidCoreId,
        quota_constraints: &arkret_wire::NewSourceQuotaConstraints,
    ) -> PersistenceResult<arkret_models_collaboration::consent_private::ConsentPrivateProxyOutcome>
    {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            crate::consent_private_commands::execute(
                conn,
                request,
                source_service,
                acceptor_service,
                quota_constraints,
                None,
            )
            .await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn read_cut(
        &self,
        holder: &AccountId,
        peer: &ConsentPeer,
        scope: arkret_wire::ConsentScope,
        device: Option<&arkret_wire::DeviceId>,
    ) -> PersistenceResult<coland_storage::ConsentCurrentCut> {
        let holder = holder.clone();
        let peer = peer.clone();
        let device = device.cloned();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let authority = crate::pcr_private_authority::lock_holder(conn, &holder, None).await?;
            let evaluated_at =
                arkret_canonical::canonical::normalize_timestamp_canonical(chrono::Utc::now());
            let device_admitted = if let Some(device) = &device {
                crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
                    conn,
                    &holder,
                    device,
                    evaluated_at,
                )
                .await?
                .is_some_and(|status| {
                    status.lifecycle == crate::pcr_device_status_fold::PcrDeviceLifecycle::Active
                })
            } else {
                true
            };
            let records = records_in_connection(conn, &holder, &authority.realm_id)
                .await?
                .into_iter()
                .filter(|r| {
                    r.value.peer == peer
                        && (r.value.consent_scope == scope
                            || r.value.consent_scope == arkret_wire::ConsentScope::Any)
                })
                .collect();
            Ok(coland_storage::ConsentCurrentCut {
                realm_id: authority.realm_id,
                generation: authority.generation,
                service_id: authority.service_id,
                head: authority.head,
                records,
                evaluated_at,
                device_admitted,
            })
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn admit(
        &self,
        write: ConsentAdmissionWrite,
    ) -> PersistenceResult<ConsentAdmissionOutcome> {
        write
            .transaction
            .validate()
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| admit(conn, &write).await)
            .await
            .map_err(PgTransactionError::into_persistence)
    }
    async fn admit_invite_delivery(
        &self,
        write: coland_storage::ConsentDeliveryWrite,
    ) -> PersistenceResult<Option<coland_storage::AccountDataCasResult>> {
        if write.record.actor != ActorId::account(write.holder.clone()).to_string()
            || write.record.account_data_key != arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY
            || write.record.tombstone
        {
            return Err(PersistenceError::SchemaViolation(
                "invalid consent-bound delivery target".into(),
            ));
        }
        let cell: arkret_models_collaboration::governance::invite_addressing::InviteDelivery =
            serde_json::from_value(write.record.payload.clone())
                .map_err(PersistenceError::database)?;
        cell.validate()
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let authority = crate::pcr_private_authority::lock_holder(conn, &write.holder, Some(&write.acceptor_service_id)).await?;
            let holder = serde_json::to_value(&write.holder).map_err(corrupt)?;
            // Match the canonical proof, then serialize with Grant/Revoke on
            // the same PCR lock. Re-read current AFTER acquiring that lock.
            let current = sql_query("SELECT r.value,e.envelope,c.commit_json FROM consent_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk JOIN realm_authorities a ON a.realm_id=r.realm_id JOIN realm_authority_root_current_results root ON root.realm_id=r.realm_id WHERE r.holder_account_id=$1 AND r.realm_id=$2 AND e.envelope->>'event_id'=$3 AND a.service_id=$4 AND root.controller_actor_id=$5")
                .bind::<Jsonb,_>(&holder).bind::<Text,_>(authority.realm_id.as_str()).bind::<Text,_>(write.consent_grant_ref.as_str())
                .bind::<Text,_>(write.acceptor_service_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(ActorId::account(write.holder.clone())).map_err(corrupt)?)
                .get_result::<Row>(&mut *conn).await.optional()?;
            let Some(current) = current else { return Ok(None) };
            let current = record(current)?;
            if write.consent_id.as_ref().is_some_and(|id| id != &current.value.consent_id)
                || !current.permits(&write.peer, arkret_wire::ConsentScope::Invite, chrono::Utc::now())
            {
                return Ok(None);
            }
            crate::accounts::compare_account_data_in_transaction(
                conn, &write.record, write.expected_revision, None,
            ).await.map(Some).map_err(PgTransactionError::from)
        }).await.map_err(PgTransactionError::into_persistence)
    }
    async fn list(&self, holder: &AccountId) -> PersistenceResult<Vec<ConsentCurrentRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let holder = holder.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let authority =
                crate::pcr_private_authority::lock_holder(conn, &holder, Some(&holder.station_id))
                    .await?;
            records_in_connection(conn, &holder, &authority.realm_id).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}
