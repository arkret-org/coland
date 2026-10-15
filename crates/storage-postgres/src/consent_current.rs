//! Consent admission and reads at the holder PCR authority cut.

use arkret_models_collaboration::consent_operations::{ConsentState, ConsentValue};
use arkret_models_collaboration::events_payloads::consent::{ConsentGrantPayload, ConsentPeer};
use arkret_models_collaboration::governance_payloads::ConsentRevokePayload;
use arkret_wire::{AccountId, ActorId, CurrentRevision, EventKind};
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
            #[derive(QueryableByName)]
            struct LockRow { #[diesel(sql_type=Text)] realm_id: String }
            let holder = serde_json::to_value(&write.holder).map_err(corrupt)?;
            // Match the canonical proof, then serialize with Grant/Revoke on
            // the same PCR lock. Re-read current AFTER acquiring that lock.
            let lock = sql_query("SELECT a.realm_id FROM realm_authorities a JOIN consent_current_results r ON r.realm_id=a.realm_id JOIN realm_commits c ON c.commit_id=r.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE r.holder_account_id=$1 AND e.envelope->>'event_id'=$2 FOR UPDATE OF a")
                .bind::<Jsonb,_>(&holder).bind::<Text,_>(write.consent_grant_ref.as_str())
                .get_result::<LockRow>(&mut *conn).await.optional()?;
            let Some(lock) = lock else { return Ok(None) };
            let current = sql_query("SELECT r.value,e.envelope,c.commit_json FROM consent_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk JOIN realm_authorities a ON a.realm_id=r.realm_id JOIN realm_authority_root_current_results root ON root.realm_id=r.realm_id WHERE r.holder_account_id=$1 AND r.realm_id=$2 AND e.envelope->>'event_id'=$3 AND a.service_id=$4 AND root.controller_actor_id=$5")
                .bind::<Jsonb,_>(&holder).bind::<Text,_>(&lock.realm_id).bind::<Text,_>(write.consent_grant_ref.as_str())
                .bind::<Text,_>(write.holder.station_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(ActorId::account(write.holder.clone())).map_err(corrupt)?)
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
        let rows=sql_query("SELECT r.value,e.envelope,c.commit_json FROM consent_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk JOIN realm_authorities a ON a.realm_id=r.realm_id JOIN realm_authority_root_current_results root ON root.realm_id=r.realm_id WHERE r.holder_account_id=$1 AND a.service_id=$2 AND root.controller_actor_id=$3 ORDER BY r.consent_id")
            .bind::<Jsonb,_>(serde_json::to_value(holder).map_err(PersistenceError::database)?).bind::<Text,_>(holder.station_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(ActorId::account(holder.clone())).map_err(PersistenceError::database)?).get_results::<Row>(&mut conn).await.map_err(PersistenceError::database)?;
        rows.into_iter().map(record).collect()
    }
    async fn admit_call(
        &self,
        request: &arkret_models_collaboration::call_invitation::CallInvitationAdmissionRequestBody,
        authority_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<coland_storage::ConsentCallAdmissionCut>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            #[derive(QueryableByName)]
            struct CutRow {
                #[diesel(sql_type = Text)]
                realm_id: String,
                #[diesel(sql_type = BigInt)]
                generation: i64,
            }
            let holder = &request.invitation.holder_account_id;
            let holder_json = serde_json::to_value(holder).map_err(corrupt)?;
            let controller = serde_json::to_value(ActorId::account(holder.clone())).map_err(corrupt)?;
            // Grant/Revoke take this same authority row lock. Acquire it even
            // when no Consent exists so absence is a real serialized cut.
            let cut = sql_query("SELECT a.realm_id,a.generation FROM realm_authorities a JOIN realm_authority_root_current_results root ON root.realm_id=a.realm_id JOIN principal_resolutions p ON p.pcr_realm_id=a.realm_id WHERE root.controller_actor_id=$1 AND a.service_id=$2 AND p.principal_id=$3 AND p.station_id=$4 FOR UPDATE OF a")
                .bind::<Jsonb,_>(&controller).bind::<Text,_>(authority_id.as_str()).bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str())
                .get_result::<CutRow>(&mut *conn).await.optional()?;
            let Some(cut) = cut else { return Ok(None) };
            let at = chrono::Utc::now();
            request.validate(at).map_err(|error| rejected(ConflictCode::SchemaViolation, &error.to_string()))?;
            let rows = sql_query("SELECT r.value,e.envelope,c.commit_json FROM consent_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE r.holder_account_id=$1 AND r.realm_id=$2 ORDER BY r.consent_id")
                .bind::<Jsonb,_>(&holder_json).bind::<Text,_>(&cut.realm_id).get_results::<Row>(&mut *conn).await?;
            let records = rows.into_iter().map(record).collect::<PersistenceResult<Vec<_>>>()?;
            let admitted = records.iter().any(|record| arkret_models_collaboration::call_invitation::consent_value_permits_call(
                &record.value, &request.invitation.inviter_actor_id, &request.invitation.media, at,
            ));
            Ok(Some(coland_storage::ConsentCallAdmissionCut {
                admitted,
                authority_generation: u64::try_from(cut.generation).map_err(corrupt)?,
                evaluated_at: at,
            }))
        }).await.map_err(PgTransactionError::into_persistence)
    }
    async fn holder_realm(
        &self,
        holder: &AccountId,
    ) -> PersistenceResult<Option<arkret_wire::RealmId>> {
        #[derive(QueryableByName)]
        struct HolderRealmRow {
            #[diesel(sql_type = Text)]
            realm_id: String,
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query("SELECT p.pcr_realm_id AS realm_id FROM principal_resolutions p JOIN realm_authority_root_current_results root ON root.realm_id=p.pcr_realm_id WHERE root.controller_actor_id=$1 AND p.principal_id=$2 AND p.station_id=$3")
            .bind::<Jsonb,_>(serde_json::to_value(ActorId::account(holder.clone())).map_err(PersistenceError::database)?).bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str())
            .get_results::<HolderRealmRow>(&mut conn).await.map_err(PersistenceError::database)?;
        if rows.len() > 1 {
            return Err(PersistenceError::SchemaViolation(
                "holder PCR mapping is not unique".into(),
            ));
        }
        rows.into_iter()
            .next()
            .map(|row| row.realm_id.parse().map_err(PersistenceError::database))
            .transpose()
    }
    async fn read_current(
        &self,
        request: &arkret_models_collaboration::consent_operations::ConsentCurrentReadRequestBody,
        authority_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<coland_storage::ConsentCurrentReadCut>> {
        request
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async move|conn| {
            #[derive(QueryableByName)]
            struct AuthorityCut {#[diesel(sql_type=Text)] realm_id:String,#[diesel(sql_type=BigInt)] generation:i64}
            #[derive(QueryableByName)]
            struct Head {#[diesel(sql_type=Jsonb)] stream_ref:Value,#[diesel(sql_type=Text)] commit_id:String,#[diesel(sql_type=BigInt)] stream_position:i64}
            let actor=serde_json::to_value(ActorId::account(request.holder_account_id.clone())).map_err(corrupt)?;
            let Some(cut)=sql_query("SELECT a.realm_id,a.generation FROM realm_authorities a JOIN realm_authority_root_current_results root ON root.realm_id=a.realm_id JOIN principal_resolutions p ON p.pcr_realm_id=a.realm_id WHERE root.controller_actor_id=$1 AND a.service_id=$2 AND p.principal_id=$3 AND p.station_id=$4 FOR UPDATE OF a")
                .bind::<Jsonb,_>(actor).bind::<Text,_>(authority_id.as_str()).bind::<Text,_>(request.holder_account_id.principal_id.as_str()).bind::<Text,_>(request.holder_account_id.station_id.as_str()).get_result::<AuthorityCut>(&mut *conn).await.optional()? else{return Ok(None)};
            let head=sql_query("SELECT stream_ref,commit_id,stream_position FROM realm_commits WHERE realm_id=$1 AND stream_ref->>'kind'='realm' ORDER BY stream_position DESC LIMIT 1")
                .bind::<Text,_>(&cut.realm_id).get_result::<Head>(&mut *conn).await?;
            let rows=sql_query("SELECT r.value,e.envelope,c.commit_json FROM consent_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE r.holder_account_id=$1 AND r.realm_id=$2 ORDER BY r.consent_id")
                .bind::<Jsonb,_>(serde_json::to_value(&request.holder_account_id).map_err(corrupt)?).bind::<Text,_>(&cut.realm_id).get_results::<Row>(&mut *conn).await?;
            let records=rows.into_iter().map(record).collect::<PersistenceResult<Vec<_>>>()?.into_iter()
                .filter(|r|r.value.peer==request.peer && (r.value.consent_scope==request.consent_scope || r.value.consent_scope==arkret_wire::ConsentScope::Any)).collect();
            Ok(Some(coland_storage::ConsentCurrentReadCut {
                realm_id:cut.realm_id.parse().map_err(corrupt)?, governance_generation:u64::try_from(cut.generation).map_err(corrupt)?,
                effective_stream_head:arkret_wire::CommitStreamHead{stream_ref:serde_json::from_value(head.stream_ref).map_err(corrupt)?,commit_id:head.commit_id.parse().map_err(corrupt)?,stream_position:u64::try_from(head.stream_position).map_err(corrupt)?},
                records,evaluated_at:chrono::Utc::now(),
            }))
        }).await.map_err(PgTransactionError::into_persistence)
    }
}
