//! Native root eligibility and the immutable finite successor source.

use arkret_models_collaboration::events_payloads::realm::RealmOwnerTransferPayload;
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_wire::{AccountId, ActorId, Event, EventKind, RealmCommit, RealmId};
use coland_storage::{
    AuthorityCommitTransaction, OwnerTransferSuccessorSource, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Bool, Jsonb, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::Value;

fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}
fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("temporarily_unavailable: {detail}"))
}

pub(crate) fn require_deadline(
    source: &OwnerTransferSuccessorSource,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let core = &source.evidence().device_projection_attestation.attestation;
    if at < core.attested_at
        || at >= core.expires_at
        || at < core.authorization_window.not_before
        || core
            .authorization_window
            .expires_at
            .is_some_and(|expiry| at >= expiry)
    {
        return Err(unavailable(
            "successor observation expired after the last accepting wait",
        ));
    }
    Ok(())
}

#[derive(QueryableByName)]
struct LocalStatus {
    #[diesel(sql_type=Bool)]
    enabled: bool,
    #[diesel(sql_type=Nullable<Text>)]
    state: Option<String>,
}
#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}

async fn known_account_denials(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
) -> PersistenceResult<()> {
    // The replica writer takes the exclusive form of this same key. Protect
    // absence as well as an existing head until the accepting transaction ends.
    sql_query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))")
        .bind::<Text, _>(format!("account-status:{}:{account}", account.station_id))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let local=sql_query("SELECT a.disabled_at IS NULL AS enabled,l.state FROM accounts a LEFT JOIN account_lifecycle l ON l.account_pk=a.pk WHERE a.principal_id=$1 AND a.station_id=$2 FOR SHARE OF a")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<LocalStatus>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if local.is_some_and(|row| {
        !row.enabled
            || row
                .state
                .as_ref()
                .is_some_and(|state| !matches!(state.as_str(), "active" | "soft_logged_out"))
    }) {
        return Err(denied("Account lifecycle refuses a new root operation"));
    }
    // Only already authenticated, durable AA records participate. A C
    // observation cannot erase a newer denial this governor already knows.
    let rows=sql_query("SELECT value FROM (SELECT DISTINCT ON(account_authority_id) record AS value FROM account_status_replica_records WHERE account_id=$1 ORDER BY account_authority_id,status_sequence DESC) heads")
        .bind::<Jsonb,_>(serde_json::to_value(account).map_err(PersistenceError::database)?)
        .get_results::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in rows {
        let record: arkret_models_collaboration::account_status::AccountStatusRecord =
            serde_json::from_value(row.value).map_err(PersistenceError::database)?;
        record.validate_shape().map_err(|error| denied(error))?;
        if record.account_id != *account
            || !matches!(
                record.status,
                AccountStatus::Active | AccountStatus::SoftLoggedOut
            )
        {
            return Err(denied(
                "known Account Authority status refuses a new root operation",
            ));
        }
    }
    Ok(())
}

/// Immutable native inception selects a lock; it does not establish current
/// eligibility. The shared planner locks this PCR and all business Realms in
/// one sorted set before any mutable source is evaluated.
async fn native_successor_pcr(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
) -> PersistenceResult<RealmId> {
    crate::agent_producer_signer_keys::immutable_human_pcr_in_connection(conn, account)
        .await?
        .ok_or_else(|| unavailable("local root participant native Human inception is unavailable"))
}

async fn require_ordinary_target(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> PersistenceResult<()> {
    if !matches!(
        crate::pcr_private_authority::accepted_governance(conn, &event.realm_id).await?,
        arkret_wire::GenesisGovernance::Collaboration
    ) {
        return Err(denied(
            "owner transfer is confined to an ordinary Collaboration Realm",
        ));
    }
    Ok(())
}

pub(crate) async fn candidate_realms(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> PersistenceResult<Vec<RealmId>> {
    if event.kind != EventKind::RealmOwnerTransfer {
        return Ok(Vec::new());
    }
    require_ordinary_target(conn, event).await?;
    let payload: RealmOwnerTransferPayload =
        serde_json::from_value(serde_json::json!(event.payload))
            .map_err(PersistenceError::database)?;
    let intent = payload
        .acceptance_intent(&event.scope_ref, &event.actor_id)
        .map_err(denied)?;
    let successor = intent.successor_account().map_err(denied)?;
    let governor = crate::agent_producer_signer_keys::governor_for_lock_plan_in_connection(
        conn,
        &event.realm_id,
    )
    .await?
    .ok_or_else(|| unavailable("owner transfer governor is unavailable for lock planning"))?;
    if successor.station_id == governor {
        return Ok(vec![native_successor_pcr(conn, successor).await?]);
    }
    Ok(Vec::new())
}

/// Repeat the actual author's existing source proof at the final clock. This
/// returns a local deadline only; it is not a transferable authorization fact.
pub(crate) async fn require_author_current(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    forwarded: Option<&coland_storage::ForwardedProducerDeviceEvidence>,
) -> PersistenceResult<(
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
)> {
    let event = &transaction.event;
    let producer = event
        .account_device_producer()
        .map_err(denied)?
        .ok_or_else(|| denied("root controller requires its original Account Device"))?;
    let original = transaction
        .producer_signer_fact
        .as_ref()
        .and_then(|fact| fact.as_account_device())
        .ok_or_else(|| unavailable("root controller original producer source is unavailable"))?;
    let at = chrono::Utc::now();
    if producer.account_id.station_id == transaction.expected_authority.service_id {
        let pcr = native_successor_pcr(conn, &producer.account_id).await?;
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, &pcr, &event.actor_id)
            .await?
            .require_open_business_mutation()?;
        crate::agent_producer_signer_keys::validate_account_device_fact_binding(
            event,
            &transaction.commit,
            Some(original),
        )?;
        let (current, authorization) =
            crate::agent_producer_signer_keys::native_current_human_device_source_in_connection(
                conn,
                &producer.account_id,
                &producer.device_id,
                at,
            )
            .await?;
        if current.key != original.key || current.accepted_at != original.accepted_at {
            return Err(denied(
                "root controller native source changed before final acceptance",
            ));
        }
        Ok((authorization.not_before, authorization.expires_at.flatten()))
    } else {
        let forwarded = forwarded.ok_or_else(|| {
            unavailable("foreign root controller has no complete original forward source")
        })?;
        let core = &forwarded.evidence.device_projection_attestation.attestation;
        let verified = arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
            &forwarded.evidence, event, &producer.account_id.station_id,
            &transaction.expected_authority.service_id,
            &core.event_authorization.forward_body_digest,
            event.realm_id.digest_suite_code().digest_suite(), at,
        ).map_err(|error| match error.error_code() {
            Some(arkret_wire::ErrorCode::DeviceUnauthorized) => {
                unavailable("root controller forward observation does not cover the final acceptance cut")
            }
            _ => denied(error),
        })?.into_fact();
        if verified != *original || forwarded.producer_signer_fact != *original {
            return Err(denied(
                "foreign root controller source differs from its original signature",
            ));
        }
        Ok((
            core.authorization_window.not_before.max(core.attested_at),
            Some(
                core.expires_at.min(
                    core.authorization_window
                        .expires_at
                        .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC),
                ),
            ),
        ))
    }
}

pub(crate) async fn require_creator(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    let producer = event
        .account_device_producer()
        .map_err(denied)?
        .ok_or_else(|| denied("ordinary Collaboration root requires a native Account Device"))?;
    if event.actor_id.as_account_id() != Some(&producer.account_id) {
        return Err(denied(
            "root creator must be the actual native Device signer",
        ));
    }
    let (source, _) =
        crate::agent_producer_signer_keys::native_current_human_device_source_in_connection(
            conn,
            &producer.account_id,
            &producer.device_id,
            commit.committed_at,
        )
        .await?;
    let guard = coland_storage::DeviceRevocationGateSelector {
        principal_id: producer.account_id.principal_id.clone(),
        station_id: producer.account_id.station_id.clone(),
        device_id: producer.device_id.to_string(),
        authorization_ref: source.key.authorization_ref,
    };
    crate::agent_producer_signer_keys::prepare_account_device_source_in_connection(
        conn,
        event,
        commit.committed_at,
        &guard,
    )
    .await?;
    known_account_denials(conn, &producer.account_id).await?;
    let (_, authorization) =
        crate::agent_producer_signer_keys::native_current_human_device_source_in_connection(
            conn,
            &producer.account_id,
            &producer.device_id,
            chrono::Utc::now(),
        )
        .await?;
    let final_now = chrono::Utc::now();
    if final_now < authorization.not_before
        || authorization
            .expires_at
            .flatten()
            .is_some_and(|expiry| final_now >= expiry)
    {
        return Err(unavailable(
            "root creator Device expired after the last accepting wait",
        ));
    }
    Ok(())
}

pub(crate) async fn require_source(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    source: &OwnerTransferSuccessorSource,
) -> PersistenceResult<()> {
    let event = &transaction.event;
    if event.kind != EventKind::RealmOwnerTransfer {
        return Err(PersistenceError::SchemaViolation(
            "successor source is confined to owner transfer".into(),
        ));
    }
    require_ordinary_target(conn, event).await?;
    let payload: RealmOwnerTransferPayload =
        serde_json::from_value(serde_json::json!(event.payload))
            .map_err(PersistenceError::database)?;
    let intent = payload
        .acceptance_intent(&event.scope_ref, &event.actor_id)
        .map_err(denied)?;
    let producer = event
        .account_device_producer()
        .map_err(denied)?
        .ok_or_else(|| denied("root control requires its actual Account Device producer"))?;
    if event.actor_id.as_account_id() != Some(&producer.account_id) {
        return Err(denied(
            "root controller cannot delegate its native signature to another actor",
        ));
    }
    let account = intent.successor_account().map_err(denied)?;
    for actor in [&event.actor_id, &ActorId::account(account.clone())] {
        let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
            conn,
            &event.realm_id,
            actor,
        )
        .await?;
        cut.require_open_lifecycle(event)?;
        cut.require_governed_member(&event.kind)?;
    }
    known_account_denials(conn, &producer.account_id).await?;
    known_account_denials(conn, account).await?;
    if account.station_id == transaction.expected_authority.service_id {
        let pcr = native_successor_pcr(conn, account).await?;
        crate::realm_authorization_cut::RealmAuthorizationCut::read(
            conn,
            &pcr,
            &ActorId::account(account.clone()),
        )
        .await?
        .require_open_business_mutation()?;
        let device = intent
            .successor_device(&payload.successor_acceptance)
            .map_err(denied)?;
        // A local known denial is read from the real current cut. Do not
        // acquire B's PCR writer lock after this Realm's writer locks.
        let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
            conn,
            account,
            &device,
            chrono::Utc::now(),
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)?
        .ok_or_else(|| unavailable("local successor current PCR cut is unavailable"))?;
        let core = &source.evidence().device_projection_attestation.attestation;
        if cut.authority.realm_id != pcr
            || cut.admission() != arkret_wire::AccountDeviceRevocationAdmissionDecision::Allow
            || cut.authority.current_generation != Some(core.authorized_generation_ref)
            || cut
                .authority
                .authorization
                .as_ref()
                .is_none_or(|authorization| {
                    authorization.event_id != core.device_authorize_event_id
                        || authorization.payload.device_public_key_did.as_str()
                            != core.device_signing_key_did.as_str()
                        || authorization.payload.hpke_key != core.hpke_key
                        || authorization.payload.not_before != core.authorization_window.not_before
                        || authorization.payload.expires_at.flatten()
                            != core.authorization_window.expires_at
                })
        {
            return Err(denied("local successor Device source is no longer current"));
        }
    }
    // Both signed Commit time and the clock after every wait must be covered.
    // The same check at the original Commit time later verifies the archive.
    for at in [transaction.commit.committed_at, chrono::Utc::now()] {
        arkret_identity::account_device_signer_evidence::verify_owner_transfer_successor_evidence(
            source.evidence(),
            &intent,
            &payload.successor_acceptance,
            at,
        )
        .map_err(|error| match error.error_code() {
            Some(arkret_wire::ErrorCode::DeviceUnauthorized) => {
                unavailable("successor observation does not cover the final acceptance cut")
            }
            _ => denied(error),
        })?;
    }
    Ok(())
}

pub(crate) async fn retain_source(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    source: &OwnerTransferSuccessorSource,
) -> PersistenceResult<()> {
    let body = serde_json::to_value(source.evidence()).map_err(PersistenceError::database)?;
    let written=sql_query("UPDATE canonical_events e SET successor_device_evidence_json=$1 WHERE e.envelope->>'event_id'=$2 AND e.realm_id=$3 AND e.kind='ak.realm.owner.transfer' AND e.state='committed' AND EXISTS(SELECT 1 FROM realm_commits c WHERE c.event_pk=e.pk AND c.commit_id=$4) AND (e.successor_device_evidence_json IS NULL OR e.successor_device_evidence_json=$1)")
        .bind::<Jsonb,_>(body).bind::<Text,_>(transaction.event.event_id.as_str())
        .bind::<Text,_>(transaction.event.realm_id.as_str()).bind::<Text,_>(transaction.commit.commit_id.as_str())
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: immutable successor source differs from its accepted original"
                .into(),
        ));
    }
    Ok(())
}
