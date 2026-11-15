//! Account lifecycle at a delegated Service recording-ready accepting cut.
//! An independent Service act and an immutable accepted replay never enter here.
use arkret_models_collaboration::account_status::{AccountStatusReceipt, AccountStatusRecord};
use arkret_models_collaboration::events_payloads::call::{CallRecordingState, CallStatePayload};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_wire::{AccountId, ActorId, DidCoreId, Event, EventKind, RealmId};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Bool, Jsonb, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};

#[derive(QueryableByName)]
struct Governor {
    #[diesel(sql_type=Text)]
    service_id: String,
}
#[derive(QueryableByName)]
struct NativePcr {
    #[diesel(sql_type=Text)]
    realm_id: String,
}
#[derive(QueryableByName)]
struct Head {
    #[diesel(sql_type=Jsonb)]
    record: serde_json::Value,
    #[diesel(sql_type=Jsonb)]
    receipt: serde_json::Value,
}
#[derive(QueryableByName)]
struct Product {
    #[diesel(sql_type=Bool)]
    enabled: bool,
    #[diesel(sql_type=Nullable<Text>)]
    state: Option<String>,
}
fn unknown(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "revision_unavailable: delegated Call Account {detail}"
    ))
}
fn inactive(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "failed_precondition: delegated Call Account {detail}"
    ))
}
fn account(event: &Event) -> PersistenceResult<Option<&AccountId>> {
    if event.kind != EventKind::CallState
        || !matches!(event.executed_by, Some(ActorId::Service { .. }))
    {
        return Ok(None);
    }
    let Some(account) = event.actor_id.as_account_id() else {
        return Ok(None);
    };
    let payload: CallStatePayload = serde_json::from_value(serde_json::json!(event.payload))
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    payload.validate().map_err(|error| {
        PersistenceError::SchemaViolation(format!("invalid delegated Call ready payload: {error}"))
    })?;
    Ok(payload
        .recording_transition
        .as_ref()
        .is_some_and(|transition| transition.to == CallRecordingState::Ready)
        .then_some(account))
}
async fn governor(conn: &mut AsyncPgConnection, realm: &RealmId) -> PersistenceResult<DidCoreId> {
    let row = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<Governor>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| unknown("accepting Station is unavailable"))?;
    DidCoreId::new(row.service_id).map_err(unknown)
}
async fn native_pcr(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
) -> PersistenceResult<Option<RealmId>> {
    let rows = sql_query("SELECT realm_id FROM pcr_genesis_units WHERE principal_id=$1 AND station_id=$2 UNION SELECT c.realm_id FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk JOIN agent_producer_signer_keys s ON s.commit_id=c.commit_id WHERE e.kind='ak.realm.create' AND e.state='committed' AND e.envelope->'actor_id'=$3 AND e.envelope->'payload'->'object'->>'purpose'='agent_control' AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',c.realm_id) AND c.stream_position=0 AND c.governance_generation=0 AND s.self_admission_kind='agent_pcr_genesis'")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .bind::<Jsonb,_>(serde_json::json!(ActorId::account(account.clone())))
        .load::<NativePcr>(&mut *conn).await.map_err(PersistenceError::database)?;
    if rows.len() > 1 {
        return Err(unknown("has more than one accepted native inception"));
    }
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let realm = RealmId::new(row.realm_id).map_err(unknown)?;
    // The locator selects only a lock. Bind it to the retained inception,
    // without evaluating mutable lifecycle or granting authority before replay.
    let original = crate::pcr_private_authority::accepted_governance(conn, &realm).await?;
    if !matches!(original, arkret_wire::GenesisGovernance::Human(ref holder) | arkret_wire::GenesisGovernance::Agent(ref holder) if holder == account)
    {
        return Err(unknown("PCR locator differs from its accepted inception"));
    }
    Ok(Some(realm))
}
/// Return candidates to the existing shared lock planner. No lock or current
/// lifecycle verdict is taken independently of that planner's whole set.
pub(super) async fn candidate_realms(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> PersistenceResult<Vec<RealmId>> {
    let Some(account) = account(event)? else {
        return Ok(Vec::new());
    };
    let station = governor(conn, &event.realm_id).await?;
    if account.station_id == station {
        let pcr = native_pcr(conn, account)
            .await?
            .ok_or_else(|| unknown("has no accepted native inception for lock planning"))?;
        return Ok(vec![pcr]);
    }
    Ok(Vec::new())
}
/// Only the actual Account actor is gated; an issuer is not an actor.
pub(super) async fn require_active(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> PersistenceResult<()> {
    let Some(account) = account(event)? else {
        return Ok(());
    };
    // The UoW already acquired the PCR, target and all other participants in
    // the existing shared planner's one globally sorted Realm lock set.
    let station = governor(conn, &event.realm_id).await?;
    // The exact existing replica-writer key also protects the initial absence
    // of a checkpoint until this Event's accepting transaction has completed.
    sql_query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))")
        .bind::<Text, _>(format!("account-status:{}:{account}", account.station_id))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let head = sql_query("SELECT record,receipt FROM account_status_replica_records WHERE account_authority_id=$1 AND account_id=$2 ORDER BY status_sequence DESC LIMIT 1")
        .bind::<Text,_>(account.station_id.as_str()).bind::<Jsonb,_>(serde_json::json!(account))
        .get_result::<Head>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let local_pcr = if account.station_id == station {
        let pcr = crate::pcr_private_authority::lock_holder(conn, account, Some(&station)).await?;
        let lifecycle = super::RealmLifecycleGates::read(conn, &pcr.realm_id).await?;
        if lifecycle.terminal || lifecycle.archived || lifecycle.frozen {
            return Err(inactive("native PCR no longer admits a new Account act"));
        }
        Some(pcr.realm_id)
    } else {
        None
    };
    if let Some(head) = head {
        let record: AccountStatusRecord = serde_json::from_value(head.record).map_err(unknown)?;
        let receipt: AccountStatusReceipt =
            serde_json::from_value(head.receipt).map_err(unknown)?;
        receipt.validate_for_record(&record).map_err(unknown)?;
        if record.account_id != *account
            || record.account_authority_id != account.station_id
            || receipt.receiver_id != station
            || local_pcr
                .as_ref()
                .is_some_and(|pcr| pcr != &record.principal_control_realm_id)
        {
            return Err(unknown("checkpoint differs from actor/PCR/acceptor"));
        }
        let terminal = match record.status {
            AccountStatus::Deactivated => Some(coland_storage::ConflictCode::AccountDeactivated),
            AccountStatus::ErasurePending => Some(coland_storage::ConflictCode::AccountErased),
            _ => None,
        };
        if let Some(code) = terminal {
            return Err(PersistenceError::Conflict(format!(
                "{code}: delegated Call Account is {}",
                record.status.as_str()
            )));
        }
        // Soft logout terminates the Human session chain, not this independently
        // authenticated Service capability. Locked/suspended ordinary writes
        // remain refused; deactivation/erasure are mandatory barriers.
        if !matches!(
            record.status,
            AccountStatus::Active | AccountStatus::SoftLoggedOut
        ) {
            return Err(inactive(format!("is {}", record.status.as_str())));
        }
    } else if local_pcr.is_none() {
        return Err(unknown("has no authenticated origin lifecycle checkpoint"));
    }
    // Accepted local Account inception establishes the legitimate initial state;
    // neither an absent status publication nor an optional product row denies
    // it. Existing product rows retain their actual lifecycle-writer lock.
    let product = sql_query("SELECT a.disabled_at IS NULL AS enabled,l.state FROM accounts a LEFT JOIN account_lifecycle l ON l.account_pk=a.pk WHERE a.principal_id=$1 AND a.station_id=$2 FOR SHARE OF a")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<Product>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if product.is_some_and(|row| {
        !row.enabled
            || row
                .state
                .as_ref()
                .is_some_and(|state| !matches!(state.as_str(), "active" | "soft_logged_out"))
    }) {
        return Err(inactive("product lifecycle is not active"));
    }
    Ok(())
}
