//! Completed native identity evidence for subsequent content recovery.
//!
//! No caller-supplied receipt, current DID document, live recovery session or
//! current factor substitutes for the original accepted two-Event unit.

use arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind;
use arkret_models_crypto::SecurityTransactionCreateRequestBody;
use arkret_wire::{
    CommittedEventRef, Event, EventId, RealmCommit, RealmId, RecoveryCompletionAttestation,
};
use coland_storage::{HumanPcrHistoryReader, PersistenceError, PersistenceResult};
use diesel::sql_types::{Binary, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension as _, RunQueryDsl as _};

use crate::AsyncPgConnection;

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "failed_precondition: content recovery source {detail}"
    ))
}

#[derive(QueryableByName)]
struct SourceRow {
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
}

/// Load a native original, checking its stored canonical preimage as well as
/// the complete suite-tagged Event ID. Neither a current row nor an envelope
/// with copied coordinates is original recovery evidence.
pub(super) async fn original(
    conn: &mut AsyncPgConnection,
    event_id: &EventId,
    realm: &RealmId,
) -> PersistenceResult<(Event, RealmCommit)> {
    original_in_scope(
        conn,
        event_id,
        &arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
    )
    .await
}

pub(super) async fn original_in_scope(
    conn: &mut AsyncPgConnection,
    event_id: &EventId,
    scope: &arkret_wire::ScopeRef,
) -> PersistenceResult<(Event, RealmCommit)> {
    let realm = scope
        .realm_id_opt()
        .ok_or_else(|| unavailable("original has no effective Realm"))?;
    let token = crate::ids::parse_event_id(event_id.as_str())
        .ok_or_else(|| unavailable("Event ID is invalid"))?;
    let row = sql_query(
        "SELECT e.envelope,c.commit_json,e.canonical_bytes FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.state='committed'",
    )
    .bind::<Binary, _>(token.to_vec())
    .get_result::<SourceRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| unavailable("accepted original is absent"))?;
    let event: Event = serde_json::from_value(row.envelope).map_err(unavailable)?;
    let commit: RealmCommit = serde_json::from_value(row.commit_json).map_err(unavailable)?;
    let suite = realm.digest_suite_code().digest_suite();
    let preimage =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().map_err(unavailable)?)
            .map_err(unavailable)?;
    if event.event_id != *event_id
        || event.realm_id != *realm
        || &event.scope_ref != scope
        || commit.realm_id != *realm
        || commit.stream_ref
            != arkret_wire::CommitStreamRef::from_scope(scope, None).map_err(unavailable)?
        || event
            .derive_event_id_with_digest_suite(suite)
            .map_err(unavailable)?
            != *event_id
        || preimage != row.canonical_bytes
        || commit.event_ref != *event_id
    {
        return Err(unavailable("original bytes or covering Commit disagree"));
    }
    commit
        .verify_commit_id_matches_content()
        .map_err(unavailable)?;
    Ok((event, commit))
}

/// The caller owns a transaction. The PCR authority lock remains held while
/// current-device qualification and the complete immutable source are read.
/// This function deliberately does not authorize any MLS transition.
pub(super) async fn qualify_in_connection(
    conn: &mut AsyncPgConnection,
    reader: &HumanPcrHistoryReader,
) -> PersistenceResult<RecoveryCompletionAttestation> {
    let initial = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        &reader.account_id,
        &reader.device_id,
        chrono::Utc::now(),
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?
    .ok_or_else(|| unavailable("replacement has no accepted PCR"))?;
    let realm = initial.authority.realm_id;
    let expires_at =
        crate::pcr_history_read::qualify(conn, reader, &realm, &reader.account_id.station_id)
            .await?;
    let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        &reader.account_id,
        &reader.device_id,
        chrono::Utc::now(),
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?
    .ok_or_else(|| unavailable("replacement cut disappeared"))?;
    let completion = native_completion(conn, &reader.account_id, &reader.device_id, cut).await?;
    if chrono::Utc::now() >= expires_at {
        return Err(unavailable("current replacement credential expired"));
    }
    Ok(completion)
}

/// Verify the signed identity unit independently of inventory input. The
/// coordinator already holds the PCR owner lock; an HTTP reader also needs
/// its own current credential and delivery lease.
pub(super) async fn native_completion(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    device: &arkret_wire::DeviceId,
    cut: crate::pcr_device_status_reader::ConfirmedPcrDeviceStatusCut,
) -> PersistenceResult<RecoveryCompletionAttestation> {
    let realm = cut.authority.realm_id.clone();
    let authorization = cut
        .authority
        .authorization
        .ok_or_else(|| unavailable("replacement authorization is absent"))?;
    if authorization.payload.authorization_binding_kind
        != DeviceAuthorizationBindingKind::PcrRecovery
    {
        return Err(unavailable(
            "ordinary Device authorization is not a recovery unit",
        ));
    }
    #[derive(QueryableByName)]
    struct TransactionIdRow {
        #[diesel(sql_type = Text)]
        transaction_id: String,
    }
    let candidates = sql_query(
        "SELECT id::text AS transaction_id FROM security_transactions \
         WHERE kind='recovery' AND principal_id=$1 AND station_id=$2 \
           AND recovery_completion->'completion_attestation'->'device_authorization_event_ref'->>'event_id'=$3 LIMIT 2",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .bind::<Text, _>(authorization.event_id.as_str())
    .get_results::<TransactionIdRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let [candidate] = candidates.as_slice() else {
        return Err(unavailable(
            "exact completed native transaction is not unique",
        ));
    };
    let transaction_id = format!("ak:transaction:{}", candidate.transaction_id);
    let transaction = super::load_one(conn, &transaction_id, false)
        .await?
        .ok_or_else(|| unavailable("native transaction disappeared"))?;
    let completed = transaction.recovery().map_err(unavailable)?;
    let receipt = &completed.recovery_receipt;
    let completion = completed.completion_attestation.clone();
    if completed.account_id != *account
        || receipt.new_device_id != *device
        || receipt.recovery_unit.events[1].event.event_id != authorization.event_id
        || authorization.payload.recovery_session_id.as_ref() != Some(&receipt.recovery_session_id)
        || cut.authority.current_generation != Some(receipt.new_model_generation_ref)
        || authorization.payload.authorized_generation_ref != receipt.new_model_generation_ref
        || authorization.source_commit_id != completion.device_authorization_event_ref.commit_id
        || receipt.recovery_unit.events[0].event.realm_id != realm
    {
        return Err(unavailable(
            "replacement, generation or original authorization differs",
        ));
    }
    let request: SecurityTransactionCreateRequestBody =
        serde_json::from_slice(&transaction.canonical_request).map_err(unavailable)?;
    if arkret_canonical::canonical_json_bytes(&request).map_err(unavailable)?
        != transaction.canonical_request
    {
        return Err(unavailable(
            "first signed R request bytes are not canonical",
        ));
    }
    let SecurityTransactionCreateRequestBody::Recovery(request) = request else {
        return Err(unavailable(
            "accepted request is another transaction branch",
        ));
    };
    completed
        .validate_for_request(&request)
        .map_err(unavailable)?;
    let reanchor = original(
        conn,
        &receipt.recovery_unit.events[0].event.event_id,
        &realm,
    )
    .await?;
    let authorize = original(
        conn,
        &receipt.recovery_unit.events[1].event.event_id,
        &realm,
    )
    .await?;
    let committed_ref = |item: &(Event, RealmCommit)| CommittedEventRef {
        event_id: item.0.event_id.clone(),
        commit_id: item.1.commit_id.clone(),
        stream_ref: item.1.stream_ref.clone(),
        stream_position: item.1.stream_position,
    };
    if reanchor.0 != receipt.recovery_unit.events[0].event
        || authorize.0 != receipt.recovery_unit.events[1].event
        || reanchor.1.previous_commit_ref.as_ref() != Some(&receipt.recovery_unit.predecessor_ref)
        || authorize.1.previous_commit_ref.as_ref() != Some(&reanchor.1.commit_id)
        || completion.reanchor_event_ref != committed_ref(&reanchor)
        || completion.device_authorization_event_ref != committed_ref(&authorize)
    {
        return Err(unavailable(
            "original consecutive Commit pair differs from signed R/C",
        ));
    }
    arkret_signatures::verify_device_authorize_possession(&authorization.payload, account)
        .map_err(unavailable)?;
    let device_key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: authorization
            .payload
            .device_public_key_did
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| unavailable("replacement public key is not did:key"))?
            .to_owned(),
    };
    for event in [&reanchor.0, &authorize.0] {
        let producer = event
            .account_device_producer()
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("original has no actual Device producer"))?;
        if event.actor_id.as_account_id() != Some(account)
            || producer.account_id != *account
            || producer.device_id != *device
            || event.executed_by.is_some()
        {
            return Err(unavailable(
                "original is not self-signed by the exact replacement",
            ));
        }
        let bytes = arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(event)
            .map_err(unavailable)?;
        arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            event
                .producer_proof
                .as_ref()
                .ok_or_else(|| unavailable("original proof is absent"))?,
            &bytes,
            &event.actor_id,
            &device_key,
            realm.digest_suite_code().digest_suite(),
        )
        .map_err(unavailable)?;
    }
    let predecessor = sql_query(
        "SELECT commit_json AS payload FROM realm_commits WHERE commit_id=$1 AND realm_id=$2",
    )
    .bind::<Text, _>(receipt.recovery_unit.predecessor_ref.as_str())
    .bind::<Text, _>(realm.as_str())
    .get_result::<crate::JsonPayloadRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| unavailable("accepted independent predecessor disappeared"))?;
    let predecessor: RealmCommit =
        serde_json::from_value(predecessor.payload).map_err(unavailable)?;
    if predecessor.stream_ref != reanchor.1.stream_ref
        || predecessor.stream_position + 1 != reanchor.1.stream_position
    {
        return Err(unavailable(
            "independent accepted predecessor does not precede the native pair",
        ));
    }
    Ok(completion)
}
