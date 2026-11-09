//! Completed native identity evidence for subsequent content recovery.
//!
//! No caller-supplied receipt, current DID document, live recovery session or
//! current factor substitutes for the original accepted two-Event unit.

use arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind;
use arkret_models_crypto::{SecurityTransactionStep, SecurityTransactionTerminalOutcome};
use arkret_wire::{
    CommitStreamHead, Event, EventId, RealmCommit, RealmId, RecoveryCompletionAttestation,
};
use coland_storage::{
    AuthorityCommitTransaction, HumanPcrHistoryReader, PersistenceError, PersistenceResult,
    RecoveryUnitCommitWrite,
};
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
async fn original(
    conn: &mut AsyncPgConnection,
    event_id: &EventId,
    realm: &RealmId,
) -> PersistenceResult<(Event, RealmCommit)> {
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
        || event.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            })
        || event
            .derive_event_id_with_digest_suite(suite)
            .map_err(unavailable)?
            != *event_id
        || preimage != row.canonical_bytes
        || commit.event_ref != *event_id
    {
        return Err(unavailable("original bytes or covering Commit disagree"));
    }
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
           AND prepared_plan->'binding'->>'authorize_event_id'=$3 \
           AND terminal_outcome->>'outcome'='completed' LIMIT 2",
    )
    .bind::<Text, _>(reader.account_id.principal_id.as_str())
    .bind::<Text, _>(reader.account_id.station_id.as_str())
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
    let plan = transaction
        .resource
        .recovery_plan()
        .ok_or_else(|| unavailable("transaction has no recovery plan"))?;
    let Some(SecurityTransactionTerminalOutcome::Completed {
        completion_attestation: Some(completion),
        ..
    }) = &transaction.resource.terminal_outcome
    else {
        return Err(unavailable(
            "transaction has no completed native attestation",
        ));
    };
    let completion = completion.clone();
    if transaction.resource.account_id != reader.account_id
        || plan.binding.replacement_device_id != reader.device_id
        || plan.binding.authorize_event_id != authorization.event_id
        || authorization.payload.recovery_session_id.as_ref()
            != Some(&plan.binding.recovery_session_id)
        || cut.authority.current_generation != Some(plan.new_model_generation_ref)
        || authorization.payload.authorized_generation_ref != plan.new_model_generation_ref
        || authorization.source_commit_id != completion.device_authorization_event_ref.commit_id
        || plan.reanchor_commit_intent.realm_id != realm
    {
        return Err(unavailable(
            "replacement, generation or original authorization differs",
        ));
    }
    let reanchor = original(conn, &plan.binding.reanchor_event_id, &realm).await?;
    let authorize = original(conn, &plan.binding.authorize_event_id, &realm).await?;
    arkret_signatures::verify_device_authorize_possession(
        &authorization.payload,
        &reader.account_id,
    )
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
        if event.actor_id.as_account_id() != Some(&reader.account_id)
            || producer.account_id != reader.account_id
            || producer.device_id != reader.device_id
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
    let step_outcome = super::load_step_outcome(
        conn,
        &transaction_id,
        SecurityTransactionStep::CommitRecoveryUnit,
    )
    .await?
    .ok_or_else(|| unavailable("atomic terminal step is absent"))?;
    let attempt = super::load_step_attempt(
        conn,
        &transaction_id,
        SecurityTransactionStep::CommitRecoveryUnit,
    )
    .await?
    .ok_or_else(|| unavailable("atomic terminal attempt is absent"))?;
    if attempt.canonical_request != step_outcome.canonical_request {
        return Err(unavailable(
            "terminal attempt differs from its accepted outcome",
        ));
    }
    let authority = crate::authority_commit::locked_authority(conn, &realm)
        .await
        .map_err(crate::PgTransactionError::into_persistence)?
        .ok_or_else(|| unavailable("PCR authority disappeared"))?;
    let predecessor = sql_query(
        "SELECT commit_json AS payload FROM realm_commits WHERE commit_id=$1 AND realm_id=$2",
    )
    .bind::<Text, _>(plan.reanchor_commit_intent.predecessor_ref.as_str())
    .bind::<Text, _>(realm.as_str())
    .get_result::<crate::JsonPayloadRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| unavailable("accepted predecessor is absent"))?;
    let predecessor: RealmCommit =
        serde_json::from_value(predecessor.payload).map_err(unavailable)?;
    let wrap = |(event, commit)| AuthorityCommitTransaction {
        expected_authority: authority.clone(),
        event,
        commit,
        producer_signer_fact: None,
        content_backup_source: None,
        mls_state: None,
        welcomes: Vec::new(),
        recipient_queue_capacity: 0,
    };
    let write = RecoveryUnitCommitWrite {
        queued_at: transaction.resource.created_at,
        transaction,
        step_outcome,
        predecessor: CommitStreamHead {
            stream_ref: predecessor.stream_ref,
            stream_position: predecessor.stream_position,
            commit_id: predecessor.commit_id,
        },
        commits: [wrap(reanchor), wrap(authorize)],
    };
    write.validate().map_err(unavailable)?;
    if chrono::Utc::now() >= expires_at {
        return Err(unavailable("current replacement credential expired"));
    }
    Ok(completion)
}
