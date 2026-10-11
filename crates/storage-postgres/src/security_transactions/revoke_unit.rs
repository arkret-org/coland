//! The PCR proposal boundary of SecurityRotation. The producer and authority
//! signatures are verified by the admission service before constructing the
//! unit; this transaction rechecks their exact durable current dependencies.

use arkret_models_collaboration::events_payloads::{DeviceOrPrincipalRef, DeviceRevokePayload};
use arkret_wire::RealmCommit;
use coland_storage::{
    AuthorityCommitWriteOutcome, ConflictCode, PersistenceError, RevokeCommandTerminalWrite,
    RevokeProposalCommitWrite, SecurityTransactionRecord,
};
use diesel::sql_types::{Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;

use super::{
    AsyncPgConnection, PgTransactionError, StepAttemptSource, accept_step_in_transaction, ids,
    load_one, load_step_outcome, update_mutable_fields,
};
use crate::authority_commit::{
    commit_verified_pcr_revoke_proposal_in_connection, queue_event_in_connection,
};
use crate::pcr_device_status_fold::PcrDeviceLifecycle;
use crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection;

#[derive(QueryableByName)]
struct RealmLockRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

#[derive(QueryableByName)]
struct AcceptedProposalRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
}

#[derive(QueryableByName)]
struct ProposalDotRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
}

/// Every refusal carries a registered [`ConflictCode`] prefix so the serving
/// layer can map it to a wire code without reading diagnostics.
fn rejected(code: ConflictCode, reason: &str) -> PgTransactionError {
    PersistenceError::Conflict(format!("{code}: {reason}")).into()
}

fn authorizer_status_code(lifecycle: PcrDeviceLifecycle) -> ConflictCode {
    match lifecycle {
        PcrDeviceLifecycle::Revoked => ConflictCode::DeviceRevoked,
        PcrDeviceLifecycle::RevocationPending => ConflictCode::DeviceRevocationPending,
        PcrDeviceLifecycle::Active
        | PcrDeviceLifecycle::GenerationFenced
        | PcrDeviceLifecycle::Expired
        | PcrDeviceLifecycle::NotYetEffective => ConflictCode::FailedPrecondition,
    }
}

pub(super) async fn commit_revoke_command_terminal_in_connection(
    conn: &mut AsyncPgConnection,
    write: RevokeCommandTerminalWrite,
) -> Result<SecurityTransactionRecord, PgTransactionError> {
    use arkret_models_crypto::{SecurityRotationRevokeCommandDecision, SecurityTransactionStep};

    write.validate()?;
    let resource = &write.transaction.resource;
    let proposal = resource.revoke_proposal.as_ref().expect("validated");
    let outcome = resource.revoke_command_outcome.as_ref().expect("validated");
    let existing = load_one(conn, resource.transaction_id.as_str(), true)
        .await?
        .ok_or_else(|| {
            rejected(
                ConflictCode::FailedPrecondition,
                "rotation transaction is absent",
            )
        })?;
    if existing.canonical_request != write.transaction.canonical_request {
        return Err(rejected(
            ConflictCode::DuplicateConflict,
            "rotation terminal changed its original canonical request",
        ));
    }
    let accepted = sql_query(
        "SELECT c.commit_json,e.envelope FROM realm_commits c \
         JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1",
    )
    .bind::<Text, _>(proposal.covering_commit_id.as_str())
    .get_result::<AcceptedProposalRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| {
        rejected(
            ConflictCode::DependencyMissing,
            "rotation terminal has no accepted proposal Event/Commit",
        )
    })?;
    let dot = sql_query("SELECT commit_id FROM pcr_device_revocation_proposals WHERE event_id=$1")
        .bind::<Text, _>(proposal.proposal_event_id.as_str())
        .get_result::<ProposalDotRow>(&mut *conn)
        .await
        .optional()?
        .ok_or_else(|| {
            rejected(
                ConflictCode::DependencyMissing,
                "rotation terminal has no immutable proposal dot",
            )
        })?;
    let plan = resource.security_rotation_plan().expect("validated");
    if dot.commit_id != proposal.covering_commit_id.as_str()
        || accepted.commit_json["commit_id"].as_str() != Some(proposal.covering_commit_id.as_str())
        || accepted.commit_json["event_ref"].as_str() != Some(proposal.proposal_event_id.as_str())
        || accepted.envelope
            != serde_json::to_value(&plan.revoke_unit.request.events[0])
                .map_err(PersistenceError::database)?
    {
        return Err(rejected(
            ConflictCode::DuplicateConflict,
            "rotation terminal differs from its accepted proposal",
        ));
    }
    if existing.resource == *resource {
        let durable = load_step_outcome(
            conn,
            resource.transaction_id.as_str(),
            SecurityTransactionStep::Revoke,
        )
        .await?;
        match (
            outcome.result,
            write.step_outcome.as_ref(),
            durable.as_ref(),
        ) {
            (SecurityRotationRevokeCommandDecision::Accepted, Some(presented), Some(stored))
                if presented.canonical_request == stored.canonical_request
                    && presented.response == stored.response
                    && presented.participant_outcome == stored.participant_outcome => {}
            (SecurityRotationRevokeCommandDecision::Rejected, None, None) => {}
            _ => {
                return Err(rejected(
                    ConflictCode::DuplicateConflict,
                    "rotation terminal exact replay changed its outcome",
                ));
            }
        }
        return Ok(existing);
    }
    let mut initial = resource.clone();
    initial.revoke_command_outcome = None;
    initial.accepted_steps.clear();
    initial.terminal_outcome = None;
    if existing.resource != initial {
        return Err(rejected(
            ConflictCode::DuplicateConflict,
            "rotation terminal changed its accepted proposal or first result",
        ));
    }
    match outcome.result {
        SecurityRotationRevokeCommandDecision::Accepted => {
            accept_step_in_transaction(
                conn,
                write.transaction.clone(),
                write.step_outcome.expect("validated"),
                StepAttemptSource::CoCommittedWithOutcome,
            )
            .await?;
            crate::pcr_device_current_results::publish_device_list_change_in_connection(
                conn,
                &resource.account_id,
            )
            .await?;
        }
        SecurityRotationRevokeCommandDecision::Rejected => {
            coland_storage::validate_security_transaction_update(&existing, &write.transaction)?;
            update_mutable_fields(conn, &write.transaction).await?;
        }
    }
    load_one(conn, resource.transaction_id.as_str(), false)
        .await?
        .ok_or_else(|| {
            rejected(
                ConflictCode::FailedPrecondition,
                "rotation terminal vanished after write",
            )
        })
}

pub(super) async fn commit_revoke_proposal_in_connection(
    conn: &mut AsyncPgConnection,
    write: RevokeProposalCommitWrite,
) -> Result<RealmCommit, PgTransactionError> {
    write.validate()?;
    let resource = &write.transaction.resource;
    let event = &write.commit.event;
    let commit = &write.commit.commit;
    let authorizer = resource.authorizing_device_id.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::FailedPrecondition,
            "rotation authorizing device is absent",
        )
    })?;
    let payload: DeviceRevokePayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| {
        rejected(
            ConflictCode::SchemaViolation,
            &format!("revoke payload is invalid: {error}"),
        )
    })?;
    payload
        .validate()
        .map_err(|error| rejected(ConflictCode::SchemaViolation, &error.to_string()))?;
    if !matches!(&payload.revoked_by, DeviceOrPrincipalRef::DeviceId(id) if id == authorizer) {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "revoke producer differs from the rotation authorizing device",
        ));
    }
    let actor = event.actor_id.as_account_id().ok_or_else(|| {
        rejected(
            ConflictCode::FailedPrecondition,
            "revoke actor is not the transaction Account",
        )
    })?;
    if actor != &resource.account_id || event.executed_by.is_some() {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "revoke actor or executor differs from the transaction",
        ));
    }
    let proof = event.producer_proof.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::SignatureInvalid,
            "revoke producer proof is absent",
        )
    })?;

    // Every accepted PCR writer takes this row lock before changing its head.
    // Reading device status after it prevents a stale authorization from being
    // used while this proposal advances the same Realm stream.
    let lock = sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
        .bind::<Text, _>(event.realm_id.as_str())
        .get_result::<RealmLockRow>(&mut *conn)
        .await
        .optional()?
        .ok_or_else(|| rejected(ConflictCode::FailedPrecondition, "PCR authority is absent"))?;
    if lock.realm_id != event.realm_id.as_str() {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "PCR authority lock differs from Event Realm",
        ));
    }
    let transaction_id = resource.transaction_id.as_str();
    let existing = load_one(conn, transaction_id, true).await?.ok_or_else(|| {
        rejected(
            ConflictCode::FailedPrecondition,
            "rotation transaction is absent",
        )
    })?;
    let mut proposal_state = existing.resource.clone();
    proposal_state.revoke_command_outcome = None;
    proposal_state.accepted_steps.clear();
    proposal_state.terminal_outcome = None;
    if proposal_state == *resource
        && existing.canonical_request == write.transaction.canonical_request
    {
        let accepted = sql_query(
            "SELECT c.commit_json,e.envelope FROM realm_commits c \
             JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1",
        )
        .bind::<Text, _>(commit.commit_id.as_str())
        .get_result::<AcceptedProposalRow>(&mut *conn)
        .await
        .optional()?
        .ok_or_else(|| {
            rejected(
                ConflictCode::DependencyMissing,
                "rotation proposal retry has no accepted Event/Commit",
            )
        })?;
        let dot =
            sql_query("SELECT commit_id FROM pcr_device_revocation_proposals WHERE event_id=$1")
                .bind::<Text, _>(event.event_id.as_str())
                .get_result::<ProposalDotRow>(&mut *conn)
                .await
                .optional()?
                .ok_or_else(|| {
                    rejected(
                        ConflictCode::DependencyMissing,
                        "rotation proposal retry has no immutable dot",
                    )
                })?;
        if accepted.commit_json
            != serde_json::to_value(commit).map_err(PersistenceError::database)?
            || accepted.envelope
                != serde_json::to_value(event).map_err(PersistenceError::database)?
            || dot.commit_id != commit.commit_id.as_str()
        {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "rotation proposal exact replay differs",
            ));
        }
        return Ok(commit.clone());
    }
    let status = confirmed_pcr_device_status_cut_in_connection(
        conn,
        &resource.account_id,
        authorizer,
        commit.committed_at,
    )
    .await?
    .ok_or_else(|| {
        rejected(
            ConflictCode::FailedPrecondition,
            "rotation authorizing device has no confirmed PCR cut",
        )
    })?;
    let authorization = status.authority.authorization.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::FailedPrecondition,
            "rotation authorizing device has no authorization",
        )
    })?;
    if status.authority.realm_id != event.realm_id || status.lifecycle != PcrDeviceLifecycle::Active
    {
        return Err(rejected(
            authorizer_status_code(status.lifecycle),
            "rotation authorizing device is not active at this PCR cut",
        ));
    }
    let did_key = authorization
        .payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            rejected(
                ConflictCode::SignatureInvalid,
                "current device authorization has no did:key public key",
            )
        })?;
    let public_key =
        arkret_canonical::multibase::decode_ed25519_multibase(did_key).map_err(|_| {
            rejected(
                ConflictCode::SignatureInvalid,
                "current device authorization key is invalid",
            )
        })?;
    let envelope_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| {
            rejected(
                ConflictCode::SignatureInvalid,
                &format!("revoke proof envelope is invalid: {error}"),
            )
        })?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &envelope_bytes,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: public_key.to_vec(),
        },
        arkret_canonical::DigestSuite::Sha256,
    )
    .map_err(|_| {
        rejected(
            ConflictCode::SignatureInvalid,
            "revoke producer proof does not match current device key",
        )
    })?;

    let mut initial = resource.clone();
    initial.revoke_proposal = None;
    if existing.resource != initial
        || existing.canonical_request != write.transaction.canonical_request
    {
        return Err(rejected(
            ConflictCode::DuplicateConflict,
            "rotation proposal changed the prepared transaction",
        ));
    }

    queue_event_in_connection(conn, event, write.queued_at).await?;
    match commit_verified_pcr_revoke_proposal_in_connection(conn, &write.commit).await? {
        AuthorityCommitWriteOutcome::Committed => {}
        AuthorityCommitWriteOutcome::Duplicate => {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "revoke Event was committed outside this proposal unit",
            ));
        }
        AuthorityCommitWriteOutcome::StaleAuthority(_) => {
            return Err(rejected(
                ConflictCode::CasConflict,
                "PCR authority changed before revoke proposal commit",
            ));
        }
    }
    crate::pcr_device_revocation_proposals::project_revoke_proposal_in_connection(
        conn, event, commit,
    )
    .await?;
    let proposal = serde_json::to_value(resource.revoke_proposal.as_ref().expect("validated"))
        .map_err(PersistenceError::database)?;
    let affected = sql_query(
        "UPDATE security_transactions SET revoke_proposal=$2 WHERE id=$1 \
         AND revoke_proposal IS NULL AND revoke_command_outcome IS NULL \
         AND accepted_steps='[]'::jsonb AND terminal_outcome IS NULL",
    )
    .bind::<diesel::sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(transaction_id))
    .bind::<Jsonb, _>(&proposal)
    .execute(&mut *conn)
    .await?;
    if affected != 1 {
        return Err(rejected(
            ConflictCode::CasConflict,
            "rotation proposal first write lost its transaction CAS",
        ));
    }
    Ok(commit.clone())
}
