//! The registered `accepted_device` authorization unit (device-lifecycle.md
//! §5.4, §5.5.1, §5.5.2).
//!
//! The Account Authority owns the pairing ledger and the §5.2.2 challenge
//! transcript; the owning Station only admits the frozen `ak.device.authorize`
//! it relays. Everything that depends on durable PCR state is decided here
//! under the PCR authority row lock: the approving device is `active` in the
//! current generation at the same status cut, the payload names exactly that
//! generation, the target device has no authorization yet, the target
//! possession signature binds the Event's complete account, and the Event
//! producer proof verifies against the approving device's accepted key. The
//! Event, its Commit, the typed device authorization and the local device
//! mirror become visible together or not at all.

use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
};
use arkret_wire::{CommitStreamRef, CommittedEventRef, ScopeRef};
use coland_storage::{
    AcceptedDeviceAuthorizationOutcome, AuthorityCommitTransaction, AuthorityCommitWriteOutcome,
    ConflictCode, PersistenceError,
};
use diesel::sql_types::{Binary, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use serde_json::Value;

use crate::pcr_device_status_fold::PcrDeviceLifecycle;
use crate::{AsyncPgConnection, PgTransactionError};

#[derive(QueryableByName)]
struct RealmLockRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

#[derive(QueryableByName)]
struct KnownEventRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    commit_json: Option<Value>,
}

/// Every refusal carries a registered [`ConflictCode`] prefix so the serving
/// layer can report it without reading diagnostics.
fn rejected(code: ConflictCode, reason: &str) -> PgTransactionError {
    PersistenceError::Conflict(format!("{code}: {reason}")).into()
}

fn approver_status_code(lifecycle: PcrDeviceLifecycle) -> ConflictCode {
    match lifecycle {
        PcrDeviceLifecycle::Revoked => ConflictCode::DeviceRevoked,
        PcrDeviceLifecycle::RevocationPending => ConflictCode::DeviceRevocationPending,
        PcrDeviceLifecycle::GenerationFenced => ConflictCode::DeviceGenerationFenced,
        PcrDeviceLifecycle::Active
        | PcrDeviceLifecycle::Expired
        | PcrDeviceLifecycle::NotYetEffective => ConflictCode::DeviceUnauthorized,
    }
}

pub(crate) async fn admit_accepted_device_unit_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    queued_at: chrono::DateTime<chrono::Utc>,
) -> Result<AcceptedDeviceAuthorizationOutcome, PgTransactionError> {
    let event = &transaction.event;
    let commit = &transaction.commit;
    if event.kind != arkret_wire::EventKind::DeviceAuthorize
        || event.executed_by.is_some()
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || event.scope_ref
            != (ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(rejected(
            ConflictCode::SchemaViolation,
            "accepted-device unit Event and Commit differ",
        ));
    }
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(|error| rejected(ConflictCode::SchemaViolation, &error.to_string()))?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(|_| {
            rejected(
                ConflictCode::EventIdDigestMismatch,
                "accepted-device Event id does not match its content",
            )
        })?;
    let payload: DeviceAuthorizePayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| {
        rejected(
            ConflictCode::SchemaViolation,
            &format!("device authorize payload is invalid: {error}"),
        )
    })?;
    if payload.authorization_binding_kind != DeviceAuthorizationBindingKind::AcceptedDevice {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "only an accepted_device authorization is admitted by this unit",
        ));
    }
    let DeviceOrPrincipalRef::DeviceId(approver) = &payload.authorized_by else {
        return Err(rejected(
            ConflictCode::SchemaViolation,
            "an accepted_device authorization is approved by a device",
        ));
    };
    if approver == &payload.device_id {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "a device cannot approve its own authorization",
        ));
    }
    let account = event.actor_id.as_account_id().ok_or_else(|| {
        rejected(
            ConflictCode::SchemaViolation,
            "accepted-device actor is not an account",
        )
    })?;
    let proof = event.producer_proof.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::SignatureInvalid,
            "accepted-device producer proof is absent",
        )
    })?;
    // §5.3: the signer is the approving device named by `authorized_by`,
    // under a DID URL of the actor principal's own verified DID.
    if crate::key_backup_current_results::verification_method_device(
        &proof.verification_method,
        account,
    )
    .as_ref()
        != Some(approver)
    {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "accepted-device proof method is not the approving device of this account",
        ));
    }
    // §5.2.2: the target possession signature commits to the complete account
    // the pairing was finalized for; this Station can check it against the
    // Event's actor without the Account Authority's pending record.
    arkret_signatures::verify_device_authorize_possession(&payload, account).map_err(|_| {
        rejected(
            ConflictCode::SignatureInvalid,
            "accepted-device target possession signature is invalid",
        )
    })?;

    // Every accepted PCR writer takes this row lock before changing its head,
    // so the status cut read below cannot move before this unit commits.
    let lock = sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
        .bind::<Text, _>(event.realm_id.as_str())
        .get_result::<RealmLockRow>(&mut *conn)
        .await
        .optional()?
        .ok_or_else(|| {
            rejected(
                ConflictCode::FailedPrecondition,
                "accepted-device PCR authority is absent",
            )
        })?;
    if lock.realm_id != event.realm_id.as_str() {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "accepted-device PCR lock differs from the Event Realm",
        ));
    }
    let token = crate::ids::parse_event_id(event.event_id.as_str()).ok_or_else(|| {
        rejected(
            ConflictCode::SchemaViolation,
            "accepted-device Event id is not canonical",
        )
    })?;
    let known = sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e \
         LEFT JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1",
    )
    .bind::<Binary, _>(token.to_vec())
    .get_result::<KnownEventRow>(&mut *conn)
    .await
    .optional()?;
    if let Some(known) = known {
        let envelope = serde_json::to_value(event).map_err(PersistenceError::database)?;
        return match known.commit_json {
            Some(stored) if known.envelope == envelope => {
                let stored: arkret_wire::RealmCommit = serde_json::from_value(stored)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
                Ok(AcceptedDeviceAuthorizationOutcome::Duplicate(stored))
            }
            _ => Err(rejected(
                ConflictCode::DuplicateConflict,
                "accepted-device Event is already known with different content",
            )),
        };
    }

    let status = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        account,
        approver,
        commit.committed_at,
    )
    .await?
    .ok_or_else(|| {
        rejected(
            ConflictCode::DeviceUnauthorized,
            "approving device has no confirmed PCR cut",
        )
    })?;
    if status.authority.realm_id != event.realm_id {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "accepted-device Event is outside the approver's PCR",
        ));
    }
    if status.lifecycle != PcrDeviceLifecycle::Active {
        return Err(rejected(
            approver_status_code(status.lifecycle),
            "approving device is not active in the current generation",
        ));
    }
    if commit.previous_commit_ref.as_ref() != Some(&status.authority.authority_commit_id) {
        return Err(rejected(
            ConflictCode::CasConflict,
            "accepted-device Commit does not extend the confirmed PCR head",
        ));
    }
    let approver_authorization = status.authority.authorization.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::DeviceUnauthorized,
            "approving device has no authorization",
        )
    })?;
    // §5.5.2: the accepted_device generation equals the PCR's current
    // generation at admission; never corrected to the current value.
    if status.authority.current_generation != Some(payload.authorized_generation_ref) {
        return Err(rejected(
            ConflictCode::DeviceGenerationFenced,
            "authorized_generation_ref is not the current device generation",
        ));
    }
    let target = crate::pcr_device_revocation_proposals::confirmed_pcr_device_cut_in_connection(
        conn,
        account,
        &payload.device_id,
    )
    .await?
    .ok_or_else(|| {
        rejected(
            ConflictCode::FailedPrecondition,
            "target device PCR cut is unavailable",
        )
    })?;
    if target.authority_commit_id != status.authority.authority_commit_id {
        return Err(rejected(
            ConflictCode::CasConflict,
            "target and approver were read at different PCR heads",
        ));
    }
    if target.authorization.is_some() || !target.proposals.is_empty() {
        return Err(rejected(
            ConflictCode::DuplicateConflict,
            "target device already has an accepted authorization history",
        ));
    }

    let did_key = approver_authorization
        .payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            rejected(
                ConflictCode::SignatureInvalid,
                "approving device authorization has no did:key key",
            )
        })?;
    let public_key =
        arkret_canonical::multibase::decode_ed25519_multibase(did_key).map_err(|_| {
            rejected(
                ConflictCode::SignatureInvalid,
                "approving device authorization key is invalid",
            )
        })?;
    let envelope_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| {
            rejected(
                ConflictCode::SignatureInvalid,
                &format!("accepted-device proof envelope is invalid: {error}"),
            )
        })?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &envelope_bytes,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: public_key.to_vec(),
        },
        suite,
    )
    .map_err(|_| {
        rejected(
            ConflictCode::SignatureInvalid,
            "accepted-device producer proof does not match the approving device key",
        )
    })?;

    crate::authority_commit::queue_event_in_connection(conn, event, queued_at).await?;
    match crate::authority_commit::commit_verified_pcr_device_transaction_in_connection(
        conn,
        transaction,
    )
    .await?
    {
        AuthorityCommitWriteOutcome::Committed => {}
        AuthorityCommitWriteOutcome::Duplicate => {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "accepted-device Event was committed outside this unit",
            ));
        }
        AuthorityCommitWriteOutcome::StaleAuthority(_) => {
            return Err(rejected(
                ConflictCode::CasConflict,
                "PCR authority changed before accepted-device commit",
            ));
        }
    }
    crate::pcr_device_current_results::project_pcr_device_current_in_connection(
        conn, event, commit, None,
    )
    .await?;
    mirror_accepted_device_in_connection(conn, account, &payload, event, commit).await?;
    Ok(AcceptedDeviceAuthorizationOutcome::Committed(
        commit.clone(),
    ))
}

/// The local device mirror the PCR genesis unit also writes for its founding
/// device. Only an unverified login placeholder of the same device may be
/// promoted; a verified or revoked row means the mirror disagrees with the
/// PCR authorization history read above.
async fn mirror_accepted_device_in_connection(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    payload: &DeviceAuthorizePayload,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> Result<(), PgTransactionError> {
    let authorization_ref = CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };
    let mut device_json = serde_json::to_value(payload).map_err(PersistenceError::database)?;
    let fields = device_json.as_object_mut().ok_or_else(|| {
        rejected(
            ConflictCode::SchemaViolation,
            "device authorize payload is not an object",
        )
    })?;
    fields.insert(
        "device_authorization_ref".to_owned(),
        serde_json::to_value(&authorization_ref).map_err(PersistenceError::database)?,
    );
    fields.insert(
        "device_authorize_event_id".to_owned(),
        serde_json::to_value(&event.event_id).map_err(PersistenceError::database)?,
    );
    let affected = sql_query(
        "INSERT INTO devices \
         (id,station_id,actor_id,device_id,device_key,verification_state,payload,created_at,updated_at) \
         VALUES ($1,$2,$3,$4,$5,'verified',$6,$7,$7) \
         ON CONFLICT(actor_id,device_id) DO UPDATE SET \
           device_key=EXCLUDED.device_key,verification_state='verified', \
           payload=EXCLUDED.payload,updated_at=EXCLUDED.updated_at \
         WHERE devices.verification_state='unverified' AND devices.revoked_at IS NULL \
           AND devices.station_id=EXCLUDED.station_id",
    )
    .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
    .bind::<Text, _>(account.station_id.as_str())
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(payload.device_id.as_str())
    .bind::<Text, _>(payload.device_public_key_did.as_str())
    .bind::<Jsonb, _>(&device_json)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await?;
    if affected != 1 {
        return Err(rejected(
            ConflictCode::DuplicateConflict,
            "target device mirror is already verified or revoked",
        ));
    }
    Ok(())
}
