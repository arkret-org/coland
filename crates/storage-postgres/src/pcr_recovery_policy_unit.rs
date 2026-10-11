//! The device-signed recovery policy publication unit (key-management.md §8,
//! §8.1; governance-objects.md §3.2).
//!
//! A recovery policy is PCR control state carried by `ak.policy.set`. Every
//! decision that depends on durable PCR state is taken here under the PCR
//! authority row lock: the signing device is `active` in the current
//! generation at the same status cut, a genesis policy is signed by the
//! founding device, a successor names the current policy and advances its
//! version, every `device_quorum` member is an active device of the same cut,
//! and both the policy signature and the Event producer proof verify against
//! the signer's accepted device key. The Event, its Commit and the accepted
//! policy row become visible together or not at all. There is no
//! quorum-signed update: every publication, rotation and revocation is
//! signed by one current-generation device.

use arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind;
use arkret_models_crypto::{
    RecoveryMethod, RecoveryPolicy, RecoveryPolicySetPayload, RecoverySignatureAlgorithm,
    recovery_policy_signature_transcript_bytes,
};
use arkret_wire::{CommitStreamRef, ScopeRef};
use coland_storage::{
    AuthorityCommitWriteOutcome, ConflictCode, PersistenceError, RecoveryPolicyPublicationOutcome,
    RecoveryPolicyPublicationWrite, RecoveryPolicyRecord,
};
use diesel::sql_types::{Binary, Integer, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use serde_json::Value;

use crate::pcr_device_status_fold::PcrDeviceLifecycle;
use crate::recovery::RecoveryPolicyRow;
use crate::{AsyncPgConnection, PgTransactionError, ids};

#[derive(QueryableByName)]
struct RealmLockRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

#[derive(QueryableByName)]
struct KnownEventRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    commit_json: Option<Value>,
}

fn rejected(code: ConflictCode, reason: &str) -> PgTransactionError {
    PersistenceError::Conflict(format!("{code}: {reason}")).into()
}

fn signer_status_code(lifecycle: PcrDeviceLifecycle) -> ConflictCode {
    match lifecycle {
        PcrDeviceLifecycle::Revoked => ConflictCode::DeviceRevoked,
        PcrDeviceLifecycle::RevocationPending => ConflictCode::DeviceRevocationPending,
        PcrDeviceLifecycle::GenerationFenced => ConflictCode::DeviceGenerationFenced,
        PcrDeviceLifecycle::Active
        | PcrDeviceLifecycle::Expired
        | PcrDeviceLifecycle::NotYetEffective => ConflictCode::DeviceUnauthorized,
    }
}

const POLICY_COLUMNS: &str = "id AS policy_id, principal_id, station_id, version, \
     acceptance_basis, trust_domain, supersedes, expires_at, issued_at, verification_method, \
     raw_payload, accepted_at";

async fn policy_accepted_by(
    conn: &mut AsyncPgConnection,
    commit_id: &arkret_wire::RealmCommitId,
) -> Result<Option<RecoveryPolicyRecord>, PgTransactionError> {
    let basis = serde_json::to_value(commit_id).map_err(PersistenceError::database)?;
    sql_query(format!(
        "SELECT {POLICY_COLUMNS} FROM recovery_policies p \
         JOIN policy_current_results c \
           ON c.policy_id=('ak:policy:' || p.id::text) \
          AND c.current_commit_id=(p.acceptance_basis #>> '{{}}') \
          AND c.value=p.raw_payload \
         WHERE p.acceptance_basis=$1"
    ))
    .bind::<Jsonb, _>(basis)
    .get_result::<RecoveryPolicyRow>(&mut *conn)
    .await
    .optional()?
    .map(RecoveryPolicyRecord::try_from)
    .transpose()
    .map_err(Into::into)
}

/// Take the account's recovery-policy lock, the same one session
/// verification, backup unlock/delete and recovery completion take before
/// reading the accepted policy (§8.1 shared lock order), then read the policy
/// every successor must supersede.
async fn current_policy(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
) -> Result<Option<RecoveryPolicyRecord>, PgTransactionError> {
    let canonical =
        arkret_canonical::canonical_json_string(account).map_err(PersistenceError::database)?;
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!("recovery-policy:{canonical}"))
        .execute(&mut *conn)
        .await?;
    sql_query(format!(
        "SELECT {POLICY_COLUMNS} FROM recovery_policies p \
         JOIN policy_current_results c \
           ON c.policy_id=('ak:policy:' || p.id::text) \
          AND c.current_commit_id=(p.acceptance_basis #>> '{{}}') \
          AND c.value=p.raw_payload \
         WHERE p.principal_id=$1 AND p.station_id=$2 \
         ORDER BY p.version DESC LIMIT 1 FOR UPDATE OF p"
    ))
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<RecoveryPolicyRow>(&mut *conn)
    .await
    .optional()?
    .map(RecoveryPolicyRecord::try_from)
    .transpose()
    .map_err(Into::into)
}

pub(crate) async fn commit_recovery_policy_unit_in_connection(
    conn: &mut AsyncPgConnection,
    write: &RecoveryPolicyPublicationWrite,
) -> Result<RecoveryPolicyPublicationOutcome, PgTransactionError> {
    let event = &write.commit.event;
    let commit = &write.commit.commit;
    if event.kind != arkret_wire::EventKind::PolicySet
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
            "recovery policy unit Event and Commit differ",
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
                "recovery policy Event id does not match its content",
            )
        })?;
    let payload: RecoveryPolicySetPayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| {
        rejected(
            ConflictCode::SchemaViolation,
            &format!("recovery policy payload is invalid: {error}"),
        )
    })?;
    payload
        .validate_shape()
        .map_err(|error| rejected(ConflictCode::SchemaViolation, &error.to_string()))?;
    let policy = &payload.value;
    let account = event.actor_id.as_account_id().ok_or_else(|| {
        rejected(
            ConflictCode::SchemaViolation,
            "recovery policy actor is not an account",
        )
    })?;
    if &policy.account_id != account {
        return Err(rejected(
            ConflictCode::DeviceUnauthorized,
            "recovery policy account differs from the Event actor",
        ));
    }
    if policy.auth_data.signature_algorithm != RecoverySignatureAlgorithm::Ed25519 {
        return Err(rejected(
            ConflictCode::UnsupportedFeature,
            "recovery policy device signature algorithm is not Ed25519",
        ));
    }
    let proof = event.producer_proof.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::SignatureInvalid,
            "recovery policy producer proof is absent",
        )
    })?;
    if proof.verification_method != policy.auth_data.verification_method {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "recovery policy and its Event are signed by different methods",
        ));
    }
    let signer = crate::key_backup_current_results::verification_method_device(
        &policy.auth_data.verification_method,
        account,
    )
    .ok_or_else(|| {
        rejected(
            ConflictCode::SignatureInvalid,
            "recovery policy method is not a device of this account",
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
                "recovery policy PCR authority is absent",
            )
        })?;
    if lock.realm_id != event.realm_id.as_str() {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "recovery policy PCR lock differs from the Event Realm",
        ));
    }
    let token = ids::parse_event_id(event.event_id.as_str()).ok_or_else(|| {
        rejected(
            ConflictCode::SchemaViolation,
            "recovery policy Event id is not canonical",
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
        let Some(stored) = known.commit_json.filter(|_| known.envelope == envelope) else {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "recovery policy Event is already known with different content",
            ));
        };
        let stored: arkret_wire::RealmCommit = serde_json::from_value(stored)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let record = policy_accepted_by(conn, &stored.commit_id)
            .await?
            .ok_or_else(|| {
                rejected(
                    ConflictCode::DuplicateConflict,
                    "recovery policy Event was committed without its policy",
                )
            })?;
        return Ok(RecoveryPolicyPublicationOutcome::Duplicate(record));
    }

    let status = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        account,
        &signer,
        commit.committed_at,
    )
    .await?
    .ok_or_else(|| {
        rejected(
            ConflictCode::DeviceUnauthorized,
            "recovery policy signer has no confirmed PCR cut",
        )
    })?;
    if status.authority.realm_id != event.realm_id {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "recovery policy Event is outside the account's PCR",
        ));
    }
    if status.lifecycle != PcrDeviceLifecycle::Active {
        return Err(rejected(
            signer_status_code(status.lifecycle),
            "recovery policy signer is not active in the current generation",
        ));
    }
    if commit.previous_commit_ref.as_ref() != Some(&status.authority.authority_commit_id) {
        return Err(rejected(
            ConflictCode::CasConflict,
            "recovery policy Commit does not extend the confirmed PCR head",
        ));
    }
    let authorization = status.authority.authorization.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::DeviceUnauthorized,
            "recovery policy signer has no authorization",
        )
    })?;

    let current = current_policy(conn, account).await?;
    check_version_ratchet(
        policy,
        current.as_ref(),
        authorization.payload.authorization_binding_kind,
    )?;
    check_quorum_members_active(
        conn,
        account,
        policy,
        &status.authority.authority_commit_id,
        commit.committed_at,
    )
    .await?;

    let did_key = authorization
        .payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            rejected(
                ConflictCode::SignatureInvalid,
                "recovery policy signer authorization has no did:key key",
            )
        })?;
    let public_key =
        arkret_canonical::multibase::decode_ed25519_multibase(did_key).map_err(|_| {
            rejected(
                ConflictCode::SignatureInvalid,
                "recovery policy signer authorization key is invalid",
            )
        })?;
    let device_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: public_key.to_vec(),
    };
    let transcript = recovery_policy_signature_transcript_bytes(policy)
        .map_err(|error| rejected(ConflictCode::SchemaViolation, &error.to_string()))?;
    if !arkret_signatures::verify_detached_ed25519_signature(
        &device_key,
        &transcript,
        policy.auth_data.signature.as_str(),
    ) {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "recovery policy signature does not match the signer device key",
        ));
    }
    let envelope_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| {
            rejected(
                ConflictCode::SignatureInvalid,
                &format!("recovery policy proof envelope is invalid: {error}"),
            )
        })?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &envelope_bytes,
        &event.actor_id,
        &device_key,
        suite,
    )
    .map_err(|_| {
        rejected(
            ConflictCode::SignatureInvalid,
            "recovery policy producer proof does not match the signer device key",
        )
    })?;

    crate::authority_commit::queue_event_in_connection(conn, event, write.queued_at).await?;
    match crate::authority_commit::commit_verified_recovery_policy_in_connection(
        conn,
        &write.commit,
    )
    .await?
    {
        AuthorityCommitWriteOutcome::Committed => {}
        AuthorityCommitWriteOutcome::Duplicate => {
            return Err(rejected(
                ConflictCode::DuplicateConflict,
                "recovery policy Event was committed outside this unit",
            ));
        }
        AuthorityCommitWriteOutcome::StaleAuthority(_) => {
            return Err(rejected(
                ConflictCode::CasConflict,
                "PCR authority changed before recovery policy commit",
            ));
        }
    }
    let record = RecoveryPolicyRecord {
        policy_id: policy.policy_id.as_str().to_owned(),
        account_id: account.clone(),
        version: u32::try_from(policy.version).map_err(|_| {
            rejected(
                ConflictCode::SchemaViolation,
                "recovery policy version is out of range",
            )
        })?,
        acceptance_basis: commit.commit_id.clone(),
        trust_domain: policy.trust_domain.as_str().to_owned(),
        supersedes: policy
            .supersedes_id
            .as_ref()
            .map(|id| id.as_str().to_owned()),
        expires_at: policy.expires_at,
        issued_at: policy.issued_at,
        raw_payload: serde_json::to_value(policy).map_err(PersistenceError::database)?,
        accepted_at: commit.committed_at,
        verification_method: policy.auth_data.verification_method.as_str().to_owned(),
    };
    upsert_policy_current_in_connection(conn, &record, event, commit).await?;
    insert_accepted_policy_in_connection(conn, &record, policy.revokes_recovery()).await?;
    Ok(RecoveryPolicyPublicationOutcome::Committed(record))
}

/// Materialize the registered `policy` family at the exact PCR Commit cut.
/// The recovery-specific table remains the immutable history/audit source;
/// callers asking for current state use this row and its typed revision.
async fn upsert_policy_current_in_connection(
    conn: &mut AsyncPgConnection,
    record: &RecoveryPolicyRecord,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> Result<(), PgTransactionError> {
    let position = i64::try_from(commit.stream_position).map_err(|_| {
        rejected(
            ConflictCode::SchemaViolation,
            "recovery policy stream position exceeds PostgreSQL BIGINT",
        )
    })?;
    let written = sql_query(
        "INSERT INTO policy_current_results \
         (realm_id,policy_id,current_commit_id,current_stream_position,current_event_id,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT(policy_id) DO UPDATE SET \
           realm_id=EXCLUDED.realm_id,current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           current_event_id=EXCLUDED.current_event_id,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE policy_current_results.realm_id=EXCLUDED.realm_id \
           AND policy_current_results.current_stream_position<EXCLUDED.current_stream_position \
           AND (policy_current_results.value->>'schema' IS DISTINCT FROM 'ak.schema.policy.v1' \
                OR policy_current_results.value->>'policy_kind' IS DISTINCT FROM 'agent')",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&record.policy_id)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<diesel::sql_types::BigInt, _>(position)
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Jsonb, _>(&record.raw_payload)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await?;
    if written != 1 {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            "Recovery Policy current cannot rebind an Agent Policy, cross Realm or move backwards",
        ));
    }
    Ok(())
}

/// §8: a genesis policy is signed by the founding device; a successor names
/// the current policy as its predecessor and strictly advances its version.
fn check_version_ratchet(
    policy: &RecoveryPolicy,
    current: Option<&RecoveryPolicyRecord>,
    signer_binding: DeviceAuthorizationBindingKind,
) -> Result<(), PgTransactionError> {
    match current {
        None => {
            if policy.version != 1 || policy.supersedes_id.is_some() {
                return Err(rejected(
                    ConflictCode::RecoveryPolicyGenesisNotV1,
                    "the first recovery policy of an account is version 1 without a predecessor",
                ));
            }
            if signer_binding != DeviceAuthorizationBindingKind::RegistrationAnchor {
                return Err(rejected(
                    ConflictCode::DeviceUnauthorized,
                    "a genesis recovery policy is signed by the founding device",
                ));
            }
        }
        Some(current) => {
            if policy.version <= u64::from(current.version) {
                return Err(rejected(
                    ConflictCode::RecoveryPolicyVersionNotMonotonic,
                    "recovery policy version does not advance the accepted policy",
                ));
            }
            if policy.supersedes_id.as_ref().map(|id| id.as_str())
                != Some(current.policy_id.as_str())
            {
                return Err(rejected(
                    ConflictCode::RecoveryPolicySupersedesInvalid,
                    "recovery policy does not supersede the accepted policy",
                ));
            }
        }
    }
    Ok(())
}

/// §8.1 publication-time executability: `device_quorum.k` may not exceed the
/// distinct members that are active devices at the same PCR cut.
async fn check_quorum_members_active(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    policy: &RecoveryPolicy,
    head: &arkret_wire::RealmCommitId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), PgTransactionError> {
    for method in &policy.methods {
        let RecoveryMethod::DeviceQuorum { k, member_ids } = method else {
            continue;
        };
        let mut distinct = member_ids.iter().collect::<Vec<_>>();
        distinct.sort_unstable();
        distinct.dedup();
        let mut active = 0u64;
        for member in distinct {
            // A member with no accepted authorization is simply not active;
            // the status fold is defined only for authorized devices.
            let authorized =
                crate::pcr_device_revocation_proposals::confirmed_pcr_device_cut_in_connection(
                    conn, account, member,
                )
                .await?
                .is_some_and(|cut| cut.authorization.is_some());
            if !authorized {
                continue;
            }
            let status =
                crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
                    conn, account, member, now,
                )
                .await?;
            if let Some(status) = status {
                if &status.authority.authority_commit_id != head {
                    return Err(rejected(
                        ConflictCode::CasConflict,
                        "quorum members and signer were read at different PCR heads",
                    ));
                }
                if status.lifecycle == PcrDeviceLifecycle::Active {
                    active += 1;
                }
            }
        }
        if u64::from(*k) > active {
            return Err(rejected(
                ConflictCode::FailedPrecondition,
                "device_quorum k exceeds the active member devices",
            ));
        }
    }
    Ok(())
}

async fn insert_accepted_policy_in_connection(
    conn: &mut AsyncPgConnection,
    record: &RecoveryPolicyRecord,
    revokes_recovery: bool,
) -> Result<(), PgTransactionError> {
    sql_query(
        "INSERT INTO recovery_policies \
         (id, principal_id, station_id, version, acceptance_basis, trust_domain, supersedes, \
          expires_at, issued_at, verification_method, raw_payload, accepted_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind::<diesel::sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(&record.policy_id))
    .bind::<Text, _>(record.account_id.principal_id.as_str())
    .bind::<Text, _>(record.account_id.station_id.as_str())
    .bind::<Integer, _>(i32::try_from(record.version).map_err(|_| {
        rejected(
            ConflictCode::SchemaViolation,
            "recovery policy version is out of range",
        )
    })?)
    .bind::<Jsonb, _>(
        serde_json::to_value(&record.acceptance_basis).map_err(PersistenceError::database)?,
    )
    .bind::<Text, _>(&record.trust_domain)
    .bind::<Nullable<diesel::sql_types::Uuid>, _>(
        record
            .supersedes
            .as_deref()
            .map(ids::typed_uuid_part_expect_internal),
    )
    .bind::<Nullable<Timestamptz>, _>(record.expires_at)
    .bind::<Timestamptz, _>(record.issued_at)
    .bind::<Text, _>(&record.verification_method)
    .bind::<Jsonb, _>(&record.raw_payload)
    .bind::<Timestamptz, _>(record.accepted_at)
    .execute(&mut *conn)
    .await?;
    // §8.1: publishing `methods=[]` invalidates every unfinished session.
    if revokes_recovery {
        sql_query(
            "UPDATE recovery_sessions SET state='rejected',updated_at=$3 \
             WHERE principal_id=$1 AND station_id=$2 AND policy_version<$4 \
               AND state IN ('pending','verified')",
        )
        .bind::<Text, _>(record.account_id.principal_id.as_str())
        .bind::<Text, _>(record.account_id.station_id.as_str())
        .bind::<Timestamptz, _>(record.accepted_at)
        .bind::<Integer, _>(i32::try_from(record.version).unwrap_or(i32::MAX))
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}
