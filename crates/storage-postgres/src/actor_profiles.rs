//! The device-signed PCR units that write the `actor_profile` and
//! `identity_accountability` typed current results.
//!
//! Both are PCR control state. Each unit takes the PCR authority row lock that
//! every PCR head writer takes, confirms the signing device is `active` in the
//! current generation at that same cut, verifies the Event producer proof
//! against the accepted device key, and writes the Event, its Commit and the
//! typed result together or not at all.
//!
//! Profile admission decides `accountable_principal_ids` against committed
//! `identity_accountability` rows in the same transaction. The rows it relies
//! on are share-locked, so a concurrent revoke is ordered before or after this
//! Commit rather than racing it, and the admission instant is the accepting
//! Commit's `committed_at` (`zh/models/actor.md` section 3.3.1).

use arkret_models_collaboration::events_payloads::{
    ActorProfileCreatePayload, ActorProfileUpdatePayload,
};
use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityProjection,
};
use arkret_models_identity::ActorProfile;
use arkret_wire::{AccountId, CommitStreamRef, DidCoreId, Event, EventKind, RealmCommit, ScopeRef};
use coland_storage::{
    AccountabilityGrantAdmissionOutcome, AccountabilityGrantAdmissionWrite,
    ActorProfileAdmissionOutcome, ActorProfileAdmissionWrite, ActorProfileResultRecord,
    AuthorityCommitTransaction, AuthorityCommitWriteOutcome, ConflictCode,
    IdentityAccountabilityRecord, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{BigInt, Binary, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value;

use crate::pcr_device_status_fold::PcrDeviceLifecycle;
use crate::{AsyncPgConnection, PgPool, PgTransactionError, ids, pg_conn};

pub struct PgActorProfileStore {
    pub pool: PgPool,
}

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

#[derive(QueryableByName)]
struct ProfileRow {
    #[diesel(sql_type = Text)]
    actor_profile_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    envelope: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    commit_json: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    accepted_value: Option<Value>,
}

#[derive(QueryableByName)]
struct ProfileResultRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

#[derive(QueryableByName)]
struct AccountabilityRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct AccountabilityResultRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

pub(crate) fn rejected(code: ConflictCode, reason: &str) -> PgTransactionError {
    PersistenceError::Conflict(format!("{code}: {reason}")).into()
}

pub(crate) fn corrupt(detail: impl std::fmt::Display) -> PgTransactionError {
    PersistenceError::SchemaViolation(detail.to_string()).into()
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

fn payload<T: serde::de::DeserializeOwned>(
    event: &Event,
    what: &str,
) -> Result<T, PgTransactionError> {
    serde_json::from_value(Value::Object(event.payload.clone().into_iter().collect())).map_err(
        |error| {
            rejected(
                ConflictCode::SchemaViolation,
                &format!("{what} payload is invalid: {error}"),
            )
        },
    )
}

/// The verified signer of a device-signed PCR self Event.
pub(crate) struct PcrSigner {
    pub(crate) account: AccountId,
    pub(crate) device_key: arkret_signatures::PublicKeyMaterial,
}

/// Either the exact Event is already committed (its Commit) or it is a new
/// Event whose signer is active at the locked PCR cut.
pub(crate) enum PcrSelfEventCut {
    Known(Box<RealmCommit>),
    Fresh(PcrSigner),
}

/// The device `signer` of `account` is active in `account`'s PCR at `at`,
/// read on this connection, and the Event producer proof verifies against
/// its accepted key. The caller holds the lock that orders that PCR's
/// writers before using the cut.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify_device_signer_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    account: &AccountId,
    signer: &arkret_wire::DeviceId,
    pcr_realm_id: &arkret_wire::RealmId,
    at: chrono::DateTime<chrono::Utc>,
    suite: arkret_canonical::DigestSuite,
    what: &str,
) -> Result<
    (
        crate::pcr_device_status_reader::ConfirmedPcrDeviceStatusCut,
        arkret_signatures::PublicKeyMaterial,
    ),
    PgTransactionError,
> {
    let proof = event.producer_proof.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::SignatureInvalid,
            &format!("{what} producer proof is absent"),
        )
    })?;
    let status = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn, account, signer, at,
    )
    .await?
    .ok_or_else(|| {
        rejected(
            ConflictCode::DeviceUnauthorized,
            &format!("{what} signer has no confirmed PCR cut"),
        )
    })?;
    if status.authority.realm_id != *pcr_realm_id {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            &format!("{what} signer is outside the account's PCR"),
        ));
    }
    if status.lifecycle != PcrDeviceLifecycle::Active {
        return Err(rejected(
            signer_status_code(status.lifecycle),
            &format!("{what} signer is not active in the current generation"),
        ));
    }
    let authorization = status.authority.authorization.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::DeviceUnauthorized,
            &format!("{what} signer has no authorization"),
        )
    })?;
    let did_key = authorization
        .payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            rejected(
                ConflictCode::SignatureInvalid,
                &format!("{what} signer authorization has no did:key key"),
            )
        })?;
    let public_key =
        arkret_canonical::multibase::decode_ed25519_multibase(did_key).map_err(|_| {
            rejected(
                ConflictCode::SignatureInvalid,
                &format!("{what} signer authorization key is invalid"),
            )
        })?;
    let device_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: public_key.to_vec(),
    };
    let envelope_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| {
            rejected(
                ConflictCode::SignatureInvalid,
                &format!("{what} proof envelope is invalid: {error}"),
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
            &format!("{what} producer proof does not match the signer device key"),
        )
    })?;
    Ok((status, device_key))
}

/// Shared PCR self-Event admission: Event/Commit agreement, the PCR lock,
/// exact replay, the signer's active status at the same cut, the Commit
/// extending the confirmed head and the producer proof against the accepted
/// device key.
pub(crate) async fn verify_pcr_self_event(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    authorization_ref: Option<&str>,
    what: &str,
) -> Result<PcrSelfEventCut, PgTransactionError> {
    let event = &transaction.event;
    let commit = &transaction.commit;
    if event.executed_by.is_some()
        || event
            .authorization_ref
            .as_deref()
            .is_some_and(|reference| Some(reference) != authorization_ref)
        || event.applet_id.is_some()
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
            &format!("{what} Event and Commit are not one direct PCR Realm-stream write"),
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
                &format!("{what} Event id does not match its content"),
            )
        })?;
    let account = event.actor_id.as_account_id().cloned().ok_or_else(|| {
        rejected(
            ConflictCode::SchemaViolation,
            &format!("{what} actor is not an account"),
        )
    })?;
    let proof = event.producer_proof.as_ref().ok_or_else(|| {
        rejected(
            ConflictCode::SignatureInvalid,
            &format!("{what} producer proof is absent"),
        )
    })?;
    let signer = crate::key_backup_current_results::verification_method_device(
        &proof.verification_method,
        &account,
    )
    .ok_or_else(|| {
        rejected(
            ConflictCode::SignatureInvalid,
            &format!("{what} is not signed by a device of its actor"),
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
                &format!("{what} PCR authority is absent"),
            )
        })?;
    if lock.realm_id != event.realm_id.as_str() {
        return Err(rejected(
            ConflictCode::FailedPrecondition,
            &format!("{what} PCR lock differs from the Event Realm"),
        ));
    }
    let token = ids::parse_event_id(event.event_id.as_str()).ok_or_else(|| {
        rejected(
            ConflictCode::SchemaViolation,
            &format!("{what} Event id is not canonical"),
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
                &format!("{what} Event is already known with different content"),
            ));
        };
        let stored: RealmCommit = serde_json::from_value(stored).map_err(corrupt)?;
        return Ok(PcrSelfEventCut::Known(Box::new(stored)));
    }

    let (status, device_key) = verify_device_signer_in_connection(
        conn,
        event,
        &account,
        &signer,
        &event.realm_id,
        commit.committed_at,
        suite,
        what,
    )
    .await?;
    if commit.previous_commit_ref.as_ref() != Some(&status.authority.authority_commit_id) {
        return Err(rejected(
            ConflictCode::TemporarilyUnavailable,
            &format!("{what} Commit does not extend the confirmed PCR head"),
        ));
    }
    Ok(PcrSelfEventCut::Fresh(PcrSigner {
        account,
        device_key,
    }))
}

async fn commit_verified(
    conn: &mut AsyncPgConnection,
    write: &AuthorityCommitTransaction,
    queued_at: chrono::DateTime<chrono::Utc>,
    what: &str,
) -> Result<(), PgTransactionError> {
    let historical = crate::agent_producer_signer_keys::prepare_admitted_own_pcr_in_connection(
        conn,
        &write.event,
        &write.commit,
    )
    .await?;
    crate::authority_commit::queue_event_in_connection(conn, &write.event, queued_at).await?;
    match crate::authority_commit::commit_verified_pcr_typed_current_in_connection(conn, write)
        .await?
    {
        AuthorityCommitWriteOutcome::Committed => {
            crate::agent_producer_signer_keys::retain_self_outcome_in_connection(
                conn,
                &write.event,
                &write.commit,
                historical,
            )
            .await?;
            Ok(())
        }
        AuthorityCommitWriteOutcome::Duplicate => Err(rejected(
            ConflictCode::DuplicateConflict,
            &format!("{what} Event was committed outside this unit"),
        )),
        AuthorityCommitWriteOutcome::StaleAuthority(_) => Err(rejected(
            ConflictCode::TemporarilyUnavailable,
            &format!("PCR authority changed before the {what} commit"),
        )),
    }
}

async fn locked_profile(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> Result<Option<ActorProfile>, PgTransactionError> {
    let row=sql_query(
        "SELECT p.actor_profile_id,p.value,e.envelope,c.commit_json,v.value AS accepted_value FROM actor_profile_current_results p \
         LEFT JOIN realm_commits c ON c.commit_id=p.current_commit_id AND c.realm_id=p.realm_id AND c.stream_position=p.current_stream_position \
         LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' AND e.envelope->'actor_id'=p.actor_id AND e.envelope->'scope_ref'=p.scope_ref \
         LEFT JOIN actor_profile_result_versions v ON v.commit_id=p.current_commit_id AND v.actor_profile_id=p.actor_profile_id \
         WHERE p.realm_id=$1 AND p.actor_id=$2 AND p.scope_ref=$3 FOR UPDATE OF p",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::json!(event.actor_id))
    .bind::<Jsonb, _>(serde_json::json!(event.scope_ref))
    .get_result::<ProfileRow>(&mut *conn)
    .await
    .optional()?;
    let Some(row) = row else {
        #[derive(QueryableByName)]
        struct Known {
            #[diesel(sql_type=diesel::sql_types::Bool)]
            present: bool,
        }
        let known=sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.realm_id=$1 AND e.state='committed' AND e.kind='ak.profile.create' AND e.envelope->'actor_id'=$2 AND e.envelope->'scope_ref'=$3) AS present")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(serde_json::json!(event.actor_id)).bind::<Jsonb,_>(serde_json::json!(event.scope_ref)).get_result::<Known>(&mut *conn).await?;
        if known.present {
            return Err(PersistenceError::Conflict(
                "revision_unavailable: accepted Profile current is absent".into(),
            )
            .into());
        }
        return Ok(None);
    };
    let source: Event = serde_json::from_value(
        row.envelope
            .ok_or_else(|| corrupt("Profile has no exact accepted Event"))?,
    )
    .map_err(corrupt)?;
    let commit: RealmCommit = serde_json::from_value(
        row.commit_json
            .ok_or_else(|| corrupt("Profile has no exact covering Commit"))?,
    )
    .map_err(corrupt)?;
    if source.scope_ref != event.scope_ref
        || source.actor_id != event.actor_id
        || commit.event_ref != source.event_id
        || commit.stream_ref
            != CommitStreamRef::from_scope(&event.scope_ref, None).map_err(corrupt)?
        || row.accepted_value.as_ref() != Some(&row.value)
    {
        return Err(PersistenceError::Conflict(
            "revision_unavailable: Profile current differs from its accepted result".into(),
        )
        .into());
    }
    {
        let profile: ActorProfile = serde_json::from_value(row.value).map_err(corrupt)?;
        if profile.id.as_ref().map(|id| id.as_str()) != Some(row.actor_profile_id.as_str()) {
            return Err(corrupt("actor profile row id differs from its value"));
        }
        Ok(Some(profile))
    }
}

async fn profile_result_at(
    conn: &mut AsyncPgConnection,
    commit_id: &arkret_wire::RealmCommitId,
) -> Result<Option<ActorProfileResultRecord>, PgTransactionError> {
    sql_query(
        "SELECT v.value,e.envelope,c.commit_json FROM actor_profile_result_versions v \
         JOIN realm_commits c ON c.commit_id=v.commit_id \
         JOIN canonical_events e ON e.pk=c.event_pk WHERE v.commit_id=$1",
    )
    .bind::<Text, _>(commit_id.as_str())
    .get_result::<ProfileResultRow>(&mut *conn)
    .await
    .optional()?
    .map(profile_record)
    .transpose()
}

fn profile_record(row: ProfileResultRow) -> Result<ActorProfileResultRecord, PgTransactionError> {
    Ok(ActorProfileResultRecord {
        profile: serde_json::from_value(row.value).map_err(corrupt)?,
        event: serde_json::from_value(row.envelope).map_err(corrupt)?,
        commit: serde_json::from_value(row.commit_json).map_err(corrupt)?,
    })
}

/// Whether every accountable principal has a committed active record for
/// `subject` at `at`, share-locking the rows relied on.
pub(crate) async fn accountability_holds_in_connection(
    conn: &mut AsyncPgConnection,
    issuers: &[DidCoreId],
    subject: &DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, PgTransactionError> {
    for issuer in issuers {
        let rows = sql_query(
            "SELECT value FROM identity_accountability_current_results \
             WHERE subject_id=$1 AND issuer_id=$2 \
             ORDER BY realm_id,scope_set_digest FOR SHARE",
        )
        .bind::<Text, _>(subject.as_str())
        .bind::<Text, _>(issuer.as_str())
        .get_results::<AccountabilityRow>(&mut *conn)
        .await?;
        let mut verified = false;
        for row in rows {
            let value: AccountabilityProjection =
                serde_json::from_value(row.value).map_err(corrupt)?;
            verified |= value.verifies_at(at);
        }
        if !verified {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) async fn admit_profile_in_connection(
    conn: &mut AsyncPgConnection,
    write: &ActorProfileAdmissionWrite,
) -> Result<ActorProfileAdmissionOutcome, PgTransactionError> {
    const WHAT: &str = "Actor Profile";
    let event = &write.commit.event;
    let commit = &write.commit.commit;
    if !matches!(
        event.kind,
        EventKind::ProfileCreate | EventKind::ProfileUpdate
    ) {
        return Err(rejected(
            ConflictCode::SchemaViolation,
            "the Actor Profile unit admits only ak.profile.create or ak.profile.update",
        ));
    }
    let signer = match verify_pcr_self_event(conn, &write.commit, None, WHAT).await? {
        PcrSelfEventCut::Known(stored) => {
            let record = profile_result_at(conn, &stored.commit_id)
                .await?
                .ok_or_else(|| {
                    rejected(
                        ConflictCode::DuplicateConflict,
                        "Actor Profile Event was committed without its profile result",
                    )
                })?;
            return Ok(ActorProfileAdmissionOutcome::Duplicate(record));
        }
        PcrSelfEventCut::Fresh(signer) => signer,
    };

    let next = materialize_profile_in_connection(conn, event, commit, &signer.account).await?;

    commit_verified(conn, &write.commit, write.queued_at, WHAT).await?;
    write_profile_current_in_connection(conn, event, commit, &next).await?;
    Ok(ActorProfileAdmissionOutcome::Committed(
        ActorProfileResultRecord {
            profile: next,
            event: event.clone(),
            commit: commit.clone(),
        },
    ))
}

/// Validate and materialize a profile after its owning unit freezes the signer cut.
pub(crate) async fn materialize_profile_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &RealmCommit,
    subject: &arkret_wire::AccountId,
) -> Result<ActorProfile, PgTransactionError> {
    materialize_profile_at(conn, event, commit.committed_at, subject).await
}

pub(crate) async fn materialize_profile_at(
    conn: &mut AsyncPgConnection,
    event: &Event,
    at: chrono::DateTime<chrono::Utc>,
    subject: &AccountId,
) -> Result<ActorProfile, PgTransactionError> {
    const WHAT: &str = "Actor Profile";
    let current = locked_profile(conn, event).await?;
    let next = match event.kind {
        EventKind::ProfileCreate => {
            if current.is_some() {
                return Err(rejected(
                    ConflictCode::FailedPrecondition,
                    "the Account and scope already have an accepted Actor Profile; submit ak.profile.update",
                ));
            }
            let create: ActorProfileCreatePayload = payload(event, WHAT)?;
            if create.object.principal_id != subject.principal_id {
                return Err(rejected(
                    ConflictCode::FailedPrecondition,
                    "ak.profile.create principal_id is not the submitting actor",
                ));
            }
            if event.executed_by.is_none() && create.object.agent_slug.is_some() {
                return Err(rejected(
                    ConflictCode::FailedPrecondition,
                    "agent_slug needs the agent_selector_claim typed current, which this Station does not project",
                ));
            }
            create
                .materialize(event)
                .map_err(|error| rejected(ConflictCode::SchemaViolation, &error.to_string()))?
        }
        _ => {
            let update: ActorProfileUpdatePayload = payload(event, WHAT)?;
            let current = current.ok_or_else(|| {
                rejected(
                    ConflictCode::FailedPrecondition,
                    "the Account and scope have no accepted Actor Profile to update",
                )
            })?;
            if current.id.as_ref() != Some(&update.target_ref) {
                return Err(rejected(
                    ConflictCode::FailedPrecondition,
                    "ak.profile.update target_ref is not the Account and scope accepted Actor Profile",
                ));
            }
            if current.principal_id != subject.principal_id {
                return Err(rejected(
                    ConflictCode::FailedPrecondition,
                    "the accepted Actor Profile belongs to another principal",
                ));
            }
            update
                .validate_paths()
                .map_err(|error| rejected(ConflictCode::SchemaViolation, &error.to_string()))?;
            if let Some(expected) = &update.expected_state_digest {
                let digest = ActorProfileUpdatePayload::state_digest(&current)
                    .map_err(|error| corrupt(error.to_string()))?;
                if *expected != digest {
                    return Err(rejected(
                        ConflictCode::FailedPrecondition,
                        "expected_state_digest does not match the current Actor Profile",
                    ));
                }
            }
            let next = update
                .apply(event, &current)
                .map_err(|error| rejected(ConflictCode::FailedPrecondition, &error.to_string()))?;
            if event.executed_by.is_none()
                && next.agent_slug.is_some()
                && next.agent_slug != current.agent_slug
            {
                return Err(rejected(
                    ConflictCode::FailedPrecondition,
                    "agent_slug needs the agent_selector_claim typed current, which this Station does not project",
                ));
            }
            next
        }
    };
    if !accountability_holds_in_connection(
        conn,
        &next.accountable_principal_ids,
        &next.principal_id,
        at,
    )
    .await?
    {
        return Err(rejected(
            ConflictCode::AccountabilityGrantMissing,
            "an accountable principal has no active accountability record at the Commit",
        ));
    }

    Ok(next)
}

/// Project a fully admitted SDK Actor Profile at its actual covering Commit.
pub(crate) async fn write_profile_current_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &RealmCommit,
    profile: &ActorProfile,
) -> Result<(), PgTransactionError> {
    let profile_id = profile
        .id
        .as_ref()
        .ok_or_else(|| corrupt("materialized Actor Profile has no id"))?
        .as_str()
        .to_owned();
    let value = serde_json::to_value(profile).map_err(PersistenceError::database)?;
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| corrupt("Commit stream position is out of range"))?;
    let advanced = sql_query(
        "INSERT INTO actor_profile_current_results \
         (realm_id,actor_profile_id,current_commit_id,current_stream_position,value,updated_at,actor_id,scope_ref) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
         ON CONFLICT (actor_profile_id) DO UPDATE SET \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value, updated_at=EXCLUDED.updated_at \
         WHERE actor_profile_current_results.realm_id=EXCLUDED.realm_id \
           AND actor_profile_current_results.actor_id=EXCLUDED.actor_id \
           AND actor_profile_current_results.scope_ref=EXCLUDED.scope_ref \
           AND actor_profile_current_results.current_stream_position<EXCLUDED.current_stream_position",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&profile_id)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .bind::<Jsonb, _>(serde_json::json!(event.actor_id))
    .bind::<Jsonb, _>(serde_json::json!(event.scope_ref))
    .execute(&mut *conn)
    .await?;
    if advanced != 1 {
        return Err(corrupt("actor_profile row was not advanced by this Commit"));
    }
    sql_query(
        "INSERT INTO actor_profile_result_versions (commit_id,actor_profile_id,value) \
         VALUES ($1,$2,$3)",
    )
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Text, _>(&profile_id)
    .bind::<Jsonb, _>(&value)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Write one `identity_accountability` row with its accepting Commit. The
/// two registered writers -- the independent grant and the provision
/// projection -- address the same row through the normalized scope digest.
pub(crate) async fn write_identity_accountability_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    commit: &RealmCommit,
    value: &AccountabilityProjection,
) -> Result<(), PgTransactionError> {
    let digest = value
        .accountability_scope
        .digest()
        .map_err(|error| corrupt(error.to_string()))?;
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| corrupt("Commit stream position is out of range"))?;
    let scope =
        serde_json::to_value(&value.accountability_scope).map_err(PersistenceError::database)?;
    let written = sql_query(
        "INSERT INTO identity_accountability_current_results \
         (realm_id,issuer_id,subject_id,accountability_scope,scope_set_digest,\
          current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT (realm_id,issuer_id,subject_id,scope_set_digest) DO UPDATE SET \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value, updated_at=EXCLUDED.updated_at \
         WHERE identity_accountability_current_results.current_stream_position\
               <EXCLUDED.current_stream_position",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(value.issuer_id.as_str())
    .bind::<Text, _>(value.subject_id.as_str())
    .bind::<Jsonb, _>(scope)
    .bind::<Text, _>(digest.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(serde_json::to_value(value).map_err(PersistenceError::database)?)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await?;
    if written != 1 {
        return Err(corrupt(
            "identity_accountability row was not advanced by a later Commit",
        ));
    }
    Ok(())
}

pub(crate) async fn admit_accountability_grant_in_connection(
    conn: &mut AsyncPgConnection,
    write: &AccountabilityGrantAdmissionWrite,
) -> Result<AccountabilityGrantAdmissionOutcome, PgTransactionError> {
    const WHAT: &str = "accountability grant";
    let event = &write.commit.event;
    let commit = &write.commit.commit;
    if event.kind != EventKind::IdentityAccountabilityGrant {
        return Err(rejected(
            ConflictCode::SchemaViolation,
            "the accountability unit admits only ak.identity.accountability_grant",
        ));
    }
    let grant: AccountabilityGrantPayload = payload(event, WHAT)?;
    let value = AccountabilityProjection::from_grant(&grant)
        .map_err(|error| rejected(ConflictCode::SchemaViolation, &error.to_string()))?;
    let signer = match verify_pcr_self_event(conn, &write.commit, None, WHAT).await? {
        PcrSelfEventCut::Known(stored) => {
            let record = accountability_result_at(conn, &stored.commit_id)
                .await?
                .ok_or_else(|| {
                    rejected(
                        ConflictCode::DuplicateConflict,
                        "accountability grant Event was committed without its current row",
                    )
                })?;
            return Ok(AccountabilityGrantAdmissionOutcome::Duplicate(record));
        }
        PcrSelfEventCut::Fresh(signer) => signer,
    };
    // self_authored_proof: the issuer is the actor, and the endorsement lives
    // in the issuer's own PCR (a later change to a provision endorsement is
    // written to that same controller PCR).
    if grant.issuer_id != signer.account.principal_id {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "accountability grant issuer is not the Event actor",
        ));
    }
    if grant.proof.verification_method
        != event
            .producer_proof
            .as_ref()
            .map(|proof| proof.verification_method.clone())
            .ok_or_else(|| corrupt("verified Event lost its producer proof"))?
    {
        return Err(rejected(
            ConflictCode::SignatureInvalid,
            "accountability grant and its Event are signed by different methods",
        ));
    }
    let binding = grant
        .canonical_proof_binding_bytes()
        .map_err(|error| rejected(ConflictCode::SignatureInvalid, &error.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_payload_proof(
        &grant.proof,
        &binding,
        &signer.device_key,
    )
    .map_err(|_| {
        rejected(
            ConflictCode::SignatureInvalid,
            "accountability grant issuer proof does not match the issuer's active device key",
        )
    })?;

    commit_verified(conn, &write.commit, write.queued_at, WHAT).await?;
    write_identity_accountability_in_connection(conn, &event.realm_id, commit, &value).await?;
    Ok(AccountabilityGrantAdmissionOutcome::Committed(
        IdentityAccountabilityRecord {
            realm_id: event.realm_id.clone(),
            value,
            commit: commit.clone(),
        },
    ))
}

async fn accountability_result_at(
    conn: &mut AsyncPgConnection,
    commit_id: &arkret_wire::RealmCommitId,
) -> Result<Option<IdentityAccountabilityRecord>, PgTransactionError> {
    // A grant Event's current row may since have been advanced by a later
    // grant on the same subject; the Event's own projection is then its
    // payload, deterministically recomputed.
    let row = sql_query(
        "SELECT c.realm_id,e.envelope->'payload' AS value,c.commit_json \
         FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.commit_id=$1",
    )
    .bind::<Text, _>(commit_id.as_str())
    .get_result::<AccountabilityResultRow>(&mut *conn)
    .await
    .optional()?;
    row.map(|row| {
        let grant: AccountabilityGrantPayload =
            serde_json::from_value(row.value).map_err(corrupt)?;
        Ok(IdentityAccountabilityRecord {
            realm_id: arkret_wire::RealmId::new(row.realm_id).map_err(corrupt)?,
            value: AccountabilityProjection::from_grant(&grant).map_err(corrupt)?,
            commit: serde_json::from_value(row.commit_json).map_err(corrupt)?,
        })
    })
    .transpose()
}

#[async_trait::async_trait]
impl coland_storage::ActorProfileStore for PgActorProfileStore {
    async fn admit_profile(
        &self,
        write: ActorProfileAdmissionWrite,
    ) -> PersistenceResult<ActorProfileAdmissionOutcome> {
        write.commit.validate().map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "invalid Actor Profile authority transaction: {error}"
            ))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            admit_profile_in_connection(conn, &write).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn admit_accountability_grant(
        &self,
        write: AccountabilityGrantAdmissionWrite,
    ) -> PersistenceResult<AccountabilityGrantAdmissionOutcome> {
        write.commit.validate().map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "invalid accountability grant authority transaction: {error}"
            ))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            admit_accountability_grant_in_connection(conn, &write).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn admit_agent_provision(
        &self,
        write: coland_storage::AgentProvisionAdmissionWrite,
    ) -> PersistenceResult<coland_storage::AgentProvisionAdmissionOutcome> {
        write.commit.validate().map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "invalid Agent provision authority transaction: {error}"
            ))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::agent_provisioning::admit_agent_provision_in_connection(conn, &write).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn admit_agent_pcr_genesis(
        &self,
        write: coland_storage::AgentPcrGenesisAdmissionWrite,
    ) -> PersistenceResult<coland_storage::AgentPcrGenesisAdmissionOutcome> {
        write.commit.validate().map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "invalid Agent PCR genesis authority transaction: {error}"
            ))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::agent_pcr_genesis::admit_agent_pcr_genesis_in_connection(conn, &write).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn admit_agent_control_event(
        &self,
        write: coland_storage::AgentControlAdmissionWrite,
    ) -> PersistenceResult<coland_storage::AgentControlAdmissionOutcome> {
        self.admit_agent_control_event_with_origin(write, None)
            .await
    }

    async fn admit_agent_control_event_with_origin(
        &self,
        write: coland_storage::AgentControlAdmissionWrite,
        origin: Option<coland_storage::AgentControlOriginSource>,
    ) -> PersistenceResult<coland_storage::AgentControlAdmissionOutcome> {
        write.commit.validate().map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "invalid Agent control authority transaction: {error}"
            ))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::agent_control::admit_agent_control_event_in_connection(
                conn,
                &write,
                origin.as_ref(),
            )
            .await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn admit_agent_same_key_renewal(
        &self,
        write: coland_storage::AgentControlAdmissionWrite,
        origin: Option<coland_storage::AgentControlOriginSource>,
    ) -> PersistenceResult<coland_storage::AgentControlAdmissionOutcome> {
        write
            .commit
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::agent_control::admit_agent_same_key_renewal_in_connection(
                conn,
                &write,
                origin.as_ref(),
            )
            .await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn current_profile(
        &self,
        account: &AccountId,
    ) -> PersistenceResult<Option<ActorProfileResultRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT a.value,e.envelope,c.commit_json \
             FROM principal_resolutions p \
             JOIN actor_profile_current_results a ON a.realm_id=p.pcr_realm_id \
             JOIN realm_commits c ON c.commit_id=a.current_commit_id \
             JOIN canonical_events e ON e.pk=c.event_pk \
             WHERE p.principal_id=$1 AND p.station_id=$2",
        )
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .get_result::<ProfileResultRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(profile_record)
            .transpose()
            .map_err(PgTransactionError::into_persistence)
    }

    async fn accountability_verified_at(
        &self,
        issuer_id: &DidCoreId,
        subject_id: &DidCoreId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT value FROM identity_accountability_current_results \
             WHERE subject_id=$1 AND issuer_id=$2",
        )
        .bind::<Text, _>(subject_id.as_str())
        .bind::<Text, _>(issuer_id.as_str())
        .get_results::<AccountabilityRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        for row in rows {
            let value: AccountabilityProjection = serde_json::from_value(row.value)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            if value.verifies_at(at) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
