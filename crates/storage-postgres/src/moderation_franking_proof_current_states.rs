//! The existing franking proof result and its local durable publication work.

use arkret_models_collaboration::events_payloads::moderation::FrankingProof;
use arkret_wire::{ActorId, Event, EventId, EventKind, RealmId, ScopeRef};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Binary, Jsonb, Nullable, SmallInt, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("signature_invalid: franking proof: {detail}"))
}

#[derive(diesel::QueryableByName)]
struct TargetRow {
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type = SmallInt)]
    digest_suite: i16,
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
}

async fn accepted_encrypted_target(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    target: &EventId,
) -> PersistenceResult<(Event, arkret_canonical::DigestSuite)> {
    let token = crate::ids::parse_event_id(target.as_str())
        .ok_or_else(|| invalid("target Event id is malformed"))?;
    let row = diesel::sql_query(
        "SELECT e.envelope,e.digest_suite,c.commit_json FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND c.realm_id=$2 AND e.state='committed'",
    )
    .bind::<Binary, _>(token.to_vec())
    .bind::<Text, _>(realm.as_str())
    .get_result::<TargetRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| invalid("target has no accepted Event and covering Commit"))?;
    let event: Event = serde_json::from_value(row.envelope).map_err(invalid)?;
    let commit: arkret_wire::RealmCommit =
        serde_json::from_value(row.commit_json).map_err(invalid)?;
    let suite = match row.digest_suite {
        1 => arkret_canonical::DigestSuite::Sha256,
        2 => arkret_canonical::DigestSuite::Blake3,
        _ => return Err(invalid("target digest suite is unregistered")),
    };
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(invalid)?;
    event
        .verify_producer_proof_self_consistency(suite)
        .map_err(invalid)?;
    let stream = arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, Some(realm.clone()))
        .map_err(invalid)?;
    if event.event_id != *target
        || event.realm_id != *realm
        || commit.event_ref != *target
        || commit.realm_id != *realm
        || commit.stream_ref != stream
        || !matches!(
            event.kind,
            EventKind::MessageCreate | EventKind::MessageRevise
        )
        || !event
            .payload
            .get("encrypted_content")
            .is_some_and(serde_json::Value::is_object)
        || event.payload.contains_key("content")
    {
        return Err(invalid("target is not an exact accepted encrypted Message"));
    }
    Ok((event, suite))
}

/// Disclosure follows the encrypted target's signed scope, even when the
/// proof itself is committed to the Realm stream.
pub(crate) async fn franking_target_scope_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    target: &EventId,
) -> PersistenceResult<ScopeRef> {
    accepted_encrypted_target(conn, realm, target)
        .await
        .map(|(event, _)| event.scope_ref)
}

/// The accepted Message and the obligation to publish its proof commit in
/// one local domain transaction. A later publication failure cannot change
/// the Message's accepted outcome.
pub(crate) async fn enqueue_franking_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    receiver: &arkret_wire::DidCoreId,
    received_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if !matches!(
        event.kind,
        EventKind::MessageCreate | EventKind::MessageRevise
    ) || !event
        .payload
        .get("encrypted_content")
        .is_some_and(serde_json::Value::is_object)
    {
        return Ok(());
    }
    // Freeze the receiver's observation at the closed FrankingProof timestamp
    // precision before storing it; no signed Event or Commit field is changed.
    let received_at = arkret_canonical::normalize_timestamp_canonical(received_at);
    diesel::sql_query(
        "INSERT INTO moderation_franking_jobs \
         (realm_id,target_event_id,received_by,received_at) VALUES($1,$2,$3,$4) \
         ON CONFLICT(realm_id,target_event_id,received_by) DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(receiver.as_str())
    .bind::<Timestamptz, _>(received_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

#[derive(diesel::QueryableByName)]
struct JobRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    target_event_id: String,
    #[diesel(sql_type = Text)]
    received_by: String,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    prepared_event: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Binary>)]
    verification_key: Option<Vec<u8>>,
}

pub(crate) async fn pending_franking_in_connection(
    conn: &mut AsyncPgConnection,
    receiver: &arkret_wire::DidCoreId,
) -> PersistenceResult<Vec<coland_storage::PendingFrankingProof>> {
    diesel::sql_query(
        "SELECT realm_id,target_event_id,received_by,received_at,prepared_event,verification_key \
         FROM moderation_franking_jobs WHERE received_by=$1 ORDER BY received_at,target_event_id LIMIT 64",
    )
    .bind::<Text, _>(receiver.as_str())
    .load::<JobRow>(conn)
    .await
    .map_err(PersistenceError::database)?
    .into_iter()
    .map(|row| Ok(coland_storage::PendingFrankingProof {
        realm_id: RealmId::new(row.realm_id).map_err(invalid)?,
        target_event_id: EventId::new(row.target_event_id).map_err(invalid)?,
        received_by: arkret_wire::DidCoreId::new(row.received_by).map_err(invalid)?,
        received_at: row.received_at,
        prepared_event: row.prepared_event.map(serde_json::from_value).transpose().map_err(invalid)?,
        verification_key: row.verification_key,
    }))
    .collect()
}

fn verify_prepared(
    event: &Event,
    proof: &FrankingProof,
    key: &[u8],
    suite: arkret_canonical::DigestSuite,
) -> PersistenceResult<()> {
    if event.kind != EventKind::ModerationFrankingProof
        || event.realm_id != proof.realm_id
        || event.actor_id != ActorId::service(proof.received_by.clone())
        || event.scope_ref
            != (ScopeRef::Realm {
                realm_id: proof.realm_id.clone(),
            })
        || key.len() != 32
    {
        return Err(invalid(
            "prepared proof does not bind its service and Realm",
        ));
    }
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(invalid)?;
    event
        .verify_producer_proof_self_consistency(suite)
        .map_err(invalid)?;
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: key.to_vec(),
    };
    arkret_signatures::franking_proof::verify_franking_proof_signature(proof, &material)
        .map_err(invalid)?;
    let producer = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| invalid("proof Event is unsigned"))?;
    if producer.verification_method != proof.verification_method {
        return Err(invalid("proof Event uses a different service method"));
    }
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(invalid)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        producer,
        &bytes,
        &event.actor_id,
        &material,
        suite,
    )
    .map_err(invalid)?;
    Ok(())
}

/// A concurrent worker may win; the durable first Event is returned exactly.
pub(crate) async fn fix_franking_in_connection(
    conn: &mut AsyncPgConnection,
    prepared: &coland_storage::PreparedFrankingProof,
) -> PersistenceResult<Event> {
    let proof: FrankingProof =
        serde_json::from_value(serde_json::to_value(&prepared.event.payload).map_err(invalid)?)
            .map_err(invalid)?;
    if proof.realm_id != prepared.realm_id
        || proof.event_id != prepared.target_event_id
        || proof.received_by != prepared.received_by
    {
        return Err(invalid("prepared proof differs from its exact job target"));
    }
    let (_, suite) =
        accepted_encrypted_target(conn, &prepared.realm_id, &prepared.target_event_id).await?;
    verify_prepared(&prepared.event, &proof, &prepared.verification_key, suite)?;
    let envelope = serde_json::to_value(&prepared.event).map_err(invalid)?;
    diesel::sql_query(
        "UPDATE moderation_franking_jobs SET prepared_event=COALESCE(prepared_event,$4), \
         verification_key=COALESCE(verification_key,$5) \
         WHERE realm_id=$1 AND target_event_id=$2 AND received_by=$3 AND received_at=$6",
    )
    .bind::<Text, _>(prepared.realm_id.as_str())
    .bind::<Text, _>(prepared.target_event_id.as_str())
    .bind::<Text, _>(prepared.received_by.as_str())
    .bind::<Jsonb, _>(&envelope)
    .bind::<Binary, _>(&prepared.verification_key)
    .bind::<Timestamptz, _>(proof.received_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    #[derive(diesel::QueryableByName)]
    struct Fixed {
        #[diesel(sql_type = Jsonb)]
        prepared_event: serde_json::Value,
    }
    let row = diesel::sql_query(
        "SELECT prepared_event FROM moderation_franking_jobs \
         WHERE realm_id=$1 AND target_event_id=$2 AND received_by=$3 AND prepared_event IS NOT NULL",
    )
    .bind::<Text, _>(prepared.realm_id.as_str())
    .bind::<Text, _>(prepared.target_event_id.as_str())
    .bind::<Text, _>(prepared.received_by.as_str())
    .get_result::<Fixed>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| invalid("prepared proof has no matching durable receipt job"))?;
    serde_json::from_value(row.prepared_event).map_err(invalid)
}

#[derive(diesel::QueryableByName)]
struct AuthorityServiceRow {
    #[diesel(sql_type = Text)]
    service_id: String,
}

/// Publish only the exact bytes fixed by the receiving service's authenticated
/// historical-method verifier. This internal worker path never relaxes the
/// public self-Event Account producer guard.
pub(crate) async fn commit_franking_current_state_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::ModerationFrankingProof {
        return Ok(());
    }
    let proof: FrankingProof =
        serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?)
            .map_err(invalid)?;
    let (_, suite) = accepted_encrypted_target(conn, &proof.realm_id, &proof.event_id).await?;
    let authority = diesel::sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(proof.realm_id.as_str())
        .get_result::<AuthorityServiceRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| invalid("receiving service authorization is unavailable"))?;
    if authority.service_id != proof.received_by.as_str()
        || commit.event_ref != event.event_id
        || commit.realm_id != proof.realm_id
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: proof.realm_id.clone(),
            })
    {
        return Err(invalid(
            "proof is not bound to the authorized receiving Station",
        ));
    }
    let job = diesel::sql_query(
        "SELECT realm_id,target_event_id,received_by,received_at,prepared_event,verification_key \
         FROM moderation_franking_jobs WHERE realm_id=$1 AND target_event_id=$2 AND received_by=$3 FOR UPDATE",
    )
    .bind::<Text, _>(proof.realm_id.as_str())
    .bind::<Text, _>(proof.event_id.as_str())
    .bind::<Text, _>(proof.received_by.as_str())
    .get_result::<JobRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| invalid("proof has no authenticated durable receipt job"))?;
    if job.received_at != proof.received_at
        || job.prepared_event.as_ref() != Some(&serde_json::to_value(event).map_err(invalid)?)
    {
        return Err(invalid("proof differs from the first fixed receipt bytes"));
    }
    let key = job
        .verification_key
        .ok_or_else(|| invalid("historical service key is absent"))?;
    verify_prepared(event, &proof, &key, suite)?;
    consume_proof_nonce(conn, &proof, event, commit.committed_at).await?;
    let position = i64::try_from(commit.stream_position).map_err(invalid)?;
    let inserted = diesel::sql_query(
        "INSERT INTO moderation_franking_proof_current_states \
         (realm_id,target_event_id,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id,target_event_id) DO NOTHING",
    )
    .bind::<Text, _>(proof.realm_id.as_str())
    .bind::<Text, _>(proof.event_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(invalid)?)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(serde_json::to_value(&proof).map_err(invalid)?)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(PersistenceError::Conflict("duplicate_conflict".into()));
    }
    diesel::sql_query(
        "DELETE FROM moderation_franking_jobs WHERE realm_id=$1 AND target_event_id=$2 AND received_by=$3",
    )
    .bind::<Text, _>(proof.realm_id.as_str())
    .bind::<Text, _>(proof.event_id.as_str())
    .bind::<Text, _>(proof.received_by.as_str())
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

async fn consume_proof_nonce(
    conn: &mut AsyncPgConnection,
    proof: &FrankingProof,
    event: &Event,
    consumed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let expires_at = coland_storage::franking_replay_nonce_expires_at(consumed_at)?;
    diesel::sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!(
            "franking_proof_nonce.v1|{}|{}",
            proof.realm_id, proof.received_by
        ))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    diesel::sql_query(
        "DELETE FROM moderation_franking_proof_nonces WHERE realm_id=$1 AND received_by=$2 AND expires_at<=$3",
    )
    .bind::<Text, _>(proof.realm_id.as_str())
    .bind::<Text, _>(proof.received_by.as_str())
    .bind::<Timestamptz, _>(consumed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let active = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM moderation_franking_proof_nonces WHERE realm_id=$1 AND received_by=$2",
    )
    .bind::<Text, _>(proof.realm_id.as_str())
    .bind::<Text, _>(proof.received_by.as_str())
    .get_result::<Count>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if active.count >= coland_storage::LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE as i64 {
        return Err(PersistenceError::Conflict("rate_limited".into()));
    }
    let inserted = diesel::sql_query(
        "INSERT INTO moderation_franking_proof_nonces \
         (realm_id,received_by,replay_nonce,proof_event_id,consumed_at,expires_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(proof.realm_id.as_str())
    .bind::<Text, _>(proof.received_by.as_str())
    .bind::<Text, _>(&proof.replay_nonce)
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Timestamptz, _>(consumed_at)
    .bind::<Timestamptz, _>(expires_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(PersistenceError::Conflict("duplicate_conflict".into()));
    }
    Ok(())
}

pub(crate) async fn complete_franking_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    target: &EventId,
    proof_event: &EventId,
) -> PersistenceResult<()> {
    let token = crate::ids::parse_event_id(proof_event.as_str())
        .ok_or_else(|| invalid("completion Event id is malformed"))?;
    #[derive(diesel::QueryableByName)]
    struct Present {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        present: bool,
    }
    let present = diesel::sql_query(
        "SELECT EXISTS(SELECT 1 FROM moderation_franking_proof_current_states r \
         JOIN realm_commits c ON c.commit_id=r.current_commit_id \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE r.realm_id=$1 AND r.target_event_id=$2 AND e.id=$3 \
         AND e.state='committed' AND e.kind='ak.moderation.franking_proof' \
         AND r.value=e.envelope->'payload') AS present",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(target.as_str())
    .bind::<Binary, _>(token.to_vec())
    .get_result::<Present>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !present.present {
        return Err(invalid("completion has no exact accepted proof result"));
    }
    diesel::sql_query(
        "DELETE FROM moderation_franking_jobs j USING canonical_events e \
         WHERE j.realm_id=$1 AND j.target_event_id=$2 AND e.id=$3 \
         AND j.prepared_event=e.envelope",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(target.as_str())
    .bind::<Binary, _>(token.to_vec())
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}
