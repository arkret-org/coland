//! Independent MIMI service authorship and attribution, rechecked before writes.
use coland_storage::{PersistenceError, PersistenceResult, SelfProducerCommitGuard};
use diesel::sql_types::{Jsonb, Text};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
fn refused(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}

pub(crate) async fn check_facade_producer_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    guard: &SelfProducerCommitGuard,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let SelfProducerCommitGuard::MimiFacade {
        service_id,
        verification_method,
        room_uri,
        binding_event_id,
        attributed_actor,
        source_provider_id,
        reporter_authority,
        submit_request_body,
        mapping_receipt,
        reporter_device_guard,
    } = guard
    else {
        return Err(refused("missing MIMI facade guard"));
    };
    if event.actor_id != arkret_wire::ActorId::service(service_id.clone())
        || event.executed_by.is_some()
        || event.authorization_ref.is_some()
        || event.applet_id.is_some()
        || !matches!(
            event.kind,
            arkret_wire::EventKind::MessageCreate | arkret_wire::EventKind::SelfModerationReport
        )
    {
        return Err(refused(
            "MIMI Event is not directly authored by the configured Service",
        ));
    }
    let row =
        diesel::sql_query("SELECT identity AS value FROM service_identity WHERE id=$1 FOR SHARE")
            .bind::<Text, _>(crate::SINGLETON_ID)
            .get_result::<JsonRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(|| refused("durable Service identity unavailable"))?;
    let stored: arkret_identity::service_identity::StoredDidCoreIdentity =
        serde_json::from_value(row.value).map_err(PersistenceError::database)?;
    stored
        .validate()
        .map_err(|_| refused("Service identity history invalid"))?;
    if &stored.identity.service_id != service_id {
        return Err(refused("Service identity changed"));
    }
    let method = stored
        .did_document
        .verification_method
        .iter()
        .find(|method| {
            method.id == verification_method.as_str()
                && stored.did_document.assertion_method.contains(&method.id)
        })
        .ok_or_else(|| refused("Service assertion method no longer current"))?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| refused("Service proof missing"))?;
    if &proof.verification_method != verification_method {
        return Err(refused("Service proof method differs"));
    }
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|_| refused("Service Event proof transcript invalid"))?;
    let digest =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(|_| refused("Event digest suite invalid"))?;
    event
        .verify_event_id_matches_content_with_digest_suite(digest)
        .map_err(|_| refused("Event id differs from Service content"))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
            value: method.public_key_multibase.clone(),
        },
        digest,
    )
    .map_err(|_| refused("Service Event signature invalid"))?;
    let row = diesel::sql_query("SELECT b.value FROM mimi_room_binding_current_states b JOIN realm_commits c ON c.commit_id=b.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE b.mimi_room_uri=$1 AND b.realm_id=$2 AND b.current_event_id=$3 AND c.realm_id=b.realm_id AND c.stream_position=b.current_stream_position AND e.state='committed' AND c.commit_json->>'event_ref'=b.current_event_id AND e.envelope->'payload'=b.value FOR UPDATE OF b")
        .bind::<Text,_>(room_uri.as_str()).bind::<Text,_>(event.realm_id.as_str())
        .bind::<Text,_>(binding_event_id.as_str()).get_result::<JsonRow>(&mut *conn).await
        .optional().map_err(PersistenceError::database)?.ok_or_else(|| refused("MIMI binding is no longer current"))?;
    if row.value.get("local_provider_role").and_then(Value::as_str) == Some("observer") {
        return Err(PersistenceError::Conflict(
            "mimi_observer_write_forbidden: observer cannot author Events".into(),
        ));
    }
    if row.value.get("status").and_then(Value::as_str) != Some("accepted")
        || !matches!(
            row.value.get("local_provider_role").and_then(Value::as_str),
            Some("hub" | "follower")
        )
    {
        return Err(refused("MIMI binding is not writable"));
    }
    crate::moderation_report_current_states::ensure_scope_member(
        conn,
        &event.realm_id,
        &event.scope_ref,
        attributed_actor,
    )
    .await?;
    if event.kind == arkret_wire::EventKind::MessageCreate {
        let provenance = event
            .payload
            .get("mimi_provenance")
            .ok_or_else(|| refused("MIMI provenance missing"))?;
        if provenance.get("source_provider_id").and_then(Value::as_str)
            != Some(source_provider_id.as_str())
            || provenance.get("attributed_sender_actor_id")
                != Some(
                    &serde_json::to_value(attributed_actor).map_err(PersistenceError::database)?,
                )
            || provenance.get("room_binding_ref").and_then(Value::as_str)
                != Some(binding_event_id.as_str())
        {
            return Err(refused("MIMI sender attribution differs"));
        }
        let receipt = mapping_receipt
            .as_ref()
            .ok_or_else(|| refused("MIMI mapping receipt missing"))?;
        if receipt.get("receipt_kind").and_then(Value::as_str) != Some("content_mapping_receipt")
            || receipt.get("mimi_room_uri").and_then(Value::as_str) != Some(room_uri.as_str())
            || receipt.get("arkret_event_id").and_then(Value::as_str)
                != Some(event.event_id.as_str())
            || receipt.get("original_envelope_digest") != provenance.get("source_envelope_digest")
        {
            return Err(refused(
                "MIMI mapping receipt differs from Event provenance",
            ));
        }
        let mut unsigned = receipt.clone();
        let proof: arkret_wire::PayloadProof = serde_json::from_value(
            unsigned
                .as_object_mut()
                .ok_or_else(|| refused("invalid MIMI receipt"))?
                .remove("proof")
                .ok_or_else(|| refused("MIMI receipt signature missing"))?,
        )
        .map_err(PersistenceError::database)?;
        if &proof.verification_method != verification_method {
            return Err(refused("MIMI receipt signer differs"));
        }
        let bytes = arkret_canonical::canonical_json_bytes(&unsigned)
            .map_err(PersistenceError::database)?;
        arkret_signatures::verify_ed25519_detached_jws_payload_proof(
            &proof,
            &bytes,
            &arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
                value: method.public_key_multibase.clone(),
            },
        )
        .map_err(|_| refused("MIMI receipt signature invalid"))?;
        let account = attributed_actor
            .as_account_id()
            .ok_or_else(|| refused("MIMI sender is not an Account"))?;
        if &account.station_id != source_provider_id {
            return Err(refused(
                "MIMI sender Station differs from authenticated provider",
            ));
        }
        let request = submit_request_body
            .as_ref()
            .ok_or_else(|| refused("MIMI request guard missing"))?;
        let request_bytes =
            arkret_canonical::canonical_json_bytes(request).map_err(PersistenceError::database)?;
        if provenance
            .get("source_envelope_digest")
            .and_then(Value::as_str)
            != Some(arkret_canonical::sha256_digest(&request_bytes).as_str())
        {
            return Err(refused("MIMI request digest differs from provenance"));
        }
        if let Some(group_id) = row.value.get("mls_group_id").and_then(Value::as_str) {
            let derived = event
                .scope_ref
                .canonical_mls_group_id()
                .map_err(|_| refused("MLS scope invalid"))?;
            if group_id != derived.as_str()
                || request.get("mls_group_id").and_then(Value::as_str) != Some(group_id)
            {
                return Err(PersistenceError::Conflict(
                    "mimi_mls_group_id_mismatch: group id differs from native scope".into(),
                ));
            }
            let key = crate::mls_group_current_states::scope_key(&event.scope_ref)?;
            let current = crate::mls_group_current_states::locked_group(conn, &key)
                .await?
                .ok_or_else(|| refused("native MLS current unavailable"))?;
            let mismatch = || {
                PersistenceError::Conflict(
                    "mimi_governance_binding_mismatch: accepted MLS frontier differs".into(),
                )
            };
            if request
                .get("epoch")
                .and_then(arkret_canonical::serde_helpers::parse_uint64_decimal_value)
                != Some(current.value.epoch)
                || current.value.effective_scope != event.scope_ref
            {
                return Err(mismatch());
            }
            let tracker = arkret_mls::MlsPublicGroupTracker::restore(
                &current.public_state,
                derived.as_str(),
                current.value.epoch,
            )
            .map_err(|_| mismatch())?;
            let accepted_binding = tracker.governance_binding().map_err(|_| mismatch())?;
            let request: arkret_models_collaboration::mimi_operations::MimiSubmitMessageRequestBody =
                serde_json::from_value(request.clone()).map_err(PersistenceError::database)?;
            let bytes = arkret_canonical::base64url_decode(request.ciphertext.payload.as_str())
                .map_err(|_| mismatch())?;
            let message: Value = serde_json::from_slice(&bytes).map_err(|_| mismatch())?;
            let associated = request
                .associated_data
                .as_ref()
                .and_then(|value| value.payload.as_ref())
                .map(|value| arkret_canonical::base64url_decode(value.as_str()))
                .transpose()
                .map_err(|_| mismatch())?
                .map(|bytes| serde_json::from_slice::<Value>(&bytes))
                .transpose()
                .map_err(|_| mismatch())?;
            let submitted_binding = message
                .get("governance_binding")
                .or_else(|| {
                    associated
                        .as_ref()
                        .and_then(|value| value.get("governance_binding"))
                })
                .or_else(|| row.value.get("governance_binding"))
                .ok_or_else(mismatch)?;
            if &serde_json::to_value(accepted_binding).map_err(PersistenceError::database)?
                != submitted_binding
            {
                return Err(mismatch());
            }
        }
    } else {
        let body: arkret_models_collaboration::mimi_operations::MimiReportAbuseRequestBody =
            serde_json::from_value(
                reporter_authority
                    .clone()
                    .ok_or_else(|| refused("MIMI reporter request missing"))?,
            )
            .map_err(PersistenceError::database)?;
        body.validate()
            .map_err(|_| refused("MIMI report claim invalid"))?;
        let authority = &body.reporter_authority;
        if &authority.actor_id != attributed_actor
            || authority.expires_at <= committed_at
            || authority.room_binding_ref.event_id != *binding_event_id
            || body.report_claim.scope_ref != event.scope_ref
        {
            return Err(refused("MIMI reporter authority differs or expired"));
        }
        for (reference, table, predicate, subject) in [
            (
                &authority.room_binding_ref,
                "mimi_room_binding_current_states",
                "mimi_room_uri",
                room_uri.as_str().to_owned(),
            ),
            (
                &authority.membership_ref,
                "member_state_current_states",
                "member_id",
                attributed_actor.to_string(),
            ),
        ] {
            // Table and predicate are closed implementation constants, never request strings.
            let query = format!(
                "SELECT c.commit_json AS value FROM {table} r JOIN realm_commits c ON c.commit_id=r.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE r.realm_id=$1 AND r.{predicate}=$2 AND e.state='committed' AND c.realm_id=r.realm_id AND c.stream_position=r.current_stream_position FOR SHARE OF r"
            );
            let row = diesel::sql_query(query)
                .bind::<Text, _>(event.realm_id.as_str())
                .bind::<Text, _>(subject)
                .get_result::<JsonRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?
                .ok_or_else(|| refused("MIMI reporter current reference unavailable"))?;
            let commit: arkret_wire::RealmCommit =
                serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            if commit.commit_id != reference.commit_id
                || commit.event_ref != reference.event_id
                || commit.stream_ref != reference.stream_ref
                || commit.stream_position != reference.stream_position
            {
                return Err(refused(
                    "MIMI reporter reference is no longer exact current",
                ));
            }
        }
        let selector = reporter_device_guard
            .as_ref()
            .ok_or_else(|| refused("MIMI reporter device authority unavailable"))?;
        crate::ensure_gate_allowed_in_transaction(conn, selector).await?;
        let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
        if payload.get("reporter_id").and_then(Value::as_str)
            != Some(attributed_actor.signing_principal_id().as_str())
            || payload.get("source_provider_id").and_then(Value::as_str)
                != Some(source_provider_id.as_str())
            || payload.get("target_ref")
                != Some(
                    &serde_json::to_value(&body.report_claim.target_ref)
                        .map_err(PersistenceError::database)?,
                )
        {
            return Err(refused("MIMI report attribution differs"));
        }
    }
    Ok(())
}

/// A losing concurrent report must roll back its Event as well as its response.
pub(crate) async fn record_report_idempotency_in_connection(
    conn: &mut AsyncPgConnection,
    record: &coland_storage::IdempotencyRecord,
) -> PersistenceResult<()> {
    use diesel::sql_types::{Integer, Timestamptz};
    let actor_key = record
        .authenticated_actor
        .canonical_key()
        .map_err(|e| refused(&e.to_string()))?;
    let inserted = diesel::sql_query("INSERT INTO idempotency_keys (actor_key,authenticated_actor,operation_id,idempotency_key,request_hash,response_status,response_body,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(actor_key,operation_id,idempotency_key) DO NOTHING")
        .bind::<Text,_>(actor_key).bind::<Jsonb,_>(serde_json::to_value(&record.authenticated_actor).map_err(PersistenceError::database)?)
        .bind::<Text,_>(&record.operation_id).bind::<Text,_>(&record.idempotency_key).bind::<Text,_>(&record.request_hash)
        .bind::<Integer,_>(record.response_status).bind::<Jsonb,_>(&record.response_body)
        .bind::<Timestamptz,_>(record.created_at).bind::<Timestamptz,_>(record.expires_at)
        .execute(conn).await.map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: MIMI report request already committed".into(),
        ));
    }
    Ok(())
}

/// The signed receipt remains in controlled local audit storage, outside Realm history.
pub(crate) async fn persist_mapping_receipt_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    guard: &SelfProducerCommitGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let SelfProducerCommitGuard::MimiFacade {
        mapping_receipt: Some(receipt),
        ..
    } = guard
    else {
        return Ok(());
    };
    diesel::sql_query("INSERT INTO audit_logs(id,actor_id,action,outcome,realm_id,payload,created_at) VALUES($1,$2,'mimi.content_mapping','accepted',$3,$4,$5)")
        .bind::<diesel::sql_types::Uuid,_>(uuid::Uuid::now_v7()).bind::<Text,_>(event.actor_id.to_string())
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(receipt)
        .bind::<diesel::sql_types::Timestamptz,_>(at).execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}
