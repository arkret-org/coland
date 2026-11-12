//! Single-object native ciphertext release at a current requester cut.

use arkret_models_crypto::{
    KeyBackup, KeyBackupUnlockProofBody, RealmActorBackupIssueUnlockChallengeRequestBody,
    RealmActorBackupUnlockChallenge, RealmActorBackupUnlockChallengeKind as Kind,
    RealmActorBackupUnlockChallengePurpose as Purpose,
};
use arkret_models_integration::{KeysBackupsUnlockResponseBody, RealmActorContentBackupSource};
use arkret_wire::{ActorId, BackupId, CommittedEventRef, ScopeRef};
use coland_storage::{PersistenceError, PersistenceResult, RealmActorBackupReader};
use diesel::sql_types::{Jsonb, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncConnection;
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::{Value, json};

use super::{AsyncPgConnection, unavailable};
use crate::{PgPool, PgTransactionError, pg_conn};

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct ChallengeRow {
    #[diesel(sql_type=Jsonb)]
    challenge: Value,
    #[diesel(sql_type=Nullable<Text>)]
    request_digest: Option<String>,
    #[diesel(sql_type=Nullable<Jsonb>)]
    fixed_reply: Option<Value>,
}

fn actor(reader: &RealmActorBackupReader) -> ActorId {
    match reader {
        RealmActorBackupReader::Device(context) => context.endpoint.authority.actor_id.clone(),
        RealmActorBackupReader::Manager(reader) => ActorId::realm(reader.actor.clone()),
    }
}

fn expiry(reader: &RealmActorBackupReader) -> chrono::DateTime<chrono::Utc> {
    match reader {
        RealmActorBackupReader::Device(context) => context
            .credential_expires_at
            .min(context.endpoint.authority.expires_at),
        RealmActorBackupReader::Manager(reader) => reader.transport_expires_at,
    }
}

/// Server-private challenge-ledger identity, never a wire selector or proof.
fn requester(reader: &RealmActorBackupReader) -> Value {
    match reader {
        RealmActorBackupReader::Device(context) => {
            json!({"kind":"realm_actor_device","actor":context.endpoint.authority.actor_id,"device_id":context.endpoint.authority.device_id,"authorization_ref":context.endpoint.authority.authorization_ref,"device_generation":context.endpoint.authority.current_device_generation_ref})
        }
        RealmActorBackupReader::Manager(reader) => {
            json!({"kind":"realm_actor_manager","actor":reader.actor,"service_id":reader.service_id})
        }
    }
}

async fn target(
    conn: &mut AsyncPgConnection,
    reader: &RealmActorBackupReader,
    id: &BackupId,
    scope: &ScopeRef,
    operation: &str,
) -> PersistenceResult<(
    KeyBackup,
    RealmActorContentBackupSource,
    CommittedEventRef,
    CommittedEventRef,
)> {
    let subject = actor(reader);
    let native = subject
        .as_realm_actor_id()
        .ok_or_else(|| unavailable("native unlock subject absent"))?;
    arkret_models_crypto::validate_realm_actor_backup_scope(native, scope).map_err(unavailable)?;
    let (manager_ref, recovery_ref, authority) = match reader {
        RealmActorBackupReader::Device(context) => {
            if context.endpoint.effective_scope != *scope {
                return Err(unavailable(
                    "native unlock scope differs from authenticated Device",
                ));
            }
            let head = super::reading::head_for_action(conn, context, operation).await?;
            if head.items.first().map(|entry| &entry.metadata.backup_id) != Some(id) {
                return Err(unavailable(
                    "native Device may unlock only the current selected-series head",
                ));
            }
            (
                head.active_series.manager_ref,
                head.active_series.recovery_ref,
                &context.authority,
            )
        }
        RealmActorBackupReader::Manager(reader) => {
            let (manager, recovery) = super::reading::qualify_manager(conn, reader).await?;
            (manager, recovery, &reader.authority)
        }
    };
    let row=sql_query("SELECT source AS value FROM realm_actor_backup_admissions WHERE backup_id=$1 AND realm_id=$2 AND actor_id=$3 AND effective_scope=$4 FOR SHARE")
        .bind::<diesel::sql_types::Uuid,_>(crate::ids::typed_uuid_part_expect_internal(id.as_str()))
        .bind::<Text,_>(native.realm_id.as_str()).bind::<Jsonb,_>(json!(subject)).bind::<Jsonb,_>(json!(scope))
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||unavailable("native exact packet source unavailable"))?;
    let source: RealmActorContentBackupSource =
        serde_json::from_value(row.value).map_err(unavailable)?;
    let backup = crate::content_root_packages::read_retained_envelope(conn, id).await?;
    arkret_identity::realm_actor_content_backup::verify_realm_actor_content_backup_source(
        &backup, &source, authority,
    )
    .map_err(unavailable)?;
    if backup.actor_id != subject || source.admission.effective_scope != *scope {
        return Err(unavailable("native exact packet subject/scope differs"));
    }
    Ok((backup, source, manager_ref, recovery_ref))
}

pub(crate) async fn issue_native_unlock(
    pool: &PgPool,
    reader: &RealmActorBackupReader,
    id: &BackupId,
    request: &RealmActorBackupIssueUnlockChallengeRequestBody,
    audience: &str,
    service_id: &arkret_wire::DidCoreId,
) -> PersistenceResult<RealmActorBackupUnlockChallenge> {
    request.validate().map_err(unavailable)?;
    let subject = actor(reader);
    if subject.as_realm_actor_id() != Some(&request.realm_actor_id) {
        return Err(unavailable("native challenge actor differs"));
    }
    match reader {
        RealmActorBackupReader::Device(_)
            if request.kind == Kind::RealmActorDevice
                && request.purpose == Purpose::SeriesPredecessor => {}
        RealmActorBackupReader::Manager(_)
            if request.kind == Kind::RealmActorManager
                && request.purpose == Purpose::ArchiveRecovery => {}
        _ => {
            return Err(unavailable(
                "native challenge purpose does not match authenticated role",
            ));
        }
    }
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async |conn| {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn,&request.realm_actor_id.realm_id).await?;
        super::lock_namespace(conn,&subject).await?;
        let (backup,source,manager_ref,recovery_ref)=target(conn,reader,id,&request.effective_scope,arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_ISSUE_UNLOCK_CHALLENGE_V1).await?;
        if request.envelope_digest!=source.admission.envelope_digest{return Err(unavailable("native challenge complete packet digest differs").into());}
        let identity=arkret_canonical::canonical_sha256(&json!({"requester":requester(reader),"backup_id":id,"request_id":request.request_id})).map_err(unavailable)?;
        let full_request=arkret_canonical::canonical_sha256(request).map_err(unavailable)?;
        // Repeated request IDs cannot be rebound even after the old challenge
        // expires. A fresh challenge uses a fresh explicit request ID.
        let existing=sql_query("SELECT challenge,request_digest,fixed_reply FROM realm_actor_backup_unlocks WHERE realm_id=$1 AND actor_id=$2 AND request_identity=$3 FOR UPDATE")
            .bind::<Text,_>(request.realm_actor_id.realm_id.as_str()).bind::<Jsonb,_>(json!(subject)).bind::<Text,_>(&identity)
            .get_result::<ChallengeRow>(&mut *conn).await.optional()?;
        if let Some(existing)=existing {
            let issued:RealmActorBackupUnlockChallenge=serde_json::from_value(existing.challenge).map_err(unavailable)?;
            let original_request=RealmActorBackupIssueUnlockChallengeRequestBody{
                request_id:arkret_wire::Base64UrlString::new(issued.request_id.to_string()).map_err(unavailable)?,
                kind:issued.kind.clone(),purpose:issued.purpose.clone(),realm_actor_id:issued.realm_actor_id.clone(),
                effective_scope:issued.effective_scope.clone(),envelope_digest:issued.envelope_digest.clone(),
            };
            if arkret_canonical::canonical_sha256(&original_request).map_err(unavailable)?!=full_request {
                return Err(PersistenceError::Conflict("duplicate_conflict: native unlock request identity is immutable".into()).into());
            }
            if issued.expires_at<=chrono::Utc::now()||issued.manager_ref!=manager_ref||issued.recovery_ref!=recovery_ref {
                return Err(unavailable("native unlock challenge is no longer current").into());
            }
            return Ok(issued);
        }
        let now=arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let random=||arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(rand::random::<[u8;32]>())).map_err(unavailable);
        let (requesting_device_id,device_authorize_event_id,device_generation)=match reader {
            RealmActorBackupReader::Device(context)=>(Some(context.endpoint.authority.device_id.clone()),Some(context.endpoint.authority.authorization_ref.event_id.clone()),Some(context.endpoint.authority.current_device_generation_ref)),
            RealmActorBackupReader::Manager(_)=>(None,None,None),
        };
        let challenge=RealmActorBackupUnlockChallenge{
            challenge_id:random()?,challenge:random()?,nonce:random()?,operation:arkret_models_crypto::RealmActorBackupUnlockChallengeOperation::Value,
            backup_id:id.clone(),audience:arkret_wire::NonEmptyString::new(audience.to_owned()).map_err(unavailable)?,service_id:service_id.clone(),
            request_id:arkret_wire::NonEmptyString::new(request.request_id.to_string()).map_err(unavailable)?,issued_at:now,expires_at:now+chrono::Duration::seconds(300),
            series_id:backup.series_id,ciphertext_digest:backup.ciphertext_digest,kind:request.kind.clone(),purpose:request.purpose.clone(),
            realm_actor_id:request.realm_actor_id.clone(),effective_scope:request.effective_scope.clone(),manager_ref,recovery_ref,
            recipient_ref:source.admission.recipient_ref,requesting_device_id,device_authorize_event_id,device_generation,envelope_digest:request.envelope_digest.clone(),
        };
        sql_query("INSERT INTO realm_actor_backup_unlocks(realm_id,actor_id,challenge_id,request_identity,purpose,effective_scope,requester,challenge,backup_id,envelope_digest,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind::<Text,_>(request.realm_actor_id.realm_id.as_str()).bind::<Jsonb,_>(json!(subject)).bind::<Text,_>(challenge.challenge_id.as_str())
            .bind::<Text,_>(&identity).bind::<Text,_>(match request.purpose{Purpose::SeriesPredecessor=>"series_predecessor",Purpose::ArchiveRecovery=>"archive_recovery"})
            .bind::<Jsonb,_>(json!(request.effective_scope)).bind::<Jsonb,_>(requester(reader)).bind::<Jsonb,_>(json!(challenge))
            .bind::<diesel::sql_types::Uuid,_>(crate::ids::typed_uuid_part_expect_internal(id.as_str())).bind::<Text,_>(request.envelope_digest.as_str())
            .bind::<diesel::sql_types::Timestamptz,_>(challenge.expires_at).execute(&mut *conn).await?;
        if chrono::Utc::now()>=expiry(reader){return Err(unavailable("native challenge requester transport expired").into());}
        Ok(challenge)
    }).await.map_err(PgTransactionError::into_persistence)
}

fn proof_coordinates(
    proof: &KeyBackupUnlockProofBody,
) -> PersistenceResult<(&BackupId, &ScopeRef, &arkret_wire::Base64UrlString)> {
    match proof {
        KeyBackupUnlockProofBody::Device(proof) => {
            proof.validate().map_err(unavailable)?;
            Ok((
                &proof.backup_id,
                &proof.effective_scope,
                &proof.challenge_id,
            ))
        }
        KeyBackupUnlockProofBody::Manager(proof) => {
            proof.validate().map_err(unavailable)?;
            Ok((
                &proof.backup_id,
                &proof.effective_scope,
                &proof.challenge_id,
            ))
        }
        KeyBackupUnlockProofBody::Account(_) => {
            Err(unavailable("Account unlock cannot select native storage"))
        }
    }
}

fn verify_proof(
    reader: &RealmActorBackupReader,
    proof: &KeyBackupUnlockProofBody,
    challenge: &RealmActorBackupUnlockChallenge,
) -> PersistenceResult<()> {
    macro_rules! exact {
        ($p:expr) => {{
            let p = $p;
            if p.backup_id != challenge.backup_id
                || p.backup_kind != arkret_models_crypto::BackupKind::SecretStorage
                || p.series_id != challenge.series_id
                || p.ciphertext_digest != challenge.ciphertext_digest
                || p.challenge != challenge.challenge
                || p.issued_at != challenge.issued_at
                || p.expires_at != challenge.expires_at
                || p.audience != challenge.audience
                || p.service_id != challenge.service_id
                || p.challenge_id != challenge.challenge_id
                || p.nonce != challenge.nonce
                || p.realm_actor_id != challenge.realm_actor_id
                || p.effective_scope != challenge.effective_scope
                || p.manager_ref != challenge.manager_ref
                || p.recovery_ref != challenge.recovery_ref
                || p.recipient_ref != challenge.recipient_ref
                || p.envelope_digest != challenge.envelope_digest
                || p.kind != challenge.kind
                || p.purpose != challenge.purpose
            {
                return Err(unavailable(
                    "native unlock proof differs from its exact issued challenge",
                ));
            }
        }};
    }
    let (method, key, bytes, signature) = match (reader, proof) {
        (RealmActorBackupReader::Device(context), KeyBackupUnlockProofBody::Device(proof)) => {
            exact!(proof);
            let current = &context.endpoint.authority;
            if challenge.requesting_device_id.as_ref() != Some(&current.device_id)
                || challenge.device_authorize_event_id.as_ref()
                    != Some(&current.authorization_ref.event_id)
                || challenge.device_generation != Some(current.current_device_generation_ref)
                || proof.requesting_device_id != current.device_id
                || proof.device_authorize_event_id != current.authorization_ref.event_id
                || proof.device_generation != current.current_device_generation_ref
            {
                return Err(unavailable("native unlock requester Device differs"));
            }
            let fingerprint =
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(&current.public_key);
            (
                format!("did:key:{fingerprint}#{fingerprint}"),
                arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: current.public_key.to_vec(),
                },
                proof.signing_payload_bytes().map_err(unavailable)?,
                &proof.signature_proof,
            )
        }
        (RealmActorBackupReader::Manager(reader), KeyBackupUnlockProofBody::Manager(proof)) => {
            exact!(proof);
            let key = arkret_identity::public_key_material_from_document(
                &reader.service_did_document,
                &reader.verification_method,
            )
            .map_err(unavailable)?;
            (
                reader.verification_method.to_string(),
                key,
                proof.signing_payload_bytes().map_err(unavailable)?,
                &proof.signature_proof,
            )
        }
        _ => {
            return Err(unavailable(
                "native unlock proof and transport roles differ",
            ));
        }
    };
    if signature.verification_method.as_str() != method
        || !arkret_signatures::verify_detached_ed25519_signature(
            &key,
            &bytes,
            signature.signature.as_str(),
        )
    {
        return Err(PersistenceError::Conflict(
            "signature_invalid: native unlock proof Ed signature differs".into(),
        ));
    }
    Ok(())
}

async fn consume_in_connection(
    conn: &mut AsyncPgConnection,
    reader: &RealmActorBackupReader,
    proof: &KeyBackupUnlockProofBody,
) -> PersistenceResult<KeysBackupsUnlockResponseBody> {
    let (id, scope, challenge_id) = proof_coordinates(proof)?;
    let subject = actor(reader);
    let row=sql_query("SELECT challenge,request_digest,fixed_reply FROM realm_actor_backup_unlocks WHERE challenge_id=$1 AND actor_id=$2 AND requester=$3 FOR UPDATE")
        .bind::<Text,_>(challenge_id.as_str()).bind::<Jsonb,_>(json!(subject)).bind::<Jsonb,_>(requester(reader))
        .get_result::<ChallengeRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||unavailable("native unlock challenge is absent for exact requester"))?;
    let challenge: RealmActorBackupUnlockChallenge =
        serde_json::from_value(row.challenge).map_err(unavailable)?;
    if challenge.expires_at <= chrono::Utc::now()
        || challenge.issued_at > chrono::Utc::now()
        || expiry(reader) <= chrono::Utc::now()
    {
        return Err(unavailable("native unlock challenge or transport expired"));
    }
    verify_proof(reader, proof, &challenge)?;
    let (backup, source, manager_ref, recovery_ref) = target(
        conn,
        reader,
        id,
        scope,
        arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1,
    )
    .await?;
    if manager_ref != challenge.manager_ref
        || recovery_ref != challenge.recovery_ref
        || source.admission.recipient_ref != challenge.recipient_ref
        || source.admission.envelope_digest != challenge.envelope_digest
    {
        return Err(unavailable(
            "native unlock current requester or immutable target changed",
        ));
    }
    let digest = arkret_canonical::canonical_sha256(proof).map_err(unavailable)?;
    let response = match reader {
        RealmActorBackupReader::Device(_) => KeysBackupsUnlockResponseBody::Device(
            arkret_models_crypto::RealmActorBackupUnlockResponseBody {
                backup,
                admission: source.admission,
            },
        ),
        RealmActorBackupReader::Manager(_) => KeysBackupsUnlockResponseBody::Manager(
            arkret_models_integration::RealmActorArchiveUnlockResponseBody {
                backup,
                native_source: source,
            },
        ),
    };
    if let Some(previous) = row.request_digest {
        if previous != digest || row.fixed_reply != Some(json!(response)) {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: native unlock consumed with different exact proof".into(),
            ));
        }
        return Ok(response);
    }
    sql_query("UPDATE realm_actor_backup_unlocks SET request_digest=$2,fixed_reply=$3,consumed_at=$4 WHERE challenge_id=$1 AND consumed_at IS NULL")
        .bind::<Text,_>(challenge_id.as_str()).bind::<Text,_>(&digest).bind::<Jsonb,_>(json!(response))
        .bind::<diesel::sql_types::Timestamptz,_>(chrono::Utc::now()).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(response)
}

pub(crate) async fn consume_native_unlock(
    pool: &PgPool,
    reader: &RealmActorBackupReader,
    proof: &KeyBackupUnlockProofBody,
) -> PersistenceResult<(
    KeysBackupsUnlockResponseBody,
    Box<dyn coland_storage::AccountContentDeliveryGuard>,
)> {
    let subject = actor(reader);
    let realm = &subject
        .as_realm_actor_id()
        .ok_or_else(|| unavailable("native unlock actor absent"))?
        .realm_id;
    let mut conn = pg_conn(pool).await?;
    let response = conn
        .transaction::<_, PgTransactionError, _>(async |conn| {
            crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
            super::lock_namespace(conn, &subject).await?;
            consume_in_connection(conn, reader, proof)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)?;
    drop(conn);
    // Durable consumption precedes disclosure. Reacquire the exact head/current
    // manager cut and retain its locks until the response frame is handed off.
    let mut held = crate::account_content_delivery::DeliveryGuard::begin(pool).await?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(held.connection(), realm).await?;
    super::lock_namespace(held.connection(), &subject).await?;
    let (id, scope, _) = proof_coordinates(proof)?;
    let (_, source, manager, recovery) = target(
        held.connection(),
        reader,
        id,
        scope,
        arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1,
    )
    .await?;
    let references = match proof {
        KeyBackupUnlockProofBody::Device(p) => (
            &p.manager_ref,
            &p.recovery_ref,
            &p.recipient_ref,
            &p.envelope_digest,
        ),
        KeyBackupUnlockProofBody::Manager(p) => (
            &p.manager_ref,
            &p.recovery_ref,
            &p.recipient_ref,
            &p.envelope_digest,
        ),
        _ => return Err(unavailable("native unlock proof role absent")),
    };
    if references
        != (
            &manager,
            &recovery,
            &source.admission.recipient_ref,
            &source.admission.envelope_digest,
        )
    {
        return Err(unavailable(
            "native unlock delivery cut changed after consumption",
        ));
    }
    Ok((
        response,
        super::reading::NativeDelivery::new(
            held,
            reader.clone(),
            arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1,
            Some(id.clone()),
        ),
    ))
}
