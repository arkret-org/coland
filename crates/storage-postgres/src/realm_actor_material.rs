//! Private exact material at one locked Realm cut, with no member-history fallback.
use arkret_models_integration::*;
use arkret_wire::{ActorId, CommitStreamRef, CurrentSelector, RealmCommit, TypedCurrentRow};
use coland_storage::{PersistenceError, PersistenceResult, RealmActorMaterialCaller};
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
fn hidden() -> PersistenceError {
    PersistenceError::NotFound("Realm actor material not found".into())
}
fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("temporarily_unavailable: {detail}"))
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(unavailable)
}

pub(crate) async fn retain_outcome(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    subject: &ActorId,
    digest: &arkret_wire::Hash,
    outcome: &arkret_wire::AuthoritySubmitOutcome,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let value = json!(RealmActorOperationOutcome::Submitted(outcome.clone()));
    let written = sql_query("INSERT INTO realm_actor_operation_outcomes(realm_id,actor_id,request_digest,requester_actor_id,event_id,outcome,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(subject)).bind::<Text,_>(digest.as_str())
        .bind::<Jsonb,_>(json!(event.actor_id)).bind::<Text,_>(event.event_id.as_str()).bind::<Jsonb,_>(&value)
        .bind::<Timestamptz,_>(at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if written == 0 {
        let row = sql_query("SELECT jsonb_build_object('event_id',event_id,'outcome',outcome,'requester',requester_actor_id) AS value FROM realm_actor_operation_outcomes WHERE realm_id=$1 AND actor_id=$2 AND request_digest=$3 FOR SHARE")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(subject)).bind::<Text,_>(digest.as_str()).get_result::<Row>(&mut *conn).await.map_err(PersistenceError::database)?;
        if row.value["event_id"] != json!(event.event_id)
            || row.value["requester"] != json!(event.actor_id)
            || row.value["outcome"] != value
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: control outcome digest reused".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn read(
    conn: &mut AsyncPgConnection,
    request: &RealmActorMaterialRequest,
    caller: &RealmActorMaterialCaller,
    governor: &arkret_wire::DidCoreId,
    sign: coland_storage::RealmActorMaterialSigner<'_>,
) -> PersistenceResult<RealmActorMaterialOutcome> {
    request.validate().map_err(|_| hidden())?;
    if arkret_canonical::canonical_json_bytes(request)
        .map_err(unavailable)?
        .len()
        > 4_194_304
    {
        return Err(hidden());
    }
    let actor = request.actor_id();
    let subject = actor.as_realm_actor_id().ok_or_else(hidden)?;
    let authority = sql_query(
        "SELECT to_jsonb(a) AS value FROM realm_authorities a WHERE realm_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(subject.realm_id.as_str())
    .get_result::<Row>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(hidden)?;
    if authority.value["service_id"] != json!(governor) {
        return Err(unavailable("Realm is governed elsewhere"));
    }
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let outcome_row = if let RealmActorMaterialRequest::Outcome {
        target_request_digest,
        ..
    } = request
    {
        Some(sql_query("SELECT jsonb_build_object('requester',o.requester_actor_id,'outcome',COALESCE(r.outcome,o.outcome)) AS value FROM realm_actor_operation_outcomes o LEFT JOIN realm_actor_recovery_intents r ON r.realm_id=o.realm_id AND r.actor_id=o.actor_id AND r.begin_event_id=o.event_id WHERE o.realm_id=$1 AND o.actor_id=$2 AND o.request_digest=$3 FOR SHARE OF o")
            .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(actor)).bind::<Text,_>(target_request_digest.as_str())
            .get_result::<Row>(&mut *conn).await.optional().map_err(PersistenceError::database)?)
    } else {
        None
    };
    let (requester, credential_expiry) = match caller {
        RealmActorMaterialCaller::Account {
            account_id,
            expires_at,
        } => {
            let requester = ActorId::account(account_id.clone());
            let permitted_until = require_account_audit(conn, actor, &requester, at).await?;
            (requester, std::cmp::min(*expires_at, permitted_until))
        }
        RealmActorMaterialCaller::Control {
            authority: expected,
            expires_at,
        } => {
            if &expected.actor_id != actor {
                return Err(hidden());
            }
            let actual =
                crate::realm_actor_control_transport::current_carrier(conn, actor, governor, at)
                    .await?;
            if &actual != expected {
                return Err(hidden());
            }
            (actor.clone(), *expires_at)
        }
        RealmActorMaterialCaller::Service {
            service_id,
            verification_method,
            public_key,
            expires_at,
        } => {
            let did = arkret_identity::verification_method_did(verification_method.as_str())
                .map_err(|_| hidden())?;
            if arkret_wire::project_did_to_core_id(&did).map_err(|_| hidden())? != *service_id {
                return Err(hidden());
            }
            let row = sql_query("SELECT did_document AS value FROM webvh_documents WHERE id=$1 AND expires_at>$2 FOR SHARE")
                .bind::<Text,_>(did.as_str()).bind::<Timestamptz,_>(at).get_result::<Row>(&mut *conn).await.map_err(PersistenceError::database)?;
            let document: arkret_identity::DidDocument = decode(row.value)?;
            arkret_identity::validate_verification_method_relationship(
                &document,
                verification_method,
                &did,
                arkret_identity::DidVerificationRelationship::AssertionMethod,
            )
            .map_err(|_| hidden())?;
            let key =
                arkret_identity::public_key_material_from_document(&document, verification_method)
                    .map_err(|_| hidden())?;
            if &key.ed25519_bytes().map_err(|_| hidden())? != public_key {
                return Err(hidden());
            }
            let requester = ActorId::service(service_id.clone());
            let own_ledger = outcome_row
                .as_ref()
                .and_then(Option::as_ref)
                .is_some_and(|row| row.value["requester"] == json!(requester));
            if !own_ledger {
                let (manager, _) = crate::realm_actor_control::current_source(
                    conn,
                    actor,
                    json!({"kind":"realm_actor_manager","actor_id":actor}),
                )
                .await
                .map_err(|_| hidden())?;
                if manager["service_id"] != json!(service_id) {
                    return Err(hidden());
                }
            }
            (requester, *expires_at)
        }
        RealmActorMaterialCaller::Device { guard, expires_at } => {
            let RealmActorMaterialRequest::Event { target, .. } = request else {
                return Err(hidden());
            };
            if &guard.authority.actor_id != actor || target != &guard.authority.authorization_ref {
                return Err(hidden());
            }
            let current = crate::realm_actor_device_authority::current_in_connection(
                conn,
                actor,
                &guard.authority.device_id,
                at,
            )
            .await
            .map_err(crate::PgTransactionError::into_persistence)?
            .ok_or_else(hidden)?;
            if current != guard.authority || &current.governance_service_id != governor {
                return Err(hidden());
            }
            crate::applet_device_admission::installation_for_keypackage_publication(
                conn,
                &current,
                &guard.effective_scope,
                &guard.service_did_document,
                at,
                false,
            )
            .await?;
            (
                actor.clone(),
                std::cmp::min(*expires_at, current.expires_at),
            )
        }
    };
    let expires_at = std::cmp::min(at + chrono::Duration::seconds(60), credential_expiry);
    if expires_at <= at {
        return Err(hidden());
    }
    let stream = CommitStreamRef::RealmControl {
        realm_id: subject.realm_id.clone(),
    };
    let head = sql_query("SELECT commit_json AS value FROM realm_commits WHERE realm_id=$1 AND stream_ref=$2 ORDER BY stream_position DESC LIMIT 1")
        .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(stream)).get_result::<Row>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let head = head
        .map(|row| decode::<RealmCommit>(row.value))
        .transpose()?
        .map(|commit| arkret_wire::CommitStreamHead {
            stream_ref: commit.stream_ref,
            stream_position: commit.stream_position,
            commit_id: commit.commit_id,
        });
    let (purpose, result) = match request {
        RealmActorMaterialRequest::Current { selectors, .. } => {
            if head.is_none() {
                return Err(unavailable("private control head unavailable"));
            }
            let mut entries = Vec::new();
            for selector in selectors {
                let current = crate::realm_actor_control::optional_current_source(
                    conn,
                    actor,
                    json!(selector),
                )
                .await
                .map_err(|_| unavailable("private current source unavailable"))?;
                if let Some((value, source)) = current {
                    let (original, _) = crate::realm_actor_control_source::original(conn, &source)
                        .await
                        .map_err(|_| unavailable("private current original unavailable"))?;
                    validate_realm_actor_current_writer(selector, &original).map_err(|_| {
                        unavailable("private current writer does not produce this selector")
                    })?;
                    entries.push(RealmActorMaterialCurrentEntry::Present {
                        row: TypedCurrentRow::Value {
                            selector: selector.clone(),
                            source_stream_ref: source.stream_ref.clone(),
                            revision: arkret_wire::CurrentRevision {
                                commit_id: source.commit_id.clone(),
                                stream_position: source.stream_position,
                            },
                            value,
                        },
                        source_ref: source,
                    });
                } else {
                    let (kind, device) = match selector {
                        CurrentSelector::RealmActorDeviceAuthorization { device_id, .. } => {
                            ("ak.device.authorize", Some(device_id.as_str()))
                        }
                        CurrentSelector::RealmActorDeviceRevocationProposals {
                            device_id, ..
                        } => ("ak.device.revoke", Some(device_id.as_str())),
                        CurrentSelector::RealmActorProfile { .. } => ("ak.profile.create", None),
                        _ => return Err(unavailable("mandatory private current is absent")),
                    };
                    let exists = sql_query("SELECT to_jsonb(EXISTS(SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.realm_id=$1 AND c.stream_ref=$2 AND e.state='committed' AND e.kind=$3 AND e.envelope->'actor_id'=$4 AND ($5::text IS NULL OR e.envelope#>>'{payload,device_id}'=$5))) AS value")
                        .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(stream)).bind::<Text,_>(kind).bind::<Jsonb,_>(json!(actor))
                        .bind::<diesel::sql_types::Nullable<Text>,_>(device).get_result::<Row>(&mut *conn).await.map_err(PersistenceError::database)?;
                    if exists.value != json!(false) {
                        return Err(unavailable("written private selector lost its current"));
                    }
                    entries.push(RealmActorMaterialCurrentEntry::NeverWritten {
                        selector: selector.clone(),
                    });
                }
            }
            (
                RealmActorMaterialPurpose::Current,
                RealmActorMaterialResult::Current { entries },
            )
        }
        RealmActorMaterialRequest::Event { target, .. } => {
            let (event, commit) = crate::realm_actor_control_source::original(conn, target).await?;
            let target_actor = if event.kind == arkret_wire::EventKind::RealmActorCreate {
                event.payload.get("actor_id")
            } else {
                event.payload.get("target_actor_id")
            };
            if target_actor.map_or(event.actor_id != *actor, |value| value != &json!(actor)) {
                return Err(hidden());
            }
            let producer_signer_fact =
                crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
                    conn, &event, &commit,
                )
                .await?
                .ok_or_else(|| unavailable("private producer original absent"))?;
            (
                RealmActorMaterialPurpose::Event,
                RealmActorMaterialResult::Event {
                    event,
                    commit,
                    producer_signer_fact,
                },
            )
        }
        RealmActorMaterialRequest::Outcome {
            target_request_digest,
            ..
        } => {
            let mut outcome = match outcome_row.flatten() {
                Some(row) => decode(row.value["outcome"].clone())?,
                None => RealmActorOperationOutcome::Status {
                    status: RealmActorOperationStatus::Unknown,
                },
            };
            if let RealmActorOperationOutcome::Submitted(
                arkret_wire::AuthoritySubmitOutcome::Accepted { commit, .. },
            ) = &outcome
            {
                let proposal = arkret_wire::CommittedEventRef {
                    event_id: commit.event_ref.clone(),
                    commit_id: commit.commit_id.clone(),
                    stream_ref: commit.stream_ref.clone(),
                    stream_position: commit.stream_position,
                };
                let (event, _) =
                    crate::realm_actor_control_source::original(conn, &proposal).await?;
                if event.kind == arkret_wire::EventKind::DeviceRevoke {
                    outcome =
                        crate::realm_actor_device_revoke::read(conn, actor, &proposal).await?;
                }
            }
            (
                RealmActorMaterialPurpose::Outcome,
                RealmActorMaterialResult::Outcome {
                    target_request_digest: target_request_digest.clone(),
                    outcome,
                },
            )
        }
    };
    let unsigned = RealmActorMaterialUnsigned {
        realm_id: subject.realm_id.clone(),
        actor_id: actor.clone(),
        purpose,
        request_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(request).map_err(unavailable)?,
        )
        .map_err(unavailable)?,
        request_nonce: request.request_nonce().into(),
        requester_actor_id: requester.clone(),
        governance_generation: decode(authority.value["generation"].clone())?,
        authority_ref: decode(authority.value["authority_ref"].clone())?,
        control_stream_head: head,
        issued_at: at,
        expires_at,
        result,
    };
    let signed = sign(&unsigned)?;
    signed
        .validate_for_request(request, &requester, at)
        .map_err(unavailable)?;
    if arkret_canonical::unsigned_value(&signed, &["signature"]).map_err(unavailable)?
        != json!(unsigned)
    {
        return Err(unavailable("material signer changed the selected cut"));
    }
    Ok(signed)
}

pub(crate) async fn require_account_audit(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    requester: &ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<chrono::DateTime<chrono::Utc>> {
    let subject = actor.as_realm_actor_id().ok_or_else(hidden)?;
    if requester.as_account_id().is_none() {
        return Err(hidden());
    }
    let creation = sql_query("SELECT to_jsonb(c) AS value FROM realm_actor_creations c WHERE realm_id=$1 AND actor_id=$2")
        .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(actor))
        .get_result::<Row>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if creation.is_none() {
        return Err(hidden());
    }
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &subject.realm_id,
        requester,
    )
    .await?;
    cut.require_open_content_read().map_err(|_| hidden())?;
    let target =
        arkret_wire::WireResourceSelector::realm_actor(actor.clone()).map_err(|_| hidden())?;
    let facts = coland_storage::OperationFacts::default();
    let evaluation = cut.evaluate(
        &[arkret_wire::CapabilityActionId::REALM_ACTOR_AUDIT],
        &target,
        &facts,
        at,
    );
    if evaluation.unreserved().is_empty() {
        return Err(hidden());
    }
    if crate::policy_action_admission::current_operation_quorum(
        conn,
        &subject.realm_id,
        arkret_wire::CapabilityActionId::RealmActorAudit,
        &target,
        &facts,
        at,
    )
    .await?
    .is_some()
    {
        return Err(hidden());
    }
    Ok(cut.audit_material_expiry(&target, at))
}
