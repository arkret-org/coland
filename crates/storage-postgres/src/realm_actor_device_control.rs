//! Subject-control-signed Realm Device authorization, committed at one private cut.
use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use arkret_models_integration::{
    RealmActorDeviceAuthorizationValue, RealmActorDeviceGenerationValue, RealmActorRecoveryValue,
};
use arkret_wire::{ActorId, CurrentRevision, EventKind, ScopeRef};
use coland_storage::{
    AcceptedDeviceAuthorizationOutcome, AuthorityCommitTransaction, AuthorityCommitWriteOutcome,
    PersistenceError,
};
use diesel::sql_types::{Binary, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::{Value, json};

use crate::PgTransactionError;

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
fn invalid(error: impl std::fmt::Display) -> PgTransactionError {
    PersistenceError::Conflict(format!("failed_precondition: {error}")).into()
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, PgTransactionError> {
    serde_json::from_value(value).map_err(invalid)
}
fn revision(source: &arkret_wire::CommittedEventRef) -> CurrentRevision {
    CurrentRevision {
        commit_id: source.commit_id.clone(),
        stream_position: source.stream_position,
    }
}

pub(crate) async fn admit(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    carrier: &coland_storage::AppletControlCarrier,
) -> Result<AcceptedDeviceAuthorizationOutcome, PgTransactionError> {
    use crate::realm_actor_control::{current_source, optional_current_source};
    let event = &transaction.event;
    let commit = &transaction.commit;
    event.validate_for_submit_structural().map_err(invalid)?;
    let value = RealmActorDeviceAuthorizationValue::from_event(event).map_err(invalid)?;
    let payload: DeviceAuthorizePayload = decode(json!(event.payload))?;
    let actor = &event.actor_id;
    if event.kind != EventKind::DeviceAuthorize
        || carrier.actor_id != *actor
        || carrier.governance_service_id != transaction.expected_authority.service_id
        || carrier.governance_generation != transaction.expected_authority.generation
        || event.scope_ref
            != (ScopeRef::RealmControl {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(invalid(
            "authorization requires its exact Realm control identity",
        ));
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let control = crate::realm_actor_control_source::current(conn, actor).await?;
    let document =
        crate::realm_actor_control_source::document(conn, actor, &control, commit.committed_at)
            .await?;
    let control_key = arkret_identity::public_key_material_from_document(
        &document,
        &control.value.control_method_kid,
    )
    .map_err(invalid)?;
    if carrier.control_ref != control.source
        || carrier.verification_method != control.value.control_method_kid
        || carrier.public_key != control_key.ed25519_bytes().map_err(invalid)?
    {
        return Err(invalid("HTTP control identity changed before acceptance"));
    }
    let known=sql_query("SELECT jsonb_build_object('event',e.envelope,'commit',c.commit_json) AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.state='committed'")
        .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).get_result::<JsonRow>(&mut *conn).await.optional()?;
    if let Some(known) = known {
        let original: arkret_wire::Event = decode(known.value["event"].clone())?;
        if original != *event {
            return Err(invalid("duplicate_conflict: authorization bytes differ"));
        }
        return Ok(AcceptedDeviceAuthorizationOutcome::Duplicate(decode(
            known.value["commit"].clone(),
        )?));
    }
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, &event.realm_id, actor)
            .await?;
    cut.require_open_lifecycle(event)?;
    let creation = crate::realm_actor_control::creation_source(conn, actor).await?;
    if creation.applet_id != value.applet_id {
        return Err(invalid("authorization names another Applet"));
    }
    for gate in ["owner", "governance"] {
        let (status, _) = current_source(
            conn,
            actor,
            json!({"kind":"realm_actor_status","actor_id":actor,"gate":gate}),
        )
        .await?;
        if status != "active" {
            return Err(invalid(
                "Device authorization requires both active status gates",
            ));
        }
    }
    let (recovery, _) = current_source(
        conn,
        actor,
        json!({"kind":"realm_actor_recovery","actor_id":actor}),
    )
    .await?;
    let recovery: RealmActorRecoveryValue = decode(recovery)?;
    let (generation, _) = current_source(
        conn,
        actor,
        json!({"kind":"realm_actor_device_generation","actor_id":actor}),
    )
    .await?;
    let generation: RealmActorDeviceGenerationValue = decode(generation)?;
    if recovery.pending.is_some()
        || value.authorized_generation_ref != generation.current_device_generation_ref
        || payload.expected_control_revision.as_ref() != Some(&revision(&control.source))
        || value.expires_at <= commit.committed_at
        || value.expires_at <= value.not_before
    {
        return Err(invalid(
            "Device generation, control CAS, recovery or validity changed",
        ));
    }
    let selector = json!({"kind":"realm_actor_device_authorization","actor_id":actor,"device_id":payload.device_id});
    let previous = optional_current_source(conn, actor, selector.clone()).await?;
    let expected = previous.as_ref().map(|(_, source)| revision(source));
    if payload.expected_device_revision.as_ref() != Some(&expected) {
        return Err(invalid("Device authorization CAS differs"));
    }
    if let Some((previous, _)) = previous {
        let previous: RealmActorDeviceAuthorizationValue = decode(previous)?;
        if previous.authorized_generation_ref != value.authorized_generation_ref
            || previous.device_public_key_did != value.device_public_key_did
        {
            return Err(invalid(
                "a fenced Device identity or key cannot be relabeled",
            ));
        }
    }
    let revokes=sql_query("SELECT c.commit_json AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.realm_id=$1 AND e.state='committed' AND e.kind='ak.device.revoke' AND e.envelope->'actor_id'=$2 AND e.envelope#>>'{payload,device_id}'=$3")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(actor)).bind::<Text,_>(payload.device_id.as_str())
        .load::<JsonRow>(&mut *conn).await?;
    for revoke in revokes {
        let commit: arkret_wire::RealmCommit = decode(revoke.value)?;
        let proposal = arkret_wire::CommittedEventRef {
            event_id: commit.event_ref,
            commit_id: commit.commit_id,
            stream_ref: commit.stream_ref,
            stream_position: commit.stream_position,
        };
        if !matches!(
            crate::realm_actor_device_revoke::read(conn, actor, &proposal).await?,
            arkret_models_integration::RealmActorRequestStatus::DeviceRevoke {
                state: arkret_models_integration::RealmActorDeviceRevocationState::Rejected,
                ..
            }
        ) {
            return Err(invalid("Device has a pending or accepted revocation"));
        }
    }
    arkret_signatures::verify_realm_device_authorize_possession(&payload, actor)
        .map_err(invalid)?;
    let device_key = arkret_canonical::decode_ed25519_multibase(
        value
            .device_public_key_did
            .strip_prefix("did:key:")
            .ok_or_else(|| invalid("Device fingerprint absent"))?,
    )
    .map_err(invalid)?;
    let native = crate::realm_actor_control_source::native_evidence(&control)?;
    let (_, log_entries, _) = native.webvh_material();
    let multikey = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&device_key);
    let commitment = arkret_signatures::webvh::webvh_next_key_hash_value(&multikey);
    if log_entries.iter().any(|entry| {
        ["updateKeys", "nextKeyHashes"].iter().any(|field| {
            entry
                .get("parameters")
                .and_then(|parameters| parameters.get(*field))
                .and_then(Value::as_array)
                .is_some_and(|values| {
                    values.iter().any(|value| {
                        value.as_str() == Some(multikey.as_str())
                            || value.as_str() == Some(commitment.as_str())
                    })
                })
        })
    }) {
        return Err(invalid("Device key overlaps native update authority"));
    }
    for method in document.verification_methods.keys() {
        let method = arkret_wire::DidUrl::new(method.clone()).map_err(invalid)?;
        if let Ok(key) = arkret_identity::public_key_material_from_document(&document, &method)
            && key.ed25519_bytes().map_err(invalid)? == device_key
        {
            return Err(invalid("Device key cannot be a DID operational method"));
        }
    }
    let registration = crate::managed_message_actor::registration(conn, event).await?;
    let service = sql_query(
        "SELECT did_document AS value FROM webvh_documents WHERE id=$1 AND expires_at>$2 FOR SHARE",
    )
    .bind::<Text, _>(
        registration
            .manifest
            .registration_epoch_evidence
            .did
            .as_str(),
    )
    .bind::<diesel::sql_types::Timestamptz, _>(commit.committed_at)
    .get_result::<JsonRow>(&mut *conn)
    .await?;
    let service: arkret_identity::DidDocument = decode(service.value)?;
    registration
        .manifest
        .registration_epoch_evidence
        .validate_against_did_document(&service)
        .map_err(invalid)?;
    let service_key = arkret_identity::public_key_material_from_document(
        &service,
        &registration.webhook_signature_policy.key_ref,
    )
    .map_err(invalid)?;
    if service_key.ed25519_bytes().map_err(invalid)? == device_key {
        return Err(invalid("Device key overlaps Service signing authority"));
    }
    crate::managed_message_actor::require_managed_identity_in_connection(
        conn,
        actor,
        &value.applet_id,
        &registration,
        commit.committed_at,
    )
    .await?;
    for entry in value.scopes.entries() {
        let scope = &entry.effective_scope;
        crate::applet_device_admission::installation_identity(
            conn,
            actor,
            &value.applet_id,
            &registration.service_id,
            scope,
            &service,
            commit.committed_at,
            true,
        )
        .await?;
        let policies =
            crate::policy_current_states::read_scoped_applet_management_policies_in_connection(
                conn,
                &event.realm_id,
                scope.circle_id(),
            )
            .await?;
        let mut resources =
            vec![arkret_models_collaboration::governance::operation_wire::PolicyResourceSelector {
            kind:arkret_models_collaboration::governance::operation_wire::PolicyResourceKind::Realm,
            realm_id:Some(event.realm_id.clone()),resource_ref:Some(event.realm_id.to_string()),
        }];
        if let Some(circle) = scope.circle_id() {
            resources.push(arkret_models_collaboration::governance::operation_wire::PolicyResourceSelector {
                kind:arkret_models_collaboration::governance::operation_wire::PolicyResourceKind::Object,
                realm_id:Some(event.realm_id.clone()),resource_ref:Some(circle.to_string()),
            });
        }
        let requester = ActorId::service(registration.service_id.clone());
        for action in &entry.actions {
            let decision=arkret_policy::applet_management::select_applet_management(Some(&policies),&arkret_policy::applet_management::AppletManagementContext {
                device_control:None,realm_id:&event.realm_id,requester_actor_id:&requester,applet_id:&value.applet_id,
                service_id: &registration.service_id,
            effective_scope:scope,managed_actor_id:Some(actor),
                operation:arkret_models_collaboration::governance::operation_wire::AppletPolicyOperation::Authorize,
                content_action:Some(*action),resources:Some(&resources),at:commit.committed_at,
            }).map_err(invalid)?;
            if matches!(
                decision.effect,
                arkret_wire::PolicyEffect::Deny | arkret_wire::PolicyEffect::Quarantine
            ) || !decision.review_requirements.is_empty()
            {
                return Err(invalid("current Applet policy denies Device authorization"));
            }
        }
    }
    let fact =
        crate::realm_actor_control_source::signer_fact(conn, event, commit.committed_at).await?;
    crate::agent_producer_signer_keys::validate_producer_fact_binding(event, commit, Some(&fact))?;
    crate::authority_commit::queue_event_in_connection(conn, event, commit.committed_at).await?;
    match crate::authority_commit::commit_verified_realm_device_in_connection(conn, transaction)
        .await?
    {
        AuthorityCommitWriteOutcome::Committed => {}
        _ => return Err(invalid("Realm Device control head moved")),
    }
    crate::agent_producer_signer_keys::retain_prepared_applet_in_connection(
        conn, event, commit, &fact,
    )
    .await?;
    crate::realm_actor_control::write_current(conn, actor, selector, json!(value), commit).await?;
    Ok(AcceptedDeviceAuthorizationOutcome::Committed(
        commit.clone(),
    ))
}
