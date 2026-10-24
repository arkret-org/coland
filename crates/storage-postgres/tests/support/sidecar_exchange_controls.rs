//! Real RFC application carriers through the governing PostgreSQL transaction.

use arkret_models_collaboration::agent_sidecar::AgentSidecarExchangeControlsValue;
use arkret_models_crypto::EncryptedEnvelope;
use arkret_wire::{
    ActorId, CommitStreamRef, CurrentSelector, CurrentState, EncryptedPayloadScheme, EventKind,
    ScopeRef, SemanticRef, SidecarId,
};
use coland_storage::{AuthorityCommitStore, MlsGroupCurrentStore};
use coland_storage_postgres::{PgAuthorityCommitStore, PgPool};

use super::{device_authorization_history, fixture_commit_step, ordinary_realm, pcr_genesis};

pub(super) async fn assert_current(
    pool: &PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
    sidecar: &SidecarId,
    head: &coland_storage::AuthorityCommitTransaction,
    group: &mut arkret_mls::ArkretMlsGroup,
    agent: &arkret_wire::DidCoreId,
) {
    let controller = &principal.history.account;
    let realm = &head.event.realm_id;
    let scope = ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let stream = CommitStreamRef::from_scope(&scope, None).unwrap();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let before = store
        .realm_state_snapshot_material_for_account(realm, controller)
        .await
        .unwrap()
        .unwrap();
    let context = before
        .current_state_entries
        .iter()
        .find_map(|row| match row {
            CurrentState::Value {
                selector:
                    CurrentSelector::SidecarContext {
                        sidecar_id,
                        source_context_ref,
                    },
                ..
            } if sidecar_id == sidecar => Some(source_context_ref.clone()),
            _ => None,
        })
        .unwrap();
    let arkret_wire::SidecarContextRef::Strand { strand_id } = &context else {
        panic!("fixture needs a Strand source")
    };
    let current = coland_storage_postgres::PgMlsGroupCurrentStore { pool: pool.clone() }
        .current(&scope)
        .await
        .unwrap()
        .unwrap()
        .value;
    let mut encrypt =
        |kind: EventKind, content_type: &str, plaintext: &[u8]| -> EncryptedEnvelope {
            let header = arkret_models_crypto::EventContentPreEncryptionHeader::reconstruct(
                "1.0",
                content_type,
                EncryptedPayloadScheme::MlsRfc9420,
                scope.clone(),
                kind.as_str(),
                group.epoch(),
                current.current_mls_commit_event_ref.clone(),
                group.local_content_sender_domain().unwrap(),
                arkret_models_crypto::EventContentRoutingContext::None,
            )
            .unwrap();
            group
                .encrypt_payload(header, plaintext)
                .unwrap()
                .to_envelope()
                .unwrap()
        };
    let content = encrypt(
        EventKind::MessageCreate,
        arkret_models_collaboration::events_payloads::message::MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE,
        b"{\"kind\":\"ak.content.text\",\"body\":\"private request\",\"format\":\"plain\"}",
    );
    let metadata = serde_json::json!({"sidecar_exchange_binding":{
        "schema":"ak.schema.agent_sidecar_event_exchange_binding.v1","exchange_id":"pg-sidecar-current-000001","role":"request",
        "request_context":{"source_track_ref":{"realm_id":realm,"strand_id":strand_id,"track_name":"discussion"},
            "source_hlc":"0198ff000000-0001-0a0b0c0d","client_order_key":"pg-request-1","addressed_agent_ids":[agent]}
    }});
    let metadata = encrypt(
        EventKind::MessageCreate,
        arkret_models_collaboration::events_payloads::message::MESSAGE_METADATA_MLS_CONTENT_TYPE,
        &serde_json::to_vec(&metadata).unwrap(),
    );
    let make = async |previous: &coland_storage::AuthorityCommitTransaction,
                      kind,
                      payload,
                      after: Vec<SemanticRef>| {
        let mut event = ordinary_realm::event_for_actor(
            kind,
            scope.clone(),
            ActorId::account(controller.clone()),
            payload,
            head.commit.committed_at,
        );
        event.semantic_refs = after;
        let event = device_authorization_history::sign_event(
            event,
            principal.history.device_verification_method.clone(),
            principal.history.founding_device_signing_seed,
        );
        let mut request =
            ordinary_realm::request_for_event(previous, event, head.commit.committed_at);
        request.authority_commit.commit.stream_ref = stream.clone();
        request.authority_commit.commit.stream_position = previous.commit.stream_position + 1;
        request.authority_commit.commit.previous_commit_ref =
            Some(previous.commit.commit_id.clone());
        super::source_candidate(pool, &mut request).await;
        request
    };
    let request = make(
        head,
        EventKind::MessageCreate,
        serde_json::json!({"strand_id":strand_id,"track_name":"discussion","encrypted_content":content,"encrypted_metadata":metadata}),
        Vec::new(),
    ).await;
    for plaintext in [true, false] {
        let mut refused_payload =
            serde_json::to_value(&request.authority_commit.event.payload).unwrap();
        if plaintext {
            refused_payload
                .as_object_mut()
                .unwrap()
                .remove("encrypted_content");
            refused_payload["content"] =
                serde_json::json!({"kind":"ak.content.text","body":"refused","format":"plain"});
        } else {
            refused_payload["strand_id"] = serde_json::to_value(
                arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [118; 32],
                )),
            )
            .unwrap();
        }
        assert!(
            fixture_commit_step(
                pool,
                make(head, EventKind::MessageCreate, refused_payload, Vec::new()).await
            )
            .await
            .is_err()
        );
        let after = store
            .realm_state_snapshot_material_for_account(realm, controller)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.visible_stream_heads, before.visible_stream_heads);
        assert_eq!(after.current_state_entries, before.current_state_entries);
    }
    fixture_commit_step(pool, request.clone()).await.unwrap();
    let messages = store
        .realm_state_snapshot_material_for_account(realm, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(messages.current_state_entries.iter().any(|row| matches!(row,
        CurrentState::Value { selector: CurrentSelector::MessageRevision { message_id }, source_stream_ref, revision, .. }
        if message_id == &arkret_wire::MessageId::from_event_id(&request.authority_commit.event.event_id)
            && source_stream_ref == &stream && revision.commit_id == request.authority_commit.commit.commit_id
    )));
    let control = arkret_models_collaboration::agent_sidecar::AgentSidecarExchangeControl {
        schema: arkret_wire::SchemaId::AGENT_SIDECAR_EXCHANGE_CONTROL_V1.to_owned(),
        exchange_id: "pg-sidecar-current-000001".to_owned(),
        request_event_id: request.authority_commit.event.event_id.clone(),
        basis_event_ids: vec![request.authority_commit.event.event_id.clone()],
        action: arkret_models_collaboration::agent_sidecar::AgentSidecarExchangeAction::Close,
        response_event_ids: Some(Vec::new()),
        failure_reason_code: None,
        expected_coordinator_agent_id: None,
        coordinator_agent_id: None,
    };
    control.validate_shape().unwrap();
    let envelope = encrypt(
        EventKind::AgentSidecarExchangeControl,
        "application/vnd.arkret.agent-sidecar-exchange-control+json",
        &serde_json::to_vec(&control).unwrap(),
    );
    let payload =
        arkret_models_collaboration::events_payloads::sidecar::AgentSidecarExchangeControlPayload {
            sidecar_id: sidecar.clone(),
            source_context_ref: context.clone(),
            encrypted_payload: envelope,
        };
    let accepted = make(
        &request.authority_commit,
        EventKind::AgentSidecarExchangeControl,
        serde_json::to_value(&payload).unwrap(),
        vec![SemanticRef::new(
            control.request_event_id.to_string(),
            "after",
        )],
    )
    .await;
    fixture_commit_step(pool, accepted.clone()).await.unwrap();
    fixture_commit_step(pool, accepted.clone()).await.unwrap();
    let material = store
        .realm_state_snapshot_material_for_account(realm, controller)
        .await
        .unwrap()
        .unwrap();
    let row = material.current_state_entries.iter().find(|row| matches!(row, CurrentState::Value {selector:CurrentSelector::AgentSidecarExchangeControls {sidecar_id,source_context_ref},..} if sidecar_id == sidecar && source_context_ref == &context)).unwrap();
    let CurrentState::Value {
        source_stream_ref,
        revision,
        value,
        ..
    } = row;
    assert_eq!(source_stream_ref, &stream);
    assert_eq!(
        revision.commit_id,
        accepted.authority_commit.commit.commit_id
    );
    assert_eq!(
        revision.stream_position,
        accepted.authority_commit.commit.stream_position
    );
    let set: AgentSidecarExchangeControlsValue = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(set.assertions().len(), 1);
    assert_eq!(
        set.assertions()[0].tag_id.event_id(),
        &accepted.authority_commit.event.event_id
    );
    assert_eq!(set.assertions()[0].value, payload);
    assert!(
        !serde_json::to_string(row)
            .unwrap()
            .contains(&control.exchange_id)
    );
    for wrong_epoch in [false, true] {
        let mut wrong = serde_json::to_value(&payload).unwrap();
        if wrong_epoch {
            wrong["encrypted_payload"]["encryption_context"]["epoch"] =
                serde_json::json!(current.epoch + 1);
        } else {
            wrong["source_context_ref"]["strand_id"] = serde_json::to_value(
                arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [119; 32],
                )),
            )
            .unwrap();
        }
        let refused = make(
            &accepted.authority_commit,
            EventKind::AgentSidecarExchangeControl,
            wrong,
            vec![SemanticRef::new(
                control.request_event_id.to_string(),
                "after",
            )],
        )
        .await;
        assert!(fixture_commit_step(pool, refused).await.is_err());
        let after = store
            .realm_state_snapshot_material_for_account(realm, controller)
            .await
            .unwrap()
            .unwrap();
        assert!(
            after.current_state_entries.contains(row),
            "a refused control cannot rewrite the held current set"
        );
        assert_eq!(
            after.visible_stream_heads, material.visible_stream_heads,
            "a refused control cannot advance an accepted native head"
        );
    }
}
