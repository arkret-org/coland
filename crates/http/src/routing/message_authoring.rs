//! Accepted ordinary-message MLS send gates.
use arkret_models_crypto::EncryptedEnvelope;
use arkret_wire::{Event, ScopeRef};
/// Why the current MLS send gate refuses one application body; the gate is
/// shared by self Event submit and the accepting
/// transaction, so every surface answers the same state with the same
/// registered identity (encryption-and-audit §2.5.2, decision 0100).
pub(crate) use coland_storage::MlsSendGateRefusal;

use crate::state::AppState;

/// Failure of the current MLS send gate.
#[derive(Debug)]
pub(crate) enum MlsSendGateError {
    Refused(MlsSendGateRefusal),
    CurrentUnavailable,
}

/// Evaluate the current MLS send gate for one application body.
///
/// `envelopes` is `None` for a plaintext body and otherwise every encrypted
/// envelope the body carries (content, then optional metadata). The gate only
/// reads: it never writes or reserves anything, so the same state gives the
/// same answer. Precedence follows §2.5.2: an uncovered key-access checkpoint
/// wins over a stale frozen epoch.
pub(crate) async fn mls_send_gate(
    state: &AppState,
    scope: &ScopeRef,
    envelopes: Option<&[&EncryptedEnvelope]>,
) -> Result<(), MlsSendGateError> {
    let current = state
        .mls_groups()
        .current(scope)
        .await
        .map_err(|_| MlsSendGateError::CurrentUnavailable)?;
    coland_storage::decide_mls_send_gate(
        current.as_ref().map(|current| &current.value),
        scope,
        envelopes,
    )
    .map_err(MlsSendGateError::Refused)
}

/// Apply the current MLS send gate to one self-submitted `ak.message.create`.
///
/// Runs before the authority transaction is prepared, so every refusal leaves
/// no Commit, idempotency record or projection behind. The refusal travels as
/// a typed [`coland_storage::ConflictCode`] so the HTTP layer renders its
/// registered identity without reading diagnostic text.
pub(crate) async fn message_create_send_gate(
    state: &AppState,
    event: &Event,
) -> Result<(), coland_services::ServiceError> {
    use coland_services::ServiceError;
    use coland_storage::ConflictCode;
    let envelopes = coland_storage::message_create_envelopes(&event.payload)
        .map_err(ServiceError::SchemaViolation)?;
    let envelopes = envelopes
        .as_ref()
        .map(|envelopes| envelopes.iter().collect::<Vec<_>>());
    mls_send_gate(state, &event.scope_ref, envelopes.as_deref())
        .await
        .map_err(|error| match error {
            MlsSendGateError::CurrentUnavailable => ServiceError::Conflict(format!(
                "{}: current MLS group is temporarily unavailable",
                ConflictCode::TemporarilyUnavailable
            )),
            MlsSendGateError::Refused(refusal) => {
                ServiceError::Conflict(format!("{}: {}", refusal.conflict_code(), refusal.detail()))
            }
        })
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_models_collaboration::events_payloads::message::ContentBlock;
    use arkret_models_crypto::{EncryptedEnvelope, EncryptedEnvelopeEncryptionContext};
    use arkret_wire::{ActorId, DidCoreId, EventId, RealmId};

    use super::*;

    const REALM: &str = "ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT";
    const LEADER: &str = "ak:did_core:web:alice.example";
    const STRAND: &str = "ak:strand:Ab1XwDyGoarexWM5f2N9k9zOpOIkgMjf0Ky-ngz87YjD";

    fn test_state() -> AppState {
        AppState::new(
            crate::config::AppConfig {
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            coland_storage_postgres::Db { pool: None },
        )
    }

    fn realm_scope(realm: &str) -> ScopeRef {
        ScopeRef::Realm {
            realm_id: RealmId::new(realm).unwrap(),
        }
    }

    fn event_ref(seed: u8) -> EventId {
        EventId::from_digest(DigestSuite::Sha256, [seed; 32])
    }

    fn envelope(context: EncryptedEnvelopeEncryptionContext) -> EncryptedEnvelope {
        EncryptedEnvelope {
            version: "1.0".to_owned(),
            content_type: "application/vnd.arkret.message+json".to_owned(),
            encryption_context: context,
            ciphertext: "Y2lwaGVydGV4dA".to_owned(),
        }
    }

    fn standard(epoch: u64, group_state_ref: EventId) -> EncryptedEnvelope {
        envelope(EncryptedEnvelopeEncryptionContext::standard(
            epoch,
            group_state_ref,
        ))
    }

    fn blob(seed: u8) -> arkret_wire::BlobRef {
        arkret_wire::BlobRef::new(format!("ak:blob:sha256:{}", hex::encode([seed; 32]))).unwrap()
    }

    /// Install the scope's accepted `mls_group` current directly.
    async fn seed_group(state: &AppState, scope: &ScopeRef, value: arkret_wire::MlsGroupCurrent) {
        state
            .mls_groups()
            .seed_test_current(&coland_storage::MlsGroupCurrentRecord {
                realm_id: scope.realm_id().clone(),
                value,
                current_commit_id: arkret_wire::RealmCommitId::from_digest([7; 32]),
                current_stream_position: 7,
                public_state: vec![1],
            })
            .await
            .unwrap();
    }

    async fn current_group(state: &AppState, scope: &ScopeRef) -> arkret_wire::MlsGroupCurrent {
        state
            .mls_groups()
            .current(scope)
            .await
            .unwrap()
            .expect("accepted MLS group")
            .value
    }

    /// The scope's accepted `ak.mls.genesis`.
    async fn accept_genesis(state: &AppState, scope: &ScopeRef, genesis: &EventId) {
        seed_group(
            state,
            scope,
            arkret_wire::MlsGroupCurrent {
                effective_scope: scope.clone(),
                genesis_event_ref: genesis.clone(),
                cipher_suite: arkret_wire::NonEmptyString::new(
                    "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                )
                .unwrap(),
                current_mls_commit_event_ref: genesis.clone(),
                epoch: 0,
                current_key_access_revision: 0,
                covered_key_access_revision: 0,
                public_tree_ref: blob(0x33),
            },
        )
        .await;
    }

    /// A winning epoch 0 -> 1 Commit that covers no newer key-access revision.
    async fn accept_commit(
        state: &AppState,
        scope: &ScopeRef,
        genesis: &EventId,
        commit: &EventId,
    ) {
        let current = current_group(state, scope).await;
        assert_eq!(&current.genesis_event_ref, genesis);
        seed_group(
            state,
            scope,
            arkret_wire::MlsGroupCurrent {
                current_mls_commit_event_ref: commit.clone(),
                epoch: current.epoch + 1,
                ..current
            },
        )
        .await;
    }

    /// A membership change the scope's winning Commit has not covered yet.
    async fn advance_key_access(state: &AppState, scope: &ScopeRef) {
        let current = current_group(state, scope).await;
        seed_group(
            state,
            scope,
            arkret_wire::MlsGroupCurrent {
                current_key_access_revision: current.current_key_access_revision + 1,
                ..current
            },
        )
        .await;
    }

    fn message_create_event(scope: &ScopeRef, payload: serde_json::Value) -> Event {
        let serde_json::Value::Object(payload) = payload else {
            unreachable!("message payload is an object")
        };
        Event {
            event_id: event_ref(0x42),
            kind: arkret_wire::EventKind::MessageCreate,
            realm_id: scope.realm_id().clone(),
            scope_ref: scope.clone(),
            actor_id: ActorId::service(DidCoreId::new(LEADER).unwrap()),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: chrono::Utc::now(),
            semantic_refs: Vec::new(),
            payload: payload.into_iter().collect(),
            producer_proof: None,
        }
    }

    fn encrypted_message(
        scope: &ScopeRef,
        content: EncryptedEnvelope,
        metadata: Option<EncryptedEnvelope>,
    ) -> Event {
        let mut payload = serde_json::json!({
            "strand_id": STRAND,
            "track_name": "discussion",
            "encrypted_content": content,
        });
        if let Some(metadata) = metadata {
            payload["encrypted_metadata"] = serde_json::to_value(metadata).unwrap();
        }
        message_create_event(scope, payload)
    }

    async fn accepted_mls_head(state: &AppState, scope: &ScopeRef) -> (u64, EventId) {
        let current = current_group(state, scope).await;
        (current.epoch, current.current_mls_commit_event_ref)
    }

    fn submit_refusal(
        result: Result<(), coland_services::ServiceError>,
    ) -> coland_storage::ConflictCode {
        let error = result.expect_err("the submit gate must refuse");
        error
            .conflict_code()
            .unwrap_or_else(|| panic!("refusal has no typed conflict code: {error}"))
    }

    #[tokio::test]
    async fn message_submit_gate_refuses_plaintext_only_after_activation() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let plaintext = message_create_event(
            &scope,
            serde_json::json!({
                "strand_id": STRAND,
                "track_name": "discussion",
                "content": ContentBlock::text("hello"),
            }),
        );
        message_create_send_gate(&state, &plaintext).await.unwrap();
        accept_genesis(&state, &scope, &event_ref(1)).await;
        assert_eq!(
            submit_refusal(message_create_send_gate(&state, &plaintext).await),
            coland_storage::ConflictCode::MlsActivationRequired
        );
    }

    #[tokio::test]
    async fn message_submit_gate_without_accepted_mls_group_is_failed_precondition() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let event = encrypted_message(&scope, standard(0, event_ref(1)), None);
        for _ in 0..2 {
            assert_eq!(
                submit_refusal(message_create_send_gate(&state, &event).await),
                coland_storage::ConflictCode::FailedPrecondition
            );
        }
        assert!(state.mls_groups().current(&scope).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn message_submit_gate_metadata_without_content_is_schema_violation() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let event = message_create_event(
            &scope,
            serde_json::json!({
                "strand_id": STRAND,
                "track_name": "discussion",
                "content": ContentBlock::text("hello"),
                "encrypted_metadata": standard(0, event_ref(1)),
            }),
        );
        let error = message_create_send_gate(&state, &event).await.unwrap_err();
        assert!(
            matches!(error, coland_services::ServiceError::SchemaViolation(_)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn message_submit_gate_uncovered_checkpoint_precedes_stale_epoch() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let (genesis, commit) = (event_ref(1), event_ref(2));
        accept_genesis(&state, &scope, &genesis).await;
        advance_key_access(&state, &scope).await;
        let current = encrypted_message(&scope, standard(0, genesis.clone()), None);
        assert_eq!(
            submit_refusal(message_create_send_gate(&state, &current).await),
            coland_storage::ConflictCode::EpochUpdateRequired
        );
        accept_commit(&state, &scope, &genesis, &commit).await;
        let before = accepted_mls_head(&state, &scope).await;
        for _ in 0..2 {
            assert_eq!(
                submit_refusal(message_create_send_gate(&state, &current).await),
                coland_storage::ConflictCode::EpochUpdateRequired
            );
        }
        assert_eq!(
            accepted_mls_head(&state, &scope).await,
            before,
            "a refused send must not move accepted MLS state"
        );
    }

    #[tokio::test]
    async fn message_submit_gate_superseded_epoch_is_epoch_mismatch() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let (genesis, commit) = (event_ref(1), event_ref(2));
        accept_genesis(&state, &scope, &genesis).await;
        accept_commit(&state, &scope, &genesis, &commit).await;
        let before = accepted_mls_head(&state, &scope).await;
        for event in [
            encrypted_message(&scope, standard(0, genesis.clone()), None),
            encrypted_message(
                &scope,
                standard(1, commit.clone()),
                Some(standard(0, genesis.clone())),
            ),
            encrypted_message(&scope, standard(1, event_ref(3)), None),
        ] {
            for _ in 0..2 {
                assert_eq!(
                    submit_refusal(message_create_send_gate(&state, &event).await),
                    coland_storage::ConflictCode::EpochMismatch
                );
            }
        }
        assert_eq!(
            accepted_mls_head(&state, &scope).await,
            before,
            "a refused send must not move accepted MLS state"
        );
        let current = encrypted_message(
            &scope,
            standard(1, commit.clone()),
            Some(standard(1, commit)),
        );
        message_create_send_gate(&state, &current).await.unwrap();
    }
}
