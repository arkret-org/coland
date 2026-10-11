//! Read-only preparation of one caller-signed ordinary message.
use arkret_models_collaboration::message_authoring::{
    MessageAuthoringContent, MessagePrepareOutcome, MessagePrepareRequestBody,
};
use arkret_models_collaboration::prepared_event_draft::PreparedEventDraft;
use arkret_models_crypto::EncryptedEnvelope;
use arkret_wire::{ActorId, Base64UrlString, EncryptedPayloadScheme, Event, Hash, ScopeRef};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::with_path("messages/prepare").post(prepare)
}
fn invalid(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(SchemaViolation, error.to_string())
}

fn prepared_event_draft(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<PreparedEventDraft, AppError> {
    let digest_payload = event
        .digest_payload()
        .map_err(|error| AppError::internal(format!("message Event draft: {error}")))?;
    let unsigned_bytes = arkret_canonical::canonical_json_bytes(&digest_payload)
        .map_err(|error| AppError::internal(format!("message Event draft bytes: {error}")))?;
    Ok(PreparedEventDraft {
        unsigned_event_bytes: Base64UrlString::new(arkret_canonical::base64url_encode(
            &unsigned_bytes,
        ))
        .map_err(|error| AppError::internal(format!("message draft encode: {error}")))?,
        event_digest: Hash::new(
            event
                .event_digest_with_digest_suite(digest_suite)
                .map_err(|error| AppError::internal(format!("message Event digest: {error}")))?,
        )
        .map_err(|error| AppError::internal(format!("message Event digest invalid: {error}")))?,
    })
}

async fn device_active(
    state: &AppState,
    selector: &coland_storage::DeviceRevocationGateSelector,
) -> Result<(), AppError> {
    state
        .persistence()
        .device_revocation_gate_status(selector)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ensure_allowed()
        .map_err(|e| AppError::capability_denied(e.to_string()))
}

/// Resolve a target only after proving current read visibility for the exact
/// authenticated actor. Keep every target denial opaque before MLS or retry
/// state can disclose the Strand's scope or existence. Visibility is the
/// durable current held here -- governed or a verified member-Station
/// replica -- so an author whose Station only replicates the Realm prepares
/// against the same accepted state it forwards to the governing Station.
async fn visible_target_scope(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    strand_id: &arkret_wire::StrandId,
    actor: &ActorId,
) -> Result<ScopeRef, AppError> {
    state
        .authority_commits()
        .visible_strand_scope_for_actor(realm_id, strand_id, actor)
        .await
        .map_err(|error| AppError::internal(format!("message target read: {error}")))?
        .ok_or_else(|| AppError::not_found("message target not found"))
}

/// Why the current MLS send gate refuses one application body; the gate is
/// shared by message prepare, self Event submit and the accepting
/// transaction, so every surface answers the same state with the same
/// registered identity (encryption-and-audit §2.5.2, decision 0100).
pub(crate) use coland_storage::MlsSendGateRefusal;

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

fn send_gate_problem(error: MlsSendGateError) -> AppError {
    match error {
        MlsSendGateError::CurrentUnavailable => {
            crate::app_error!(
                TemporarilyUnavailable,
                "current MLS group is temporarily unavailable"
            )
        }
        MlsSendGateError::Refused(MlsSendGateRefusal::ActivationRequired) => crate::app_error!(
            FailedPrecondition,
            "plaintext is not allowed after MLS activation",
        )
        .with_reason_code(arkret_wire::ReasonCode::MLS_ACTIVATION_REQUIRED),
        MlsSendGateError::Refused(MlsSendGateRefusal::NotActivated) => {
            crate::app_error!(FailedPrecondition, "scope has no accepted MLS group",)
        }
        MlsSendGateError::Refused(MlsSendGateRefusal::EpochUpdateRequired) => crate::app_error!(
            FailedPrecondition,
            "the scope key-access revision is not yet covered by an accepted MLS Commit",
        )
        .with_reason_code(arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED),
        MlsSendGateError::Refused(MlsSendGateRefusal::EpochMismatch) => crate::app_error!(
            EpochMismatch,
            "frozen message encryption context is no longer applicable",
        ),
    }
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

/// Check a message intent against the target scope's accepted MLS state.
///
/// Each branch keeps its registered identity so a client can choose between
/// retrying as-is, waiting for a covering Commit and re-encrypting:
/// plaintext into an activated scope is `failed_precondition` /
/// `mls_activation_required`; a non-RFC 9420 frozen context is
/// `schema_violation`; a frozen scope other than the Strand's is
/// `failed_precondition` / `scope_ref_mismatch`; a sender domain other than the
/// authenticated device is `capability_denied`; absent accepted MLS state is
/// generic `failed_precondition` with no reason; a current MLS read fault is
/// `temporarily_unavailable`; an uncovered key-access revision is
/// `failed_precondition` / `epoch_update_required`; and a frozen epoch or group
/// state the scope has moved past is `epoch_mismatch`.
async fn validate_encryption_context(
    state: &AppState,
    content: &MessageAuthoringContent,
    scope: &ScopeRef,
    device: &str,
) -> Result<(), AppError> {
    let MessageAuthoringContent::Mls {
        encrypted_content,
        encrypted_metadata,
        encryption_context: frozen,
    } = content
    else {
        return mls_send_gate(state, scope, None)
            .await
            .map_err(send_gate_problem);
    };
    if frozen.scheme != EncryptedPayloadScheme::MlsRfc9420 {
        return Err(invalid(
            "message encryption_context.scheme must be mls_rfc9420",
        ));
    }
    let envelopes: Vec<&EncryptedEnvelope> = std::iter::once(encrypted_content)
        .chain(encrypted_metadata)
        .collect();
    for envelope in &envelopes {
        envelope.validate().map_err(invalid)?;
        if envelope.encryption_context.routing_context().is_some() {
            return Err(invalid(
                "message envelopes carry only the standard RFC 9420 epoch and group_state_ref",
            ));
        }
    }
    if &frozen.effective_scope != scope {
        return Err(crate::app_error!(
            FailedPrecondition,
            "message encryption scope does not match the target Strand scope",
        )
        .with_reason_code(arkret_wire::ReasonCode::SCOPE_REF_MISMATCH));
    }
    if frozen.sender_domain != device {
        return Err(AppError::capability_denied(
            "message sender domain does not match the authenticated device",
        ));
    }
    mls_send_gate(state, scope, Some(&envelopes))
        .await
        .map_err(send_gate_problem)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.messages.command.prepare", tags("messages"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.messages.command.prepare.v1"))]
async fn prepare(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<MessagePrepareRequestBody>,
) -> JsonResult<MessagePrepareOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account = crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
        state, &session,
    )
    .await?;
    let body = body.into_inner();
    body.validate().map_err(invalid)?;
    if body.account_id != account || body.account_id.station_id.as_str() != state.service_id() {
        return Err(AppError::not_found("message preparation not found"));
    }
    let observed_at = crate::wire::now();
    let expires_at = body
        .created_at
        .checked_add_signed(chrono::Duration::seconds(300))
        .ok_or_else(|| {
            crate::app_error!(
                AuthoringRequestExpired,
                "message preparation timestamp overflows expiry",
            )
        })?;
    if body.created_at > observed_at || expires_at <= observed_at {
        return Err(crate::app_error!(
            AuthoringRequestExpired,
            "message preparation has expired or has a future creation time",
        ));
    }
    let request_digest = body.canonical_request_digest().map_err(invalid)?;
    let request_hash = request_digest.as_str().to_owned();
    let generation =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            account.principal_id.as_str(),
            session.require_human_device_id(),
        )
        .await
        .map_err(|e| AppError::capability_denied(e.to_string()))?;
    device_active(state, &generation).await?;
    let actor = ActorId::account(account);
    let scope = visible_target_scope(state, &body.realm_id, &body.intent.strand_id, &actor).await?;
    let operation_id = "ak.self.messages.command.prepare.v1";
    let key = format!(
        "{}:{}:{}",
        session.require_human_device_id(),
        generation.authorization_ref.event_id,
        body.request_id
    );
    if let Some(record) = state
        .jobs()
        .scoped_idempotency_record(&actor, operation_id, &key)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
    {
        if record.request_hash != request_hash {
            return Err(crate::app_error!(
                DuplicateConflict,
                "message request_id already has another intent",
            ));
        }
        if record.expires_at <= observed_at {
            return Err(crate::app_error!(
                AuthoringRequestExpired,
                "message preparation expired",
            ));
        }
        let result: MessagePrepareOutcome =
            serde_json::from_value(record.response_body).map_err(invalid)?;
        result.validate_against_request(&body).map_err(invalid)?;
        visible_target_scope(state, &body.realm_id, &body.intent.strand_id, &actor).await?;
        return json_ok(result);
    }
    validate_encryption_context(
        state,
        &body.intent.content,
        &scope,
        session.require_human_device_id(),
    )
    .await?;
    let digest_suite = state
        .projections()
        .realm_digest_suite(body.realm_id.as_str());
    let authored =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MessageCreate>::new(
            scope,
            actor.clone(),
            body.intent.payload(),
        )
        .and_then(|draft| draft.author_with_digest_suite(body.created_at, digest_suite))
        .map_err(invalid)?;
    let outcome = MessagePrepareOutcome {
        request_digest,
        draft: prepared_event_draft(authored.event(), digest_suite)?,
        observed_at,
        expires_at,
    };
    outcome.validate_against_request(&body).map_err(invalid)?;
    device_active(state, &generation).await?;
    state
        .jobs()
        .store_idempotency_record(coland_services::jobs::IdempotencyState {
            authenticated_actor: actor.clone(),
            operation_id: operation_id.to_owned(),
            idempotency_key: key.clone(),
            request_hash: request_hash.clone(),
            response_status: 200,
            response_body: serde_json::to_value(&outcome).map_err(invalid)?,
            created_at: observed_at,
            expires_at: outcome.expires_at,
        })
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let landed = state
        .jobs()
        .scoped_idempotency_record(&actor, operation_id, &key)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(AuthoringRequestExpired, "preparation record is unavailable",)
        })?;
    if landed.request_hash != request_hash {
        return Err(crate::app_error!(
            DuplicateConflict,
            "message request identity conflicts with concurrent request",
        ));
    }
    let result: MessagePrepareOutcome =
        serde_json::from_value(landed.response_body).map_err(invalid)?;
    result.validate_against_request(&body).map_err(invalid)?;
    device_active(state, &generation).await?;
    visible_target_scope(state, &body.realm_id, &body.intent.strand_id, &actor).await?;
    json_ok(result)
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_models_collaboration::events_payloads::message::ContentBlock;
    use arkret_models_collaboration::message_authoring::MessageEncryptionContext;
    use arkret_models_crypto::{
        EncryptedEnvelope, EncryptedEnvelopeEncryptionContext, EncryptedEnvelopeRoutingContext,
    };
    use arkret_wire::{DidCoreId, EventId, RealmId};

    use super::*;

    const REALM: &str = "ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT";
    const OTHER_REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000006";
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

    fn mls_content(
        content: EncryptedEnvelope,
        metadata: Option<EncryptedEnvelope>,
        effective_scope: ScopeRef,
        sender_domain: &str,
    ) -> MessageAuthoringContent {
        MessageAuthoringContent::Mls {
            encrypted_content: content,
            encrypted_metadata: metadata,
            encryption_context: MessageEncryptionContext {
                scheme: EncryptedPayloadScheme::MlsRfc9420,
                effective_scope,
                sender_domain: sender_domain.to_owned(),
            },
        }
    }

    fn plaintext() -> MessageAuthoringContent {
        MessageAuthoringContent::Plaintext {
            content: ContentBlock::text("hello"),
            metadata: None,
        }
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

    async fn problem(error: AppError) -> (StatusCode, serde_json::Value) {
        let mut res = Response::new();
        error
            .write(&mut Request::new(), &mut Depot::new(), &mut res)
            .await;
        let status = res.status_code.expect("problem status");
        let body = salvo::test::ResponseExt::take_json(&mut res)
            .await
            .expect("problem body");
        (status, body)
    }

    async fn assert_problem(
        result: Result<(), AppError>,
        status: StatusCode,
        code: &str,
        reason_code: Option<&str>,
    ) {
        let (actual_status, body) = problem(result.expect_err("the branch must reject")).await;
        assert_eq!(actual_status, status, "{body}");
        assert_eq!(body["status"], status.as_u16(), "{body}");
        assert_eq!(
            body["type"],
            format!("https://arkret.org/problems/{code}"),
            "{body}"
        );
        match reason_code {
            Some(reason_code) => assert_eq!(body["reason_code"], reason_code, "{body}"),
            None => assert!(body.get("reason_code").is_none(), "{body}"),
        }
    }

    #[tokio::test]
    async fn message_authoring_plaintext_is_prepared_before_mls_activation() {
        let state = test_state();
        let scope = realm_scope(REALM);
        validate_encryption_context(&state, &plaintext(), &scope, DEVICE)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn message_authoring_plaintext_after_activation_is_mls_activation_required() {
        let state = test_state();
        let scope = realm_scope(REALM);
        accept_genesis(&state, &scope, &event_ref(1)).await;
        assert_problem(
            validate_encryption_context(&state, &plaintext(), &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "failed_precondition",
            Some("mls_activation_required"),
        )
        .await;
    }

    #[test]
    fn message_authoring_non_rfc9420_scheme_is_rejected_before_preparation() {
        let content = mls_content(standard(0, event_ref(1)), None, realm_scope(REALM), DEVICE);
        let mut value = serde_json::to_value(content).unwrap();
        value["encryption_context"]["scheme"] = serde_json::json!("mls_exporter_aead_v1");
        assert!(serde_json::from_value::<MessageAuthoringContent>(value).is_err());
    }

    #[test]
    fn message_authoring_exporter_counter_is_rejected_before_preparation() {
        let content = mls_content(standard(0, event_ref(1)), None, realm_scope(REALM), DEVICE);
        let mut value = serde_json::to_value(content).unwrap();
        value["encrypted_content"]["encryption_context"]["counter"] = serde_json::json!(7);
        assert!(serde_json::from_value::<MessageAuthoringContent>(value).is_err());
    }

    #[tokio::test]
    async fn message_authoring_metadata_routing_context_is_schema_violation() {
        let state = test_state();
        let scope = realm_scope(REALM);
        accept_genesis(&state, &scope, &event_ref(1)).await;
        let metadata = envelope(EncryptedEnvelopeEncryptionContext::StandardMls {
            epoch: 0,
            group_state_ref: event_ref(1),
            routing_context: Some(EncryptedEnvelopeRoutingContext {
                target_ref: event_ref(9),
                routing_tag: "A".repeat(43),
            }),
        });
        let content = mls_content(
            standard(0, event_ref(1)),
            Some(metadata),
            scope.clone(),
            DEVICE,
        );
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_frozen_scope_mismatch_is_scope_ref_mismatch() {
        let state = test_state();
        let scope = realm_scope(REALM);
        accept_genesis(&state, &scope, &event_ref(1)).await;
        let content = mls_content(
            standard(0, event_ref(1)),
            None,
            realm_scope(OTHER_REALM),
            DEVICE,
        );
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "failed_precondition",
            Some("scope_ref_mismatch"),
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_foreign_sender_domain_is_capability_denied() {
        let state = test_state();
        let scope = realm_scope(REALM);
        accept_genesis(&state, &scope, &event_ref(1)).await;
        let content = mls_content(
            standard(0, event_ref(1)),
            None,
            scope.clone(),
            "ak:device:01904100-0000-7000-8000-00000000000e",
        );
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::FORBIDDEN,
            "capability_denied",
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_without_accepted_mls_group_is_failed_precondition() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let content = mls_content(standard(0, event_ref(1)), None, scope.clone(), DEVICE);
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "failed_precondition",
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_current_read_fault_is_temporarily_unavailable() {
        assert_problem(
            Err(send_gate_problem(MlsSendGateError::CurrentUnavailable)),
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_uncovered_key_access_revision_is_epoch_update_required() {
        let state = test_state();
        let scope = realm_scope(REALM);
        accept_genesis(&state, &scope, &event_ref(1)).await;
        advance_key_access(&state, &scope).await;
        let content = mls_content(standard(0, event_ref(1)), None, scope.clone(), DEVICE);
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "failed_precondition",
            Some("epoch_update_required"),
        )
        .await;
        accept_commit(&state, &scope, &event_ref(1), &event_ref(2)).await;
        assert_problem(
            validate_encryption_context(&state, &content, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "failed_precondition",
            Some("epoch_update_required"),
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_superseded_epoch_is_epoch_mismatch() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let (genesis, commit) = (event_ref(1), event_ref(2));
        accept_genesis(&state, &scope, &genesis).await;
        accept_commit(&state, &scope, &genesis, &commit).await;
        let stale_content = mls_content(standard(0, genesis.clone()), None, scope.clone(), DEVICE);
        assert_problem(
            validate_encryption_context(&state, &stale_content, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "epoch_mismatch",
            None,
        )
        .await;
        let stale_metadata = mls_content(
            standard(1, commit.clone()),
            Some(standard(0, genesis)),
            scope.clone(),
            DEVICE,
        );
        assert_problem(
            validate_encryption_context(&state, &stale_metadata, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "epoch_mismatch",
            None,
        )
        .await;
        let wrong_group_state = mls_content(standard(1, event_ref(3)), None, scope.clone(), DEVICE);
        assert_problem(
            validate_encryption_context(&state, &wrong_group_state, &scope, DEVICE).await,
            StatusCode::CONFLICT,
            "epoch_mismatch",
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn message_authoring_current_mls_context_is_prepared() {
        let state = test_state();
        let scope = realm_scope(REALM);
        let (genesis, commit) = (event_ref(1), event_ref(2));
        accept_genesis(&state, &scope, &genesis).await;
        accept_commit(&state, &scope, &genesis, &commit).await;
        let content = mls_content(
            standard(1, commit.clone()),
            Some(standard(1, commit)),
            scope.clone(),
            DEVICE,
        );
        validate_encryption_context(&state, &content, &scope, DEVICE)
            .await
            .unwrap();
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
