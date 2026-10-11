use sha2::{Digest, Sha256};

use super::*;
#[cfg(test)]
pub(in crate::routing) fn event_semantic_refs(
    object: &serde_json::Map<String, Value>,
    max_len: usize,
) -> Result<Vec<String>, EventValidationError> {
    let Some(value) = object.get("semantic_refs") else {
        return Ok(Vec::new());
    };
    let Some(values) = value.as_array() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "semantic_refs must be an array",
        ));
    };
    // scalability-constraints.md §2 — total semantic_refs[] across all roles ≤ 128.
    if values.len() > max_len
        || arkret_wire::event_envelope::validate_semantic_ref_count(values.len()).is_err()
    {
        return Err(event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            "semantic_refs[] exceeds the v1 maximum of 128 entries",
        ));
    }
    let mut authorized_refs = Vec::new();
    for value in values {
        let Some(reference) = value.as_object() else {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_invalid",
                "semantic_refs entries must be objects",
            ));
        };
        let id = event_string_field(reference, &["id"]).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_invalid",
                "semantic_refs entries require id",
            )
        })?;
        let role = event_string_field(reference, &["role"]).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_invalid",
                "semantic_refs entries require role",
            )
        })?;
        if role == "authorized_by" {
            if arkret_identifiers::GrantId::new(id.clone()).is_err() {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "param_invalid",
                    "authorized_by semantic refs must use the ak:grant: typed prefix",
                ));
            }
            authorized_refs.push(id);
        }
    }
    // scalability-constraints.md §2 — the `authorized_by` role is capped at 64
    // within the 128 total; authorized_by refs MUST be the minimal authorizing
    // state set (event-and-patch.md §2.2).
    if arkret_wire::event_envelope::validate_authorized_by_ref_count(authorized_refs.len()).is_err()
    {
        return Err(event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            "authorized_by semantic refs exceed the v1 maximum of 64 entries",
        ));
    }
    Ok(authorized_refs)
}

fn event_for_canonical_digest(envelope: &Value) -> Result<Event, EventValidationError> {
    // `canonical_*` are storage adapter metadata, not Event fields. All
    // protocol exclusions (`proofs`, `unsigned`, reducer-stamped fields) are
    // owned by SDK `Event::digest_payload`; Coland must not mirror that list.
    let mut value = envelope.clone();
    if let Value::Object(object) = &mut value {
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    serde_json::from_value(value).map_err(|error| {
        event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            format!("event envelope is not an SDK Event: {error}"),
        )
    })
}

pub(in crate::routing) fn event_canonical_bytes(
    envelope: &Value,
) -> Result<Vec<u8>, EventValidationError> {
    let event = event_for_canonical_digest(envelope)?;
    let payload = event.digest_payload().map_err(|error| {
        event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            format!("event digest payload cannot be built: {error}"),
        )
    })?;
    canonical::canonical_json_bytes(&payload).map_err(|_| {
        event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            "event envelope cannot be canonicalized",
        )
    })
}

#[cfg(test)]
pub(crate) fn is_valid_event_id(value: &str) -> bool {
    EventId::new(value.to_owned()).is_ok()
}

/// The single Event -> `Operation` mapper.
///
/// It is deliberately a function of the accepted wire envelope alone. The
/// authenticated submitting device is request context, not an Event field
/// (`event-envelope.schema.json` declares no `device_id` and closes the
/// object), so replay can reach exactly the same Operation as admission did.
fn projection_operation_from_wire(
    kind: &str,
    event_id: &str,
    envelope: &Value,
) -> Option<Operation> {
    if arkret_wire::EventKind::try_new(kind).is_none() {
        tracing::debug!(kind, "projection: kind is not registered");
        return None;
    }
    let Some(operation_id) = event_operation_id(envelope, event_id) else {
        tracing::debug!(kind, event_id, "projection: event_operation_id failed");
        return None;
    };
    let event = event_for_canonical_digest(envelope)
        .map_err(|error| {
            tracing::debug!(
                kind,
                event_id,
                ?error,
                "projection: SDK Event decode failed"
            );
            error
        })
        .ok()?;
    Operation::from_accepted_event(
        operation_id,
        arkret_wire::OperationKind::Create,
        None,
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .map_err(|error| {
        tracing::debug!(
            kind,
            event_id,
            %error,
            "projection: SDK accepted Event projection failed"
        );
        error
    })
    .ok()
}

/// Rebuild the exact internal projection DTO used at admission from one
/// canonical Event record.  Hydration must not invent a second Event ->
/// Operation mapping: the accepted wire envelope is the source of truth and
/// this delegates to the same mapper used by the live submit path.
pub(crate) fn projection_operation_from_canonical_record(
    record: &AcceptedEvent,
) -> Option<Operation> {
    // The stored envelope is the accepted Event verbatim, so every typed
    // field it carries (`realm_id`, `actor_id`, `semantic_refs`, …) is revalidated
    // by the SDK `Event` decode inside the shared mapper. Rebuilding an
    // admission-shaped DTO here would only reintroduce request context that
    // replay does not have.
    projection_operation_from_wire(&record.kind, &record.event_id, &record.envelope)
}

/// Domain separator for the Operation handle coland derives for an accepted
/// Event. Versioned and distinct from protocol identity domains. This is a
/// Coland-local operation handle and is not a Realm identity derivation.
const EVENT_PROJECTION_OPERATION_DOMAIN: &[u8] = b"ak:operation:coland-event-projection:v1:";

fn event_projection_operation_uuid(event_id: &str) -> uuid::Uuid {
    let mut hasher = Sha256::new();
    hasher.update(EVENT_PROJECTION_OPERATION_DOMAIN);
    hasher.update(event_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

pub(crate) fn event_operation_id(envelope: &Value, event_id: &str) -> Option<OperationId> {
    // Prefer the client-supplied alias when it's a valid OperationId
    // (`ak:operation:<uuid v7>` per `arkret-rust-sdk/identifiers`). A client
    // that authored the draft locally already dedupes on that value, so
    // honouring it keeps a resubmission idempotent end to end.
    //
    // The alias lives in `unsigned`, which is outside the signed canonical
    // Event transcript, so it is routinely absent: a federated Event, a
    // non-SDK submitter, and every Event coland authors itself carry none.
    // Server correctness MUST NOT depend on it — returning `None` here drops
    // the entire projection chain for the Event, and with it
    // `validate_operation_semantics`, so a payload the kind's registered
    // validator would have rejected gets durably accepted instead.
    if let Some(alias) = envelope
        .get("unsigned")
        .and_then(Value::as_object)
        .and_then(|unsigned| unsigned.get("local_operation_idempotency_alias"))
        .and_then(Value::as_str)
        && let Ok(operation_id) = OperationId::new(alias.to_owned())
    {
        return Some(operation_id);
    }
    // Otherwise coland allocates the handle. `Operation` is
    // `ak.local.operation_draft.v1` — an SDK-local reducer DTO, not a wire
    // fact — so its id is the receiver's to mint, and `id-kind-registry.json`
    // makes `operation` producer-allocated (UUIDv7). Deriving it from the
    // Event id under a domain separator is what keeps it reproducible: live
    // admission and `projection_operation_from_canonical_record` hydration
    // must land on the same handle or the projection would re-key on reboot.
    //
    // Retyping the Event id into `ak:operation:<uuid>` — what this used to do
    // — cannot work: an Event id is a content-bound full-digest token
    // (`encoding.md` §4.0), while an Operation id is producer-allocated
    // (UUIDv7), so the retyped
    // value never validated and this function always returned `None`.
    let event_id = EventId::new(event_id.to_owned()).ok()?;
    OperationId::new(format!(
        "ak:operation:{}",
        event_projection_operation_uuid(event_id.as_str())
    ))
    .ok()
}

/// Resolve the Event's producer-signed `scope_ref` for read-path visibility.
pub(crate) fn effective_scope_for_envelope(envelope: &Value) -> Option<String> {
    let scope = envelope.get("scope_ref")?.as_object()?;
    match scope.get("kind").and_then(Value::as_str) {
        Some("circle") => scope
            .get("circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        Some("realm") => scope
            .get("realm_id")
            .and_then(Value::as_str)
            .map(|realm_id| format!("realm:{realm_id}")),
        _ => None,
    }
}

/// Strict accepted-envelope materialization for canonical scans. Privacy views
/// are applied by the caller; signed payloads must never be rewritten in place.
pub(crate) fn canonical_event_for_read(record: &AcceptedEvent) -> Result<Event, AppError> {
    let event: Event = serde_json::from_value(record.envelope.clone())
        .map_err(|error| AppError::internal(format!("invalid canonical Event: {error}")))?;
    if event.event_id.as_str() != record.event_id
        || event
            .derive_event_id_with_digest_suite(record.digest_suite)
            .map_err(|error| AppError::internal(error.to_string()))?
            != event.event_id
        || event.kind.as_str() != record.kind
        || event.actor_id.to_string() != record.actor_id
        || record
            .realm_id
            .as_deref()
            .is_some_and(|realm| realm != event.realm_id.as_str())
        || event
            .event_digest_with_digest_suite(record.digest_suite)
            .map_err(|error| AppError::internal(error.to_string()))?
            != record.canonical_digest
    {
        return Err(AppError::internal(
            "canonical Event index or digest mismatch",
        ));
    }
    Ok(event)
}

#[cfg(test)]
/// Committed-event read surfaces keep the stream slot without rewriting
/// signed bytes. Derive Message redaction from accepted history even when no
/// independent projection row exists, then emit the minimal withheld branch.
pub(crate) async fn canonical_event_read_row(
    state: &AppState,
    record: &AcceptedEvent,
) -> Result<CommittedEventView, AppError> {
    let event = canonical_event_for_read(record)?;
    let withheld = if retention_tombstone_for_event(state, &record.event_id).is_some() {
        true
    } else if matches!(
        event.kind,
        arkret_wire::EventKind::MessageCreate | arkret_wire::EventKind::MessageRevise
    ) {
        let message_id = if event.kind == arkret_wire::EventKind::MessageCreate {
            record.event_id.replacen("ak:event:", "ak:message:", 1)
        } else {
            event
                .payload
                .get("message_id")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::internal("revision has no canonical message target"))?
                .to_owned()
        };
        let records = state
            .event_queries()
            .canonical_events()
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        let mut redacted = false;
        for candidate in records {
            let Some(kind) = arkret_wire::EventKind::try_new(&candidate.kind) else {
                continue;
            };
            if !arkret_wire::events::kinds::is_redaction_kind(&kind)
                || canonical_realm_id_for_record(&candidate).as_deref()
                    != Some(event.realm_id.as_str())
            {
                continue;
            }
            let target = coland_domain::reducer::message_redaction_target_ref(
                &candidate.envelope["payload"],
            );
            if target.as_deref().is_some_and(|target| {
                target == message_id || target == message_id.replacen("ak:message:", "ak:event:", 1)
            }) {
                canonical_event_for_read(&candidate)?;
                redacted = true;
            }
        }
        redacted
    } else {
        false
    };
    let committed = state
        .persistence()
        .committed_event(&event.event_id)
        .await
        .map_err(|error| AppError::internal(format!("committed Event lookup failed: {error}")))?
        .ok_or_else(|| AppError::internal("accepted Event has no successful RealmCommit"))?;
    Ok(if withheld {
        withheld_event_read_row(committed.commit)
    } else {
        CommittedEventView::Full(CommittedEventFullView {
            commit: committed.commit,
            event,
        })
    })
}

#[cfg(test)]
pub(crate) fn withheld_event_read_row(commit: arkret_wire::RealmCommit) -> CommittedEventView {
    CommittedEventView::Withheld(CommittedEventWithheldView {
        commit,
        event_disclosure: EventDisclosure {
            status: EventDisclosureStatus::Withheld,
        },
    })
}

/// SPEC-SOL-003 — pre-acceptance validation for the durable
/// `ak.device.revoke` Control Move. v1 scaffold scope: only the principal
/// may revoke its own sibling devices (recovery-service revocation lands
/// with the recovery strands), and a device MUST NOT revoke itself
/// (`device-lifecycle.md` §2.2 self-lockout rule). The principal-control
/// realm binding itself is enforced by
/// `validate_principal_control_realm_binding`; payload field presence by
/// the registry payload schema.
pub(crate) fn canonical_realm_id_for_record(record: &AcceptedEvent) -> Option<String> {
    if record.kind == arkret_wire::EventKind::RealmCreate.as_str() {
        return record
            .event_id
            .strip_prefix("ak:event:")
            .map(|token| format!("ak:realm:{token}"));
    }
    record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| record.realm_id.as_deref().map(normalize_persisted_realm_id))
}

fn normalize_persisted_realm_id(id: &str) -> String {
    id.to_owned()
}

fn session_actor_id(state: &AppState, session: &SessionRecord) -> Option<arkret_wire::ActorId> {
    crate::routing::identity::session_actor::session_actor_from_credential(state, session).ok()
}

fn is_governance_replay_input(record: &AcceptedEvent) -> bool {
    matches!(
        record.kind.as_str(),
        arkret_wire::event_kind_str::REALM_CREATE | arkret_wire::event_kind_str::DEVICE_REANCHOR
    )
}

pub(crate) async fn event_visible_to_session(
    state: &AppState,
    record: &AcceptedEvent,
    session: &SessionRecord,
) -> bool {
    let Some(session_actor) = session_actor_id(state, session) else {
        return false;
    };
    if session_actor.to_string() == record.actor_id {
        return true;
    }
    // A Contact participant may resolve the exact bilateral request/response
    // after acceptance as well. This does not disclose the peer's PCR: only
    // the Events already named by this pair's accepted Contact are visible.
    if matches!(
        record.kind.as_str(),
        "ak.contact.requested" | "ak.contact.accepted"
    ) {
        let Ok(author) = serde_json::from_str::<arkret_wire::ActorId>(&record.actor_id) else {
            return false;
        };
        if let Ok(Some(contact)) = state.contacts().contact_any(&author, &session_actor).await
            && contact.status == "accepted"
            && ((contact.requester_id == author && contact.target_id == session_actor)
                || (contact.target_id == author && contact.requester_id == session_actor))
            && (contact
                .request_event_ref
                .as_ref()
                .is_some_and(|id| id.as_str() == record.event_id)
                || contact
                    .response_event_ref
                    .as_ref()
                    .is_some_and(|id| id.as_str() == record.event_id))
        {
            return true;
        }
    }
    // An ordinary Realm's Realm stream is decided by this Station's typed
    // current alone, governing or held as an anchored replica.
    let Ok(event_id) = arkret_wire::EventId::new(record.event_id.clone()) else {
        return false;
    };
    match state
        .authority_commits()
        .committed_event_for_member(&event_id, &session_actor, &state.service_core_id())
        .await
    {
        Ok(coland_storage::MemberCommittedEventRead::Read(view)) => {
            return matches!(*view, arkret_wire::CommittedEventView::Full(_));
        }
        Ok(coland_storage::MemberCommittedEventRead::OutsideOrdinaryRealmStream) => {}
        Ok(
            coland_storage::MemberCommittedEventRead::NotVisible
            | coland_storage::MemberCommittedEventRead::PendingAnchor,
        )
        | Err(_) => return false,
    }
    match canonical_realm_id_for_record(record) {
        Some(realm_id) => {
            // Agent PCR Events are authored as the Agent Actor, while the
            // delegated human controller owns the device key that signs the
            // accepted Seal. The controller must be able to resolve the exact
            // Event closure named by that Seal in order to verify and pin the
            // Agent PCR checkpoint; Agent PCRs intentionally have no ordinary
            // membership row.
            if let Some(controller_account) = session_actor.as_account_id()
                && crate::routing::identity::agent_pcr::agent_record_for_controller_account_pcr(
                    state,
                    controller_account,
                    &realm_id,
                )
                .await
                .ok()
                .flatten()
                .is_some()
            {
                return circle_event_visible_to_session(state, record, session);
            }
            // The genesis and reanchor anchors remain visible to current
            // members. Other history follows the signed scope and join cut;
            // no legacy Seal closure may widen it.
            let realm_visible = if is_governance_replay_input(record) {
                crate::routing::realm_has_member(state, &realm_id, &session_actor.to_string()).await
            } else {
                realm_event_visible_to_session(
                    state,
                    &realm_id,
                    record.received_at,
                    Some(&record.actor_id),
                    Some(session),
                )
                .await
            };
            realm_visible && circle_event_visible_to_session(state, record, session)
        }
        None => false,
    }
}

fn circle_event_visible_to_session(
    state: &AppState,
    record: &AcceptedEvent,
    session: &SessionRecord,
) -> bool {
    let Some(scope_circle_id) = effective_scope_for_envelope(&record.envelope)
        .filter(|scope| scope.starts_with("ak:circle:"))
    else {
        return true;
    };
    let Some(session_actor) = session_actor_id(state, session) else {
        return false;
    };
    if record.actor_id == session_actor.to_string() {
        return true;
    }
    state
        .projections()
        .snapshot()
        .circle_scope_visible_to_actor_at(
            &scope_circle_id,
            &session_actor.to_string(),
            record.received_at,
        )
}

#[cfg(test)]
mod refs_limit_tests {
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn own_event_visibility_never_crosses_station_accounts() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let session = SessionRecord {
            token_hash: "test".into(),
            account_pk: None,
            actor: "ak:did_core:web:alice.example".into(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: "device".into(),
            },
            audience: state.service_id().clone(),
            session_public_key: None,
            session_grant: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };
        let mut record = visibility_record(
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            json!({"scope_ref": {"kind": "circle", "circle_id": "ak:circle:fixture"}}),
        );
        record.actor_id = session_actor_id(&state, &session).unwrap().to_string();
        assert!(event_visible_to_session(&state, &record, &session).await);
        assert!(circle_event_visible_to_session(&state, &record, &session));
        record.actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(session.actor.clone()).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ))
        .to_string();
        assert!(!event_visible_to_session(&state, &record, &session).await);
        assert!(!circle_event_visible_to_session(&state, &record, &session));
    }

    fn semantic_refs_object(refs: serde_json::Value) -> serde_json::Map<String, Value> {
        json!({ "semantic_refs": refs })
            .as_object()
            .unwrap()
            .clone()
    }

    fn visibility_record(kind: &str, envelope: Value) -> AcceptedEvent {
        AcceptedEvent {
            event_id: "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM".to_owned(),
            actor_id: "ak:did_core:web:alice.example".to_owned(),
            realm_id: None,
            kind: kind.to_owned(),
            schema_id: "ak.schema.test.v1".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            canonical_bytes: Vec::new(),
            envelope,
            received_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn accepted_contact_exposes_only_exact_pair_events() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let session = SessionRecord {
            token_hash: "contact-visibility".into(),
            account_pk: None,
            actor: "ak:did_core:web:alice.example".into(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: "device".into(),
            },
            audience: state.service_id().clone(),
            session_public_key: None,
            session_grant: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };
        let alice = session_actor_id(&state, &session).unwrap();
        let bob = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap(),
            state.service_core_id(),
        ));
        let mut record = visibility_record("ak.contact.requested", json!({}));
        record.actor_id = bob.to_string();
        let mut contact = coland_domain::identity::ContactRecord {
            requester_id: bob,
            target_id: alice,
            contact_round_id: None,
            granted_to_target_scopes: vec!["direct_message".into()],
            granted_to_requester_scopes: vec!["direct_message".into()],
            status: "accepted".into(),
            pending_incoming_admitted: true,
            request_event_ref: Some(arkret_wire::EventId::new(record.event_id.clone()).unwrap()),
            request_slot_states: Vec::new(),
            request_receipts: Vec::new(),
            request_mirror_receipts: Vec::new(),
            contact_round_evidence: None,
            contact_round_evidence_history: Vec::new(),
            control_outcomes: Vec::new(),
            response_event_ref: None,
            tombstone_event_ref: None,
            message: None,
            peer_host_id: None,
            peer_service_resolution: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state
            .contacts()
            .save_contact(contact.clone())
            .await
            .unwrap();
        assert!(event_visible_to_session(&state, &record, &session).await);
        record.kind = "ak.device.authorize".into();
        assert!(!event_visible_to_session(&state, &record, &session).await);
        record.kind = "ak.contact.requested".into();
        contact.request_event_ref = None;
        state
            .contacts()
            .save_contact(contact.clone())
            .await
            .unwrap();
        assert!(!event_visible_to_session(&state, &record, &session).await);
        contact.request_event_ref =
            Some(arkret_wire::EventId::new(record.event_id.clone()).unwrap());
        contact.status = "tombstoned".into();
        state.contacts().save_contact(contact).await.unwrap();
        assert!(!event_visible_to_session(&state, &record, &session).await);
    }

    #[test]
    fn governance_replay_visibility_does_not_classify_ordinary_events_as_control_moves() {
        let message = visibility_record(
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            json!({"auth_context": {}}),
        );
        let control = visibility_record(arkret_wire::event_kind_str::MEMBER_STATE, json!({}));
        let genesis = visibility_record(arkret_wire::event_kind_str::REALM_CREATE, json!({}));

        assert!(!is_governance_replay_input(&message));
        assert!(!is_governance_replay_input(&control));
        assert!(is_governance_replay_input(&genesis));
    }

    // scalability-constraints.md §2 — total refs[] across all roles ≤ 128.
    #[test]
    fn total_refs_over_max_rejected_as_refs_too_large() {
        let refs: Vec<Value> = (0..(MAX_SEMANTIC_REFS + 1))
            .map(|_| json!({"id": "ak:event:e", "role": "after"}))
            .collect();
        let err =
            event_semantic_refs(&semantic_refs_object(json!(refs)), MAX_SEMANTIC_REFS).unwrap_err();
        assert_eq!(err.code, "schema_violation");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // §2 — `authorized_by` role ≤ 64 within the 128 total.
    #[test]
    fn authorized_by_over_max_rejected_as_refs_too_large() {
        let refs: Vec<Value> = (0..(arkret_wire::event_envelope::MAX_AUTHORIZED_BY_REFS + 1))
            .map(|index| {
                let event_id = arkret_identifiers::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [index as u8; 32],
                );
                let grant_id = arkret_identifiers::GrantId::from_event_id(&event_id);
                json!({
                    "id": grant_id,
                    "role": "authorized_by"
                })
            })
            .collect();
        let err =
            event_semantic_refs(&semantic_refs_object(json!(refs)), MAX_SEMANTIC_REFS).unwrap_err();
        assert_eq!(err.code, "schema_violation");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn within_limits_collects_only_authorized_by_refs() {
        let refs = json!([
            {
                "id": "ak:grant:Aews9kH_oZbsLC9YX_XMJSaKOrsppWb0OKlspPS-1a6p",
                "role": "authorized_by"
            },
            {"id": "ak:event:e2", "role": "after"}
        ]);
        let out = event_semantic_refs(&semantic_refs_object(refs), MAX_SEMANTIC_REFS).unwrap();
        assert_eq!(
            out,
            vec!["ak:grant:Aews9kH_oZbsLC9YX_XMJSaKOrsppWb0OKlspPS-1a6p".to_owned()]
        );
    }

    #[test]
    fn authorized_by_rejects_event_id_alias() {
        let refs = json!([{
            "id": "ak:event:Aews9kH_oZbsLC9YX_XMJSaKOrsppWb0OKlspPS-1a6p",
            "role": "authorized_by"
        }]);
        let err = event_semantic_refs(&semantic_refs_object(refs), MAX_SEMANTIC_REFS).unwrap_err();
        assert_eq!(err.code, "param_invalid");
    }
}
