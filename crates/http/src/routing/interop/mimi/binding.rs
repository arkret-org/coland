use super::*;

/// Resolve the exact canonical room URI against its authority-committed
/// current state.
pub(super) async fn latest_mimi_room_binding(
    state: &AppState,
    room_id: &str,
) -> Result<Option<MimiRoomBindingProjection>, AppError> {
    current_mimi_room_binding_for_uri(state, &mimi_room_uri(state, room_id)?).await
}

/// Resolve the unique current binding by the full canonical room URI.
pub(super) async fn current_mimi_room_binding_for_uri(
    state: &AppState,
    room_uri: &str,
) -> Result<Option<MimiRoomBindingProjection>, AppError> {
    let room_uri = arkret_wire::MimiRoomUri::new(room_uri.to_owned())
        .map_err(|error| AppError::param_invalid(format!("invalid MIMI room URI: {error}")))?;
    state
        .authority_commits()
        .current_mimi_room_binding(&room_uri)
        .await
        .map_err(|error| {
            AppError::internal(format!("MIMI current binding lookup failed: {error}"))
        })?
        .map(|record| {
            let binding = serde_json::to_value(record.current.value).map_err(|error| {
                AppError::internal(format!("MIMI current binding encoding: {error}"))
            })?;
            Ok(MimiRoomBindingProjection {
                event_id: record.source_event_id.to_string(),
                realm_id: record.realm_id.to_string(),
                binding,
            })
        })
        .transpose()
}

/// Resolve an authority-carried room-binding Event ref to the unique current
/// binding for that Event's signed canonical room URI.
pub(super) async fn current_mimi_room_binding_for_event_id(
    state: &AppState,
    event_id: &arkret_wire::EventId,
) -> Result<Option<MimiRoomBindingProjection>, AppError> {
    let room_uri = state
        .authority_commits()
        .committed_event(event_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("MIMI committed Event lookup failed: {error}"))
        })?
        .filter(|record| record.event.kind == arkret_wire::EventKind::MimiRoomBinding)
        .and_then(|record| {
            record
                .event
                .payload
                .get("mimi_room_uri")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let Some(room_uri) = room_uri else {
        return Ok(None);
    };
    let current = current_mimi_room_binding_for_uri(state, &room_uri).await?;
    Ok(current.filter(|binding| binding.event_id == event_id.as_str()))
}

pub(super) fn enforce_mimi_writable_binding(binding: &Value) -> Result<(), AppError> {
    validate_mimi_room_binding_payload(binding)?;
    let binding_payload = mimi_room_binding_security_payload(binding);
    match binding_payload.get("status").and_then(Value::as_str) {
        Some("accepted") => {}
        Some(_) | None => {
            return Err(AppError::param_invalid(
                "MIMI room binding is not writable in its current state",
            )
            .with_reason_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE));
        }
    }
    match binding_payload
        .get("local_provider_role")
        .and_then(Value::as_str)
    {
        Some("hub" | "follower") => {}
        Some("observer") => {
            return Err(
                AppError::capability_denied("MIMI observer binding cannot submit writes")
                    .with_reason_code(arkret_wire::ReasonCode::MIMI_OBSERVER_WRITE_FORBIDDEN),
            );
        }
        _ => {
            return Err(
                AppError::param_invalid("MIMI room binding has no writable provider role")
                    .with_reason_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE),
            );
        }
    }

    Ok(())
}

pub(super) async fn enforce_mimi_submit_binding(
    state: &AppState,
    source_provider: &str,
    room_binding: &MimiRoomBindingProjection,
    body: &MimiSubmitMessageRequestBody,
    message: &Value,
    associated_data: Option<&Value>,
) -> Result<(), AppError> {
    enforce_mimi_writable_binding(&room_binding.binding)?;
    let binding_payload = mimi_room_binding_security_payload(&room_binding.binding);
    let Some(binding_group_id) = binding_payload
        .get("mls_group_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(());
    };
    let submit_group_id = mimi_submit_mls_group_id(body).ok_or_else(|| {
        AppError::param_invalid("MIMI submit_message is missing mls_group_id")
            .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
    })?;
    let expected_scope: arkret_wire::ScopeRef = serde_json::from_value(serde_json::json!({
        "kind": "realm",
        "realm_id": room_binding.realm_id,
    }))
    .map_err(|_| {
        AppError::param_invalid("MIMI room binding has an invalid Realm scope")
            .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
    })?;
    validate_mimi_group_ids(&expected_scope, binding_group_id, submit_group_id)?;
    let epoch = mimi_submit_epoch(body).ok_or_else(|| {
        AppError::param_invalid("MIMI submit_message is missing MLS epoch")
            .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
    })?;
    let governance_binding =
        mimi_governance_binding_candidate(binding_payload, message, associated_data).ok_or_else(
            || {
                AppError::param_invalid("MIMI submit_message lacks governance_binding")
                    .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
            },
        )?;
    validate_mimi_submit_governance_binding(
        governance_binding,
        &room_binding.realm_id,
        binding_group_id,
        epoch,
    )?;

    let sender_route = crate::routing::actor_delivery_station(state, &body.sender_actor_id).await?;
    if sender_route.as_str() != source_provider {
        return Err(AppError::capability_denied(
            "MIMI source provider does not attest the sender's current route",
        )
        .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH));
    }
    if !crate::routing::realm_has_member(
        state,
        &room_binding.realm_id,
        &body.sender_actor_id.to_string(),
    )
    .await
    {
        return Err(AppError::capability_denied(
            "MIMI attributed sender is not a current Realm member",
        )
        .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH));
    }

    let Some(current) = state
        .mls_groups()
        .current(&expected_scope)
        .await
        .map_err(|error| AppError::internal(format!("current MLS group lookup: {error}")))?
    else {
        return Err(AppError::param_invalid(
            "MIMI submit_message has no accepted MLS security frontier",
        )
        .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING));
    };
    let mismatch = || {
        AppError::param_invalid(
            "MIMI accepted GroupInfo, room binding and effective scope disagree",
        )
        .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
    };
    let derived = expected_scope
        .canonical_mls_group_id()
        .map_err(|_| mismatch())?;
    if current.value.effective_scope != expected_scope {
        return Err(mismatch());
    }
    // This public state is installed only by native RFC 9420 admission. Recheck
    // its actual authenticated group, rather than trusting a claimed JSON id.
    let tracker = arkret_mls::MlsPublicGroupTracker::restore(
        &current.public_state,
        derived.as_str(),
        current.value.epoch,
    )
    .map_err(|_| mismatch())?;
    let verified_binding = tracker.governance_binding().map_err(|_| mismatch())?;
    let current = current.value;
    let current_binding = crate::routing::mls::current_mls_group_binding(state, &current).await?;
    if verified_binding != current_binding {
        return Err(mismatch());
    }
    let current_group_id = expected_scope.canonical_mls_group_id().map_err(|_| {
        AppError::param_invalid("MIMI MLS scope cannot derive a group id")
            .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
    })?;
    validate_mimi_group_ids(&expected_scope, binding_group_id, current_group_id.as_str())?;
    if current.epoch != epoch
        || arkret_canonical::canonical_json_bytes(&current_binding).map_err(|error| {
            AppError::internal(format!("MLS frontier canonicalization: {error}"))
        })? != arkret_canonical::canonical_json_bytes(governance_binding).map_err(|error| {
            AppError::internal(format!("MIMI governance binding canonicalization: {error}"))
        })?
    {
        return Err(AppError::param_invalid(
            "MIMI submit_message does not match the current accepted MLS security frontier",
        )
        .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH));
    }
    Ok(())
}

fn validate_mimi_group_ids(
    scope: &arkret_wire::ScopeRef,
    room_binding_group_id: &str,
    other_group_id: &str,
) -> Result<(), AppError> {
    let derived_group_id = scope.canonical_mls_group_id().map_err(|_| {
        AppError::param_invalid("MIMI MLS scope cannot derive a group id")
            .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
    })?;
    if room_binding_group_id != derived_group_id.as_str()
        || other_group_id != derived_group_id.as_str()
    {
        return Err(AppError::param_invalid(
            "MIMI MLS group id does not match the accepted security scope",
        )
        .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH));
    }
    Ok(())
}

pub(super) fn validate_mimi_room_binding_payload(binding: &Value) -> Result<(), AppError> {
    let payload = mimi_room_binding_security_payload(binding);
    if payload
        .get("hub_provider_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(
            AppError::param_invalid("MIMI room binding requires hub_provider_id")
                .with_reason_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE),
        );
    }
    match payload.get("local_provider_role").and_then(Value::as_str) {
        Some("hub" | "follower" | "observer") => {}
        _ => {
            return Err(AppError::param_invalid(
                "MIMI room binding requires a known local_provider_role",
            )
            .with_reason_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE));
        }
    }
    match payload.get("status").and_then(Value::as_str) {
        Some("proposed" | "accepted" | "revoked" | "migrating") => Ok(()),
        _ => Err(
            AppError::param_invalid("MIMI room binding requires a lifecycle status")
                .with_reason_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE),
        ),
    }
}

pub(super) fn mimi_room_binding_security_payload(binding: &Value) -> &Value {
    binding
        .get("payload")
        .filter(|payload| payload.is_object())
        .unwrap_or(binding)
}

pub(super) fn mimi_submit_mls_group_id(body: &MimiSubmitMessageRequestBody) -> Option<&str> {
    body.mls_group_id
        .as_ref()
        .map(MlsGroupId::as_str)
        .filter(|value| !value.trim().is_empty())
}

pub(super) fn mimi_submit_epoch(body: &MimiSubmitMessageRequestBody) -> Option<u64> {
    body.epoch
}

pub(super) fn mimi_governance_binding_candidate<'a>(
    binding_payload: &'a Value,
    message: &'a Value,
    associated_data: Option<&'a Value>,
) -> Option<&'a Value> {
    governance_binding_field(message)
        .or_else(|| associated_data.and_then(governance_binding_field))
        .or_else(|| governance_binding_field(binding_payload))
}

/// `governance_binding` is the canonical carrier name in every schema that
/// defines the object (`event-payload.schema.json#/$defs/mls_governance_binding`
/// and `mls-governance-proof-bundle.schema.json`); no spec schema defines a
/// field named `mls_governance_binding`.
pub(super) fn governance_binding_field(value: &Value) -> Option<&Value> {
    crate::routing::mls::payload_fields::governance_binding(value)
}

pub(super) fn validate_mimi_submit_governance_binding(
    binding: &Value,
    realm_id: &str,
    group_id: &str,
    epoch: u64,
) -> Result<(), AppError> {
    let error = |reason: &'static str| {
        AppError::param_invalid("MIMI submit_message governance_binding is not valid")
            .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
            .with_reason_detail(reason)
    };
    let binding: arkret_models_crypto::MlsGovernanceBindingPayload =
        serde_json::from_value(binding.clone())
            .map_err(|_| error("mls_governance_binding_invalid"))?;
    binding
        .validate()
        .map_err(|_| error("mls_governance_binding_invalid"))?;
    let derived_group_id = binding
        .mls_group_id()
        .map_err(|_| error("mls_governance_binding_invalid"))?;
    if derived_group_id.as_str() != group_id || binding.next_epoch() != epoch {
        return Err(error("mls_governance_binding_generation_mismatch"));
    }
    if binding
        .effective_scope()
        .realm_id_opt()
        .map(|id| id.as_str())
        != Some(realm_id)
    {
        return Err(error("mls_governance_binding_scope_mismatch"));
    }
    Ok(())
}

/// Admit the exact caller-authored room-binding Event carried by a MIMI update.
pub(super) async fn admit_mimi_room_binding_event(
    state: &AppState,
    room_id: &str,
    update_body: &Value,
    binding: &Value,
    submission: Value,
) -> Result<String, AppError> {
    let submission: arkret_wire::EventAdmissionSubmission = serde_json::from_value(submission)
        .map_err(|error| {
            AppError::schema_violation(format!("MIMI room binding Event is invalid: {error}"))
        })?;
    let realm_id = binding
        .get("binding_scope")
        .and_then(|s| s.get("realm_id"))
        .and_then(Value::as_str)
        .or_else(|| binding.get("realm_id").and_then(Value::as_str))
        .ok_or_else(|| {
            AppError::param_invalid(
                "room_binding requires `binding_scope.realm_id` or a top-level `realm_id`",
            )
            .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
        })?;

    let expected_room_uri = mimi_room_uri(state, room_id)?;
    let event = &submission.event;
    let sender_actor_id = update_body
        .get("sender_actor_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
        .ok_or_else(|| {
            AppError::param_invalid("room binding update requires sender_actor_id")
                .with_wire_code("mimi_room_binding_event_invalid")
        })?;
    let binding_group_id = binding.get("mls_group_id").and_then(Value::as_str);
    let update_group_id = update_body.get("mls_group_id").and_then(Value::as_str);
    if event.kind != arkret_wire::EventKind::MimiRoomBinding
        || event.realm_id.as_str() != realm_id
        || event.actor_id != sender_actor_id
        || serde_json::to_value(&event.payload).ok().as_ref() != Some(binding)
        || binding.get("mimi_room_uri").and_then(Value::as_str) != Some(expected_room_uri.as_str())
        || binding_group_id.is_none()
        || binding_group_id != update_group_id
    {
        return Err(AppError::param_invalid(
            "room_binding_event does not match the authenticated MIMI room update",
        )
        .with_wire_code("mimi_room_binding_event_invalid"));
    }
    // Reject all cross-bound request/Event identities before domain-state validation.
    validate_mimi_room_binding_payload(binding)?;
    let next: arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingPayload =
        serde_json::from_value(binding.clone()).map_err(|error| {
            AppError::schema_violation(format!("MIMI binding payload is invalid: {error}"))
        })?;
    next.validate_shape().map_err(|error| {
        AppError::schema_violation(format!("MIMI binding payload is invalid: {error}"))
    })?;
    let current = state
        .authority_commits()
        .current_mimi_room_binding(&next.mimi_room_uri)
        .await
        .map_err(|error| {
            AppError::internal(format!("MIMI current binding lookup failed: {error}"))
        })?;
    let exact_accepted_replay = state
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .map_err(|error| AppError::internal(format!("MIMI accepted Event lookup failed: {error}")))?
        .is_some_and(|original| original.event == *event);
    if !exact_accepted_replay {
        validate_mimi_binding_transition_preflight(current.as_ref(), &next)?;
    }
    local_mimi_sender_account(&sender_actor_id, &state.service_core_id())?;
    let event_id = event.event_id.to_string();
    crate::state::submit_mimi_binding_event(state, &submission)
        .await
        .map_err(|error| {
            AppError::capability_denied(format!("MIMI room binding admission refused: {error}"))
        })?;
    Ok(event_id)
}

fn validate_mimi_binding_transition_preflight(
    current: Option<&coland_storage::MimiRoomBindingCurrentRecord>,
    next: &arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingPayload,
) -> Result<(), AppError> {
    use arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingStatus as Status;

    let status = current.map(|record| record.current.value.status);
    let allowed = matches!(
        (status, next.status),
        (None, Status::Proposed | Status::Accepted)
            | (Some(Status::Proposed), Status::Accepted | Status::Revoked)
            | (Some(Status::Accepted), Status::Migrating | Status::Revoked)
            | (Some(Status::Migrating), Status::Accepted | Status::Revoked)
    );
    if !allowed {
        return Err(
            AppError::param_invalid("MIMI room binding status transition is invalid")
                .with_reason_code(
                    arkret_wire::ReasonCode::MIMI_ROOM_BINDING_STATUS_TRANSITION_INVALID,
                ),
        );
    }
    if status == Some(Status::Migrating) && next.status == Status::Accepted {
        let proof = next.migration_proof.as_ref().ok_or_else(|| {
            AppError::param_invalid("MIMI migration resolution requires committed lineage proof")
                .with_reason_code(
                    arkret_wire::ReasonCode::MIMI_ROOM_BINDING_MIGRATION_PROOF_INVALID,
                )
        })?;
        let current = current.expect("migrating status has current row");
        if current.source_event_id != proof.migrating_event_id
            || current.current.revision.commit_id != proof.migrating_commit_id
            || current.realm_id != next.binding_scope.realm_id
        {
            return Err(AppError::param_invalid(
                "MIMI migration proof does not name current binding",
            )
            .with_reason_code(arkret_wire::ReasonCode::MIMI_ROOM_BINDING_MIGRATION_PROOF_INVALID));
        }
    } else if next.migration_outcome.is_some() || next.migration_proof.is_some() {
        return Err(AppError::param_invalid(
            "MIMI migration fields are not valid on this transition",
        )
        .with_reason_code(arkret_wire::ReasonCode::MIMI_ROOM_BINDING_MIGRATION_PROOF_INVALID));
    }
    Ok(())
}

// This local submit path has no accepted foreign-account authority bridge.
// Do not manufacture one from a provider signature or from a bare principal.
fn local_mimi_sender_account(
    actor: &arkret_wire::ActorId,
    local_station: &arkret_wire::DidCoreId,
) -> Result<arkret_wire::AccountId, AppError> {
    actor
        .as_account_id()
        .filter(|account| &account.station_id == local_station)
        .cloned()
        .ok_or_else(|| {
            AppError::capability_denied("MIMI room binding requires a proven local Account sender")
        })
}

#[cfg(test)]
#[allow(
    clippy::items_after_test_module,
    reason = "the local-sender tests stay beside the private binding helpers they exercise"
)]
mod local_sender_tests {
    use super::*;

    #[test]
    fn mimi_group_id_guard_uses_the_accepted_scope_derivation() {
        let scope: arkret_wire::ScopeRef = serde_json::from_value(json!({
            "kind": "realm",
            "realm_id": "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"
        }))
        .unwrap();
        let group_id = scope.canonical_mls_group_id().unwrap();
        assert!(validate_mimi_group_ids(&scope, &group_id, &group_id).is_ok());
        assert!(validate_mimi_group_ids(&scope, "wrong-room-group", &group_id).is_err());
        assert!(validate_mimi_group_ids(&scope, &group_id, "wrong-message-group").is_err());
    }

    #[test]
    fn room_binding_accepts_the_registered_hub_provider_id_and_rejects_the_retired_field() {
        let payload = json!({
            "profile": "ak.profile.mimi_interop.v1",
            "mimi_room_uri": "mimi://example.com/rooms/fixture",
            "binding_scope": {
                "realm_id": "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
                "strand_id": "ak:strand:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"
            },
            "hub_provider_id": "ak:did_core:web:provider.example",
            "local_provider_role": "hub",
            "status": "accepted"
        });
        let typed: arkret_models_collaboration::events_payloads::MimiRoomBindingPayload =
            serde_json::from_value(payload.clone()).unwrap();
        assert!(validate_mimi_room_binding_payload(&serde_json::to_value(typed).unwrap()).is_ok());
        let mut retired = payload;
        let provider = retired
            .as_object_mut()
            .unwrap()
            .remove("hub_provider_id")
            .unwrap();
        retired["hub_provider"] = provider;
        assert!(validate_mimi_room_binding_payload(&retired).is_err());
    }

    #[test]
    fn room_binding_never_relabels_a_foreign_or_service_sender_as_a_local_account() {
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:sender.example").unwrap();
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let account = arkret_wire::AccountId::new(principal.clone(), station.clone());
        assert_eq!(
            local_mimi_sender_account(&arkret_wire::ActorId::account(account.clone()), &station)
                .unwrap(),
            account,
        );
        for rejected in [
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal.clone(),
                arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
            )),
            arkret_wire::ActorId::service(principal),
        ] {
            assert!(local_mimi_sender_account(&rejected, &station).is_err());
        }
    }
}

pub(super) fn unsupported_mimi_draft(body: &Value) -> Option<&'static str> {
    for (field, expected, message) in [
        (
            "protocol_draft",
            "draft-ietf-mimi-protocol-06",
            "unsupported MIMI protocol draft",
        ),
        (
            "content_draft",
            "draft-ietf-mimi-content-08",
            "unsupported MIMI content draft",
        ),
        (
            "room_policy_draft",
            "draft-ietf-mimi-room-policy-03",
            "unsupported MIMI room policy draft",
        ),
        (
            "identifier_draft",
            "draft-kohbrok-mimi-identifiers-01",
            "unsupported MIMI identifier draft",
        ),
    ] {
        let value = body
            .get(field)
            .or_else(|| body.get("mimi").and_then(|mimi| mimi.get(field)))
            .and_then(|value| value.as_str());
        if value.is_some_and(|value| value != expected) {
            return Some(message);
        }
    }
    None
}

pub(super) fn valid_mimi_room_id(room_id: &str) -> bool {
    !room_id.is_empty()
        && room_id.len() <= 256
        && room_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '~'))
}

pub(super) fn valid_mimi_content_type(value: &str) -> bool {
    matches!(
        value,
        "application/mimi-content"
            | "text/plain;charset=utf-8"
            | "text/markdown;variant=GFM-MIMI"
            | "application/vnd.arkret.content+json"
    )
}
