use arkret_models_collaboration::events_payloads::call::{
    CallCreatePayload, CallLifecycleState, CallModerationDelta, CallRecordingStartPayload,
    CallRecordingState, CallRosterDelta, CallStatePayload, CallTranscriptState,
    RecordingCaptureKind,
};

use super::*;

impl ProjectionState {
    /// Cache an already accepted preview policy without using it for admission.
    pub(crate) fn apply_realm_preview_policy(&mut self, operation: &Operation) -> ProjectionEffect {
        let policy = match serde_json::from_value::<
            arkret_models_collaboration::events_payloads::preview::PreviewPolicyPayload,
        >(operation.payload.clone())
        {
            Ok(policy) => policy,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        let realm_id = operation.realm_id.to_string();
        self.set_realm_facet(
            &realm_id,
            facet::REALM_PREVIEW_POLICY,
            serde_json::to_value(policy.value).expect("serializable preview policy"),
        );
        ProjectionEffect::RealmPreviewPolicyProjected { realm_id }
    }

    /// Apply one closed Realm-bootstrap facet.
    ///
    /// Each of these kinds writes exactly one Realm-singleton facet whose
    /// value is the whole accepted payload, and each is write-once: the
    /// bootstrap sequence declares the Realm's opening policy and a second
    /// accepted Event of the same kind would be a silent redefinition.
    pub fn apply_realm_bootstrap_facet(&mut self, operation: &Operation) -> ProjectionEffect {
        let kind = operation.event_kind.clone();
        if kind == arkret_wire::EventKind::RealmPolicyBundle {
            return self.apply_realm_policy_bundle(operation);
        }
        let name = match &kind {
            arkret_wire::EventKind::RealmAlias => facet::REALM_ALIAS,
            arkret_wire::EventKind::RealmJoinRule => facet::REALM_JOIN_RULE,
            arkret_wire::EventKind::RealmDiscovery => facet::REALM_DISCOVERY,
            arkret_wire::EventKind::RealmPlaintextVisibleServices => {
                facet::REALM_PLAINTEXT_VISIBLE_SERVICES
            }
            _ => {
                return ProjectionEffect::Rejected {
                    reason: "out_of_order_bootstrap".to_owned(),
                };
            }
        };
        let realm_id = operation.realm_id.to_string();
        let target = FacetRef::singleton(name);
        if self.facet_value(&realm_id, &target).is_some() {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
            };
        }
        let value = operation.payload.clone();
        if kind == arkret_wire::EventKind::RealmJoinRule {
            // `realm_join_rule_payload` is `{"value": <enum>}`, so the scalar
            // rule lives one level down.
            let Some(join_rule) = value.get("value").and_then(Value::as_str) else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            };
            // An accepted policy bundle is the other half of the pair; a Realm
            // that has not written one yet is checked when it does.
            if join_rule_requires_an_automatic_gate(join_rule)
                && self.realm_policy_bundle_value(&realm_id).is_some()
                && !join_policy_declares_an_automatic_gate(self.realm_join_policy_value(&realm_id))
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::JOIN_RULE_POLICY_MISMATCH.to_owned(),
                };
            }
            self.realm_join_rules
                .insert(realm_id.clone(), join_rule.to_owned());
        }
        self.set_facet(&realm_id, target, value);
        ProjectionEffect::RealmBootstrapFacetProjected {
            realm_id,
            kind: kind.as_str().to_owned(),
        }
    }

    /// Project `ak.realm.policy_bundle` into the Realm policy facet. The
    /// Event Envelope wire shape is the flat closed `realm_policy_bundle_payload`
    /// object, NOT a `{"value": ...}` state payload wrapper —
    /// `additionalProperties:false` on that def makes the wrapper
    /// unrepresentable on the wire.
    pub(crate) fn apply_realm_policy_bundle(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let value = operation.payload.clone();
        let Ok(bundle) = operation.typed_payload::<arkret_wire::event_spec::RealmPolicyBundle>()
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        if bundle.validate().is_err() {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }
        let Some(incoming_revision) = value.get("policy_revision").and_then(Value::as_u64) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        let previous_revision = self
            .realm_policy_bundle_value(&realm_id)
            .and_then(|current| current.get("policy_revision"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let expected_revision = previous_revision.saturating_add(1);
        if incoming_revision < expected_revision {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::POLICY_REVISION_ROLLBACK.to_owned(),
            };
        }
        if incoming_revision > expected_revision {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::POLICY_REVISION_GAP.to_owned(),
            };
        }
        if self.realm_security_class(&realm_id).as_deref() == Some("high_assurance")
            && !matches!(
                value.get("federation_policy").and_then(Value::as_str),
                Some("closed" | "restricted" | "quarantine")
            )
        {
            return ProjectionEffect::Rejected {
                reason: "high_assurance_federation_policy_invalid".to_owned(),
            };
        }
        if let Some(join_policy) = value.get("join_policy")
            && let Err(reason) = validate_join_policy_payload(join_policy)
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if join_rule_requires_an_automatic_gate(self.realm_default_join_rule(&realm_id))
            && !join_policy_declares_an_automatic_gate(value.get("join_policy"))
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::JOIN_RULE_POLICY_MISMATCH.to_owned(),
            };
        }
        self.set_realm_facet(&realm_id, facet::REALM_POLICY_BUNDLE, value);
        ProjectionEffect::RealmPolicyBundleProjected { realm_id }
    }

    pub(crate) fn apply_realm_search_policy(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let value = state_payload_value(&operation.payload).clone();
        if let Err(reason) = validate_realm_search_policy_payload(&value) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        self.set_realm_facet(&realm_id, facet::REALM_SEARCH_POLICY, value);
        ProjectionEffect::RealmSearchPolicyProjected { realm_id }
    }

    /// Replace this exact scope's whole receipt policy, preserving omissions.
    pub(crate) fn apply_scope_read_receipt_policy(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let scope = &operation.context.accepted_scope_ref;
        if !matches!(
            scope,
            arkret_wire::ScopeRef::Realm { .. } | arkret_wire::ScopeRef::Circle { .. }
        ) || scope.realm_id_opt() != Some(&operation.realm_id)
            || serde_json::from_value::<
                arkret_models_collaboration::events_payloads::ReadReceiptPolicyPayload,
            >(operation.payload.clone())
            .and_then(|value| value.validate().map_err(serde::de::Error::custom))
            .is_err()
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }
        let subject = match arkret_canonical::canonical_json_bytes(scope) {
            Ok(bytes) => String::from_utf8(bytes).expect("canonical JSON is UTF-8"),
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        self.set_facet(
            operation.realm_id.as_ref(),
            FacetRef::new(facet::SCOPE_READ_RECEIPT_POLICY, subject),
            operation.payload.clone(),
        );
        ProjectionEffect::ScopeReadReceiptPolicyProjected {
            scope_ref: scope.clone(),
        }
    }

    /// Project `ak.realm.media_service` into the Realm media-service facet
    /// consumed by the media token exchange (`routing::interop::webrtc`). The
    /// SDK's exact payload type validates the closed descriptor before its
    /// `value` is projected.
    pub(crate) fn apply_realm_media_service(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let payload = match serde_json::from_value::<
            arkret_models_collaboration::events_payloads::realm::RealmMediaServicePayload,
        >(operation.payload.clone())
        {
            Ok(payload) => payload,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        if payload.value.foci.is_empty() {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::MEDIA_SERVICE_FOCI_REQUIRED.to_owned(),
            };
        }
        let Ok(value) = serde_json::to_value(&payload.value) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        self.set_realm_facet(&realm_id, facet::REALM_MEDIA_SERVICE, value);
        ProjectionEffect::RealmMediaServiceProjected { realm_id }
    }

    /// Project a validated `ak.call.create` Event. The CallId is the accepted
    /// Event identity with a typed prefix; it is never supplied by the author.
    pub(crate) fn apply_call_create(&mut self, operation: &Operation) -> ProjectionEffect {
        if operation.payload.get("call_id").is_some() {
            return ProjectionEffect::Rejected {
                reason: "call_id_must_be_event_derived".to_owned(),
            };
        }
        let payload = match serde_json::from_value::<CallCreatePayload>(operation.payload.clone()) {
            Ok(payload) if payload.validate().is_ok() => payload,
            _ => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID.to_owned(),
                };
            }
        };
        let event_id = operation.context.event_id.clone();
        let call_id = arkret_identifiers::CallId::from_event_id(&event_id).to_string();
        let initial_state = call_lifecycle_wire(payload.initial_state);
        let realm_id = operation.realm_id.to_string();
        let state_facet = FacetRef::new(facet::CALL_STATE, &call_id);
        match self
            .facet_value(&realm_id, &state_facet)
            .and_then(Value::as_str)
        {
            None => {}
            Some(current) if current == initial_state => {
                return ProjectionEffect::CallStateProjected { call_id };
            }
            Some(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID.to_owned(),
                };
            }
        }
        self.set_facet(
            &realm_id,
            state_facet,
            Value::String(initial_state.to_owned()),
        );
        ProjectionEffect::CallStateProjected { call_id }
    }

    /// Project a validated `ak.call.state` Event into the independent call
    /// facets it names. Every delta the payload carries is applied, or the
    /// whole Event is rejected; a partially applied call Event would leave the
    /// roster and the lifecycle disagreeing.
    pub(crate) fn apply_call_state(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload = match serde_json::from_value::<CallStatePayload>(
            state_payload_value(&operation.payload).clone(),
        ) {
            Ok(payload) => payload,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        if let Err(reason) = payload.validate() {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let realm_id = operation.realm_id.to_string();
        let call_id = payload.call_id.to_string();
        let state_facet = FacetRef::new(facet::CALL_STATE, &call_id);
        if payload.state_transition.is_none() && self.facet_value(&realm_id, &state_facet).is_none()
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID.to_owned(),
            };
        }

        let mut writes: Vec<(FacetRef, Value)> = Vec::new();

        if let Some(transition) = &payload.state_transition {
            let from = call_lifecycle_wire(transition.from);
            let to = call_lifecycle_wire(transition.to);
            if let Err(reason) = self.check_call_lifecycle_edge(&realm_id, &state_facet, from, to) {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
            writes.push((state_facet, Value::String(to.to_owned())));
        }

        if let Some(focus) = &payload.focus {
            let focus_facet = FacetRef::new(facet::CALL_FOCUS, &call_id);
            let Ok(next) = serde_json::to_value(focus) else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            };
            // `call-state.md` §5 — a committed `session_focus` is final for the
            // life of the call; a later focus write may refine the mode but not
            // move the session off the focus already committed to.
            if let Some(committed) = self
                .facet_value(&realm_id, &focus_facet)
                .and_then(|value| value.get("session_focus"))
                .and_then(Value::as_str)
                && next.get("session_focus").and_then(Value::as_str) != Some(committed)
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::SESSION_FOCUS_ALREADY_COMMITTED.to_owned(),
                };
            }
            writes.push((focus_facet, next));
        }

        if let Some(transition) = &payload.recording_transition {
            let subject = [call_id.as_str(), transition.recording_id.as_str()];
            let capture = FacetRef::composite(facet::CALL_RECORDING, &subject);
            let from = call_recording_wire(transition.from);
            let to = call_recording_wire(transition.to);
            if !matches!(
                (from, to),
                ("recording", "stopped" | "ready" | "failed") | ("stopped", "ready")
            ) || self
                .facet_value(&realm_id, &capture)
                .and_then(Value::as_str)
                != Some(from)
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::RECORDING_STATE_TRANSITION_INVALID.to_owned(),
                };
            }
            writes.push((capture, Value::String(to.to_owned())));
            if let Some(result) = &transition.capture_metadata {
                let Ok(value) = serde_json::to_value(result) else {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                };
                writes.push((
                    FacetRef::composite(facet::CALL_RECORDING_RESULT, &subject),
                    value,
                ));
            }
        }

        if let Some(transition) = &payload.transcript_transition {
            let subject = [call_id.as_str(), transition.recording_id.as_str()];
            let capture = FacetRef::composite(facet::CALL_TRANSCRIPT, &subject);
            let from = call_transcript_wire(transition.from);
            let to = call_transcript_wire(transition.to);
            if !matches!(
                (from, to),
                ("transcribing", "stopped" | "ready" | "failed") | ("stopped", "ready")
            ) || self
                .facet_value(&realm_id, &capture)
                .and_then(Value::as_str)
                != Some(from)
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::RECORDING_STATE_TRANSITION_INVALID.to_owned(),
                };
            }
            writes.push((capture, Value::String(to.to_owned())));
            if let Some(result) = &transition.capture_metadata {
                let Ok(value) = serde_json::to_value(result) else {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                };
                writes.push((
                    FacetRef::composite(facet::CALL_TRANSCRIPT_RESULT, &subject),
                    value,
                ));
            }
        }

        if let Some(delta) = &payload.roster_delta {
            let roster = FacetRef::new(facet::CALL_ROSTER, &call_id);
            let mut entries = self.facet_entries(&realm_id, &roster);
            match delta {
                CallRosterDelta::Join { participant } => {
                    let Ok(entry) = serde_json::to_value(participant) else {
                        return ProjectionEffect::Rejected {
                            reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                        };
                    };
                    upsert_call_entry(
                        &mut entries,
                        &["actor_id", "device_id"],
                        entry,
                        operation.context.event_id.as_str(),
                    );
                }
                CallRosterDelta::Leave {
                    actor_id,
                    device_id,
                    ..
                } => {
                    // The covering Commit already decided the whole-axis CAS.
                    // This cache only restores its accepted effective roster.
                    let actor =
                        serde_json::to_value(actor_id).expect("typed roster actor serializes");
                    entries.retain(|entry| {
                        entry.get("value").and_then(|value| value.get("actor_id")) != Some(&actor)
                            || entry
                                .get("value")
                                .and_then(|value| value.get("device_id"))
                                .and_then(Value::as_str)
                                != Some(device_id.as_str())
                    });
                }
            }
            writes.push((roster, Value::Array(entries)));
        }

        if let Some(delta) = &payload.moderation_delta {
            let moderation = FacetRef::new(facet::CALL_MODERATION, &call_id);
            let mut entries = self.facet_entries(&realm_id, &moderation);
            match delta {
                CallModerationDelta::RemoveParticipant { removal } => {
                    let Ok(entry) = serde_json::to_value(removal) else {
                        return ProjectionEffect::Rejected {
                            reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                        };
                    };
                    upsert_call_entry(
                        &mut entries,
                        &["actor_id", "action"],
                        entry,
                        operation.context.event_id.as_str(),
                    );
                }
                CallModerationDelta::RestoreParticipant { actor_id, .. } => {
                    // Restore an accepted delta; admission lives in the authority UoW.
                    let actor = serde_json::to_value(actor_id)
                        .expect("typed moderation subject serializes");
                    entries.retain(|entry| {
                        entry.get("value").and_then(|value| value.get("actor_id")) != Some(&actor)
                            || entry
                                .get("value")
                                .and_then(|value| value.get("action"))
                                .and_then(Value::as_str)
                                != Some("ban")
                    });
                }
            }
            writes.push((moderation, Value::Array(entries)));
        }

        for (target, value) in writes {
            self.set_facet(&realm_id, target, value);
        }
        ProjectionEffect::CallStateProjected { call_id }
    }

    /// Project the capture transition and initial result of a validated
    /// `ak.call.recording.start`. Consent and visible notice are checked before
    /// either facet changes.
    pub(crate) fn apply_call_recording_start(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload = match serde_json::from_value::<CallRecordingStartPayload>(
            state_payload_value(&operation.payload).clone(),
        ) {
            Ok(payload) => payload,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        if payload.capture_metadata.retention.consent_confirmed != Some(true) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::RECORDING_CONSENT_REQUIRED.to_owned(),
            };
        }
        let realm_id = operation.realm_id.to_string();
        let call_id = payload.call_id.to_string();
        let subject = [call_id.as_str(), payload.recording_id.as_str()];
        let (capture, result, opening) = match payload.capture_kind {
            RecordingCaptureKind::Recording => (
                FacetRef::composite(facet::CALL_RECORDING, &subject),
                FacetRef::composite(facet::CALL_RECORDING_RESULT, &subject),
                "recording",
            ),
            RecordingCaptureKind::Transcript => (
                FacetRef::composite(facet::CALL_TRANSCRIPT, &subject),
                FacetRef::composite(facet::CALL_TRANSCRIPT_RESULT, &subject),
                "transcribing",
            ),
        };
        if self.facet_value(&realm_id, &capture).is_some() {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::RECORDING_STATE_TRANSITION_INVALID.to_owned(),
            };
        }
        let Ok(outcome) = serde_json::to_value(&payload.capture_metadata) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        self.set_facet(&realm_id, capture, Value::String(opening.to_owned()));
        self.set_facet(&realm_id, result, outcome);
        ProjectionEffect::CallStateProjected { call_id }
    }

    /// `call-state.md` §4.2 — the legal-successor table plus the terminal
    /// guard, checked against the currently projected head.
    fn check_call_lifecycle_edge(
        &self,
        realm_id: &str,
        state_facet: &FacetRef,
        from: &str,
        to: &str,
    ) -> std::result::Result<(), &'static str> {
        let current = self
            .facet_value(realm_id, state_facet)
            .and_then(Value::as_str);
        match current {
            Some(current) if current == from => {}
            Some(current) if is_terminal_call_state(current) => {
                return Err(arkret_wire::ReasonCode::CALL_STATE_TERMINAL);
            }
            _ => return Err(arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID),
        }
        let legal = match from {
            "scheduled" => matches!(
                to,
                "ringing" | "connecting" | "cancelled" | "missed" | "failed"
            ),
            "ringing" => matches!(
                to,
                "connecting" | "active" | "missed" | "cancelled" | "failed"
            ),
            "connecting" => matches!(to, "active" | "failed" | "ended"),
            "active" => matches!(to, "ended" | "failed"),
            _ => false,
        };
        if legal {
            Ok(())
        } else if is_terminal_call_state(from) {
            Err(arkret_wire::ReasonCode::CALL_STATE_TERMINAL)
        } else {
            Err(arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID)
        }
    }

    /// Current entries of a list-valued facet, or an empty list.
    fn facet_entries(&self, realm_id: &str, target: &FacetRef) -> Vec<Value> {
        self.facet_value(realm_id, target)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    /// Project a canonical `ak.realm.link` event into its facet and query caches.
    ///
    /// The HTTP operation materializes its default `status=active` before this
    /// point. Durable Event admission requires `status` explicitly.
    pub(crate) fn apply_realm_link(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(target_realm_id) = operation
            .payload
            .get("target_realm_id")
            .and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: "realm_link_target_missing".to_owned(),
            };
        };
        let Some(link_kind) = operation.payload.get("link_kind").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "realm_link_kind_missing".to_owned(),
            };
        };
        if arkret_models_collaboration::governance::realm_governance::RealmLinkKind::parse(
            link_kind,
        )
        .is_none()
        {
            return ProjectionEffect::Rejected {
                reason: "realm_link_kind_invalid".to_owned(),
            };
        }
        if target_realm_id == realm_id {
            return ProjectionEffect::Rejected {
                reason: "realm_link_self_reference".to_owned(),
            };
        }
        let status = operation
            .payload
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("active");
        let Some(next_status) =
            arkret_models_collaboration::governance::realm_governance::RealmLinkStatus::parse(
                status,
            )
        else {
            return ProjectionEffect::Rejected {
                reason: "realm_link_status_invalid".to_owned(),
            };
        };
        let current_status = self
            .realm_links
            .get(&realm_id)
            .and_then(|links| {
                links.iter().find(|link| {
                    link.target_realm_id == target_realm_id && link.link_kind == link_kind
                })
            })
            .and_then(|link| {
                arkret_models_collaboration::governance::realm_governance::RealmLinkStatus::parse(
                    &link.status,
                )
            });
        if current_status.is_some_and(|current| !current.can_transition_to(next_status)) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REALM_LINK_INVALID_TRANSITION.to_owned(),
            };
        }
        let label = operation
            .payload
            .get("label")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let commitment = operation
            .payload
            .get("commitment")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        self.set_facet(
            &realm_id,
            FacetRef::composite(facet::REALM_LINK, &[target_realm_id, link_kind]),
            serde_json::json!({
                "realm_id": realm_id,
                "target_realm_id": target_realm_id,
                "link_kind": link_kind,
                "status": status,
                "label": label,
                "commitment": commitment,
                "updated_at": arkret_canonical::format_timestamp_canonical(now),
            }),
        );

        // Structured side-band cache mirror. Outbound: keyed by source
        // realm. Inbound: keyed by target realm.
        let row = RealmLinkState {
            realm_id: realm_id.clone(),
            target_realm_id: target_realm_id.to_owned(),
            link_kind: link_kind.to_owned(),
            status: status.to_owned(),
            label,
            commitment,
            created_at: now,
            updated_at: now,
        };
        upsert_realm_link(self.realm_links.entry(realm_id.clone()).or_default(), &row);
        upsert_realm_link(
            self.realm_links_inbound
                .entry(target_realm_id.to_owned())
                .or_default(),
            &row,
        );

        ProjectionEffect::RealmLinkProjected {
            realm_id,
            target_realm_id: target_realm_id.to_owned(),
            link_kind: link_kind.to_owned(),
            status: status.to_owned(),
        }
    }
}

/// `call-state.md` §4.2 — terminal call lifecycle states.
fn is_terminal_call_state(state: &str) -> bool {
    matches!(state, "ended" | "missed" | "failed" | "cancelled")
}

fn call_lifecycle_wire(state: CallLifecycleState) -> &'static str {
    match state {
        CallLifecycleState::Scheduled => "scheduled",
        CallLifecycleState::Ringing => "ringing",
        CallLifecycleState::Connecting => "connecting",
        CallLifecycleState::Active => "active",
        CallLifecycleState::Ended => "ended",
        CallLifecycleState::Missed => "missed",
        CallLifecycleState::Failed => "failed",
        CallLifecycleState::Cancelled => "cancelled",
    }
}

fn call_recording_wire(state: CallRecordingState) -> &'static str {
    match state {
        CallRecordingState::Recording => "recording",
        CallRecordingState::Stopped => "stopped",
        CallRecordingState::Ready => "ready",
        CallRecordingState::Failed => "failed",
    }
}

fn call_transcript_wire(state: CallTranscriptState) -> &'static str {
    match state {
        CallTranscriptState::Transcribing => "transcribing",
        CallTranscriptState::Stopped => "stopped",
        CallTranscriptState::Ready => "ready",
        CallTranscriptState::Failed => "failed",
    }
}

/// Insert or replace one entry of a list-valued call facet.
///
/// Entries are a cache fold of accepted Events; typed current and CAS live
/// in the accepting authority transaction.
fn upsert_call_entry(entries: &mut Vec<Value>, keys: &[&str], value: Value, tag_id: &str) {
    let matches_key = |entry: &Value| {
        keys.iter()
            .all(|key| entry.get("value").and_then(|v| v.get(key)) == value.get(key))
    };
    entries.retain(|entry| !matches_key(entry));
    entries.push(serde_json::json!({ "tag_id": tag_id, "value": value }));
}

/// join-policy.md 2: `restricted` and `knock_restricted` promise an entry gate.
/// A policy carrying only `principal_admission` / `cooldown` hard gates admits
/// exactly the set `public` admits, so the pair is a contradictory declaration
/// and neither facet may be written under it.
pub fn join_policy_declares_an_automatic_gate(join_policy: Option<&Value>) -> bool {
    join_policy
        .and_then(|policy| policy.get("gates"))
        .and_then(Value::as_array)
        .is_some_and(|gates| {
            gates.iter().any(|gate| {
                matches!(
                    gate.get("kind").and_then(Value::as_str),
                    Some("claim_required" | "challenge_response" | "parent_membership")
                )
            })
        })
}

pub fn join_rule_requires_an_automatic_gate(join_rule: &str) -> bool {
    matches!(join_rule, "restricted" | "knock_restricted")
}
