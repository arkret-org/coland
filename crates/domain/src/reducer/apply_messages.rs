use arkret_models_collaboration::events_payloads::{
    PollBlock, PollContentBlock, PollResponseBlock,
};

use super::*;

impl ProjectionState {
    pub(crate) fn apply_message(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let event_id = operation.context.event_id.to_string();
        let message_id = message_id_from_payload_or_event_id(&operation.payload, &event_id);
        let sender = operation.context.sender.to_string();
        let thread_id = operation
            .payload
            .get("strand_id")
            .and_then(|v| v.as_str())
            .unwrap_or(operation.realm_id.as_str())
            .to_owned();
        // The receiver has already verified this immutable scope against the
        // Strand. A missing local Strand projection must not change the scope.
        let strand_scope = match &operation.context.accepted_scope_ref {
            arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id.to_string()),
            _ => None,
        };
        let content = message_content_from_payload(&operation.payload, strand_scope);
        let encrypted = operation
            .payload
            .get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| operation.payload.get("encrypted_content").is_some());

        let poll_content = operation
            .payload
            .get("content")
            .filter(|raw| {
                matches!(
                    content_kind(raw),
                    Some("ak.content.poll" | "ak.content.poll.response")
                )
            })
            .map(|raw| serde_json::from_value::<PollContentBlock>(raw.clone()));
        let definition = match poll_content {
            Some(Ok(block)) => {
                if operation
                    .context
                    .committed_ref
                    .as_ref()
                    .is_none_or(|reference| {
                        reference.event_id != operation.context.accepted_event_id
                    })
                {
                    return ProjectionEffect::Rejected {
                        reason: "poll_accepting_commit_unavailable".to_owned(),
                    };
                }
                let scope_realm = match &operation.context.accepted_scope_ref {
                    arkret_wire::ScopeRef::Realm { realm_id }
                    | arkret_wire::ScopeRef::Circle { realm_id, .. } => Some(realm_id),
                    _ => None,
                };
                if scope_realm != Some(&operation.realm_id) {
                    return ProjectionEffect::Rejected {
                        reason: "poll_ref_cross_scope".to_owned(),
                    };
                }
                if let Err(error) = block.validate() {
                    return ProjectionEffect::Rejected {
                        reason: error.to_string(),
                    };
                }
                match block {
                    PollContentBlock::Response(response) => {
                        return self.apply_poll_response(&response, operation, now);
                    }
                    PollContentBlock::Definition(definition) => Some(definition),
                }
            }
            Some(Err(error)) => {
                return ProjectionEffect::Rejected {
                    reason: format!("invalid Poll content: {error}"),
                };
            }
            None => None,
        };
        let state = MessageState {
            event_id: event_id.clone(),
            message_id,
            realm_id: operation.realm_id.to_string(),
            sender,
            thread_id,
            content,
            encrypted,
            operation_id: operation.operation_id.to_string(),
            created_at: now,
            revision_of: None,
            redacted_at: None,
        };
        let effect = ProjectionEffect::MessageCreated(state.clone());
        if let Some(reply) = operation.payload.get("reply_to_id").and_then(Value::as_str)
            && let Ok(target) = arkret_wire::MessageId::new(reply)
        {
            use arkret_models_collaboration::objects::relation::RelationEndpoint;
            let relation_id =
                arkret_wire::RelationId::from_event_id(&operation.context.event_id).to_string();
            let scope_circle_id = match &operation.context.accepted_scope_ref {
                arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id.to_string()),
                _ => None,
            };
            self.relations.insert(
                relation_id.clone(),
                ColandRelationState {
                    relation_id,
                    realm_id: operation.realm_id.to_string(),
                    relation_kind: "replies_to".to_owned(),
                    scope_circle_id,
                    from_ref: Some(RelationEndpoint::Object(state.message_id.clone())),
                    to_ref: Some(RelationEndpoint::Object(target.to_string())),
                    rank: None,
                    fields: BTreeMap::new(),
                    state: "active".to_owned(),
                    source_event_id: Some(event_id.clone()),
                    source_event_digest: None,
                    created_at: now,
                    updated_at: now,
                },
            );
        }
        if let Some(definition) = definition {
            self.apply_poll_create(operation, definition, now);
        }
        self.messages.insert(event_id, state);
        effect
    }

    fn apply_poll_create(
        &mut self,
        operation: &Operation,
        definition: PollBlock,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let scope_circle_id = match &operation.context.accepted_scope_ref {
            arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id.clone()),
            _ => None,
        };
        self.polls.insert(
            arkret_wire::MessageId::from_event_id(&operation.context.event_id),
            PollState {
                message_event_id: operation.context.event_id.clone(),
                realm_id: operation.realm_id.clone(),
                scope_circle_id,
                definition,
                votes: BTreeMap::new(),
                responses: BTreeMap::new(),
                created_at: now,
                updated_at: now,
            },
        );
    }

    pub(crate) fn apply_poll_response(
        &mut self,
        content: &PollResponseBlock,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let response = &content.poll_response;
        let Some(poll) = self.polls.get(&response.poll_ref) else {
            return ProjectionEffect::Rejected {
                reason: "poll_ref_unknown".to_owned(),
            };
        };
        let accepted_circle = match &operation.context.accepted_scope_ref {
            arkret_wire::ScopeRef::Realm { realm_id } if realm_id == &operation.realm_id => None,
            arkret_wire::ScopeRef::Circle {
                realm_id,
                circle_id,
            } if realm_id == &operation.realm_id => Some(circle_id),
            _ => {
                return ProjectionEffect::Rejected {
                    reason: "poll_ref_cross_scope".to_owned(),
                };
            }
        };
        if poll.realm_id != operation.realm_id || poll.scope_circle_id.as_ref() != accepted_circle {
            return ProjectionEffect::Rejected {
                reason: "poll_ref_cross_scope".to_owned(),
            };
        }
        let valid = poll
            .definition
            .poll
            .answers
            .iter()
            .map(|option| option.id.clone())
            .collect::<BTreeSet<_>>();
        let selected = match validate_poll_selections(
            &response.selections,
            &valid,
            usize::try_from(poll.definition.poll.max_selection_count).unwrap_or(usize::MAX),
        ) {
            Ok(selected) => selected,
            Err(reason) => {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        };
        let Some(accepted_ref) = operation.context.committed_ref.clone() else {
            return ProjectionEffect::Rejected {
                reason: "poll_accepting_commit_unavailable".to_owned(),
            };
        };
        let heads = match operation.payload.get("poll_response_heads") {
            Some(heads) => match serde_json::from_value::<
                Vec<arkret_models_collaboration::events_payloads::message::PollResponseHead>,
            >(heads.clone())
            {
                Ok(heads) => heads,
                Err(error) => {
                    return ProjectionEffect::Rejected {
                        reason: error.to_string(),
                    };
                }
            },
            None => Vec::new(),
        };
        let partition = arkret_models_collaboration::poll::PollPartition {
            realm_id: operation.realm_id.clone(),
            stream_ref: accepted_ref.stream_ref.clone(),
            poll_ref: response.poll_ref.clone(),
            poll_event_ref: poll.message_event_id.clone(),
            actor_id: operation.context.sender.clone(),
        };
        let verified = match arkret_models_collaboration::poll::VerifiedPollVote::new(
            partition,
            accepted_ref,
            &response.selections,
            &valid,
            usize::try_from(poll.definition.poll.max_selection_count).unwrap_or(usize::MAX),
            heads,
            |id| {
                poll.responses
                    .get(id)
                    .map(|prior| (prior.partition.clone(), prior.accepted_ref.clone()))
            },
        ) {
            Ok(response) => response,
            Err(error) => {
                return ProjectionEffect::Rejected {
                    reason: error.to_string(),
                };
            }
        };
        let mut inputs = arkret_models_collaboration::poll::PollResponseSet::default();
        for prior in poll
            .responses
            .values()
            .cloned()
            .chain(std::iter::once(verified.clone()))
        {
            if let Err(error) = inputs.insert(prior) {
                return ProjectionEffect::Rejected {
                    reason: error.to_string(),
                };
            }
        }
        // This projection is a cache of verified inputs. The accepting Commit
        // position wins even when an older response is delivered afterwards.
        let winner_is_incoming = inputs
            .project(false)
            .get(&verified.partition)
            .is_some_and(|projection| projection.winner.as_ref() == Some(&verified.accepted_ref));
        let poll_ref = response.poll_ref.clone();
        let actor_id = operation.context.sender.clone();
        let Some(poll) = self.polls.get_mut(&poll_ref) else {
            return ProjectionEffect::Rejected {
                reason: "poll_ref_unknown".to_owned(),
            };
        };
        poll.responses
            .insert(verified.accepted_ref.event_id.clone(), verified);
        if winner_is_incoming {
            poll.votes.insert(actor_id, selected);
        }
        poll.updated_at = poll.updated_at.max(now);
        ProjectionEffect::Ignored
    }

    pub(crate) fn apply_message_revise(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let target_ref = operation
            .payload
            .get("message_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let original_id = self
            .message_by_target_ref(target_ref)
            .map(|message| message.event_id.clone());
        let new_event_id = operation.context.event_id.to_string();

        if let Some(original_id) = original_id {
            let Some(original) = self.messages.get(&original_id) else {
                return self.queue_pending_replay(
                    original_id,
                    operation,
                    "message_revision_target_unknown",
                );
            };
            let mut revised = original.clone();
            revised.event_id = new_event_id.clone();
            revised.revision_of = Some(original_id.clone());
            revised.created_at = now;
            revised.operation_id = operation.operation_id.to_string();
            if let Some(content) = operation.payload.get("content") {
                revised.content = content.clone();
                revised.encrypted = false;
            } else if let Some(encrypted_content) = operation.payload.get("encrypted_content") {
                revised.content = encrypted_content.clone();
                revised.encrypted = true;
            }
            let effect = ProjectionEffect::MessageRevised {
                original_id: original_id.clone(),
                revision: revised.clone(),
            };
            self.messages.insert(new_event_id, revised);
            effect
        } else if target_ref.trim().is_empty() {
            self.apply_message(operation, now)
        } else {
            self.queue_pending_replay(target_ref, operation, "message_revision_target_unknown")
        }
    }

    /// Writes the parallel redaction OR-Set using the registered target
    /// subject verbatim. For `ak.message.redact`, that subject is the
    /// Message typed ID shared by every revision in the chain. The ordered-log historical entry id
    /// (the original [`MessageState`]) is preserved unchanged; the
    /// projection layer at read time consults the redaction cell and
    /// replaces the payload with a tombstone.
    ///
    /// `redacted` is an irreversible terminal (spec common-fields.md section
    /// 5.1) and the cell family is an `or_set` add, so there is no
    /// un-redaction path: neither payload class registers a field that could
    /// request one.
    ///
    /// When the payload's `target_ref` names a `ak:strand:` or
    /// `ak:morph:` typed-id, the redaction
    /// additionally flips the corresponding projection's state to
    /// `ObjectLifecycleState::Redacted` per spec common-fields.md section 5.1.
    /// Space containers are intentionally excluded: they have no Redacted
    /// terminal, and removal routes through `ak.space.tombstone` only.
    pub(crate) fn apply_redaction(&mut self, operation: &Operation) -> ProjectionEffect {
        // Attribution is the redaction Event's own actor; neither redaction
        // payload class carries an actor-supplied override.
        let by = operation.context.sender.to_string();
        let reason = redaction_human_reason(&operation.payload);
        let redaction_event_id = operation.context.event_id.to_string();

        // The Message path and the cross-object path are separate targets, not
        // a fallback chain: `ak.message.redact` carries `payload.message_id`,
        // `ak.redaction` carries `payload.target_ref`, and only the former can
        // resolve to a Message cell. Requiring a Message target before reaching
        // the object branch would silently ignore every Strand / Morph
        // redaction.
        let target_ref = message_redaction_target_ref(&operation.payload);
        let message_redaction = crate::kinds::canonical_kind_for_operation(operation)
            == Some(arkret_wire::EventKind::MessageRedact);
        let resolved_message = target_ref
            .as_deref()
            .and_then(|target| self.message_by_target_ref(target))
            .cloned();
        if message_redaction && resolved_message.is_none() {
            return self.queue_pending_replay(
                target_ref.unwrap_or_default(),
                operation,
                "message_redaction_target_unknown",
            );
        }
        let target = if message_redaction {
            resolved_message
                .as_ref()
                .map(|message| message.message_id.clone())
        } else {
            target_ref.clone()
        }
        .unwrap_or_default();
        if !target.is_empty() {
            let cell = RedactionCellValue {
                redacted_at: operation.created_at,
                by: by.clone(),
                reason: reason.clone(),
                redaction_event_id: Some(redaction_event_id),
            };
            self.redaction_cells.insert(target.clone(), cell);
            if message_redaction {
                for message in self
                    .messages
                    .values_mut()
                    .filter(|message| message.message_id == target)
                {
                    message.redacted_at = Some(operation.created_at);
                    self.redactions.insert(message.event_id.clone());
                }
            } else {
                self.redactions.insert(target.clone());
            }
        }

        // Strand / Morph object-level redaction. If the payload's
        // `target_ref` names a typed-id, push the projection to the Redacted terminal
        // state. State-machine guard against terminal source is policed
        // by `check_redaction_target_transition` preflight; by the time
        // the reducer runs here, the source state is known-permissible.
        let updated_by = Some(by);
        if let Some(object_ref) = redaction_object_ref(operation) {
            if let Some(strand) = self.strands.get_mut(&object_ref) {
                strand.state = ObjectLifecycleState::Redacted;
                strand.state_changed_at = Some(operation.created_at);
                // common-fields.md 5.2: every registered content slot MUST be
                // cleared in the same transition that writes state=redacted, so
                // the post-state satisfies strand.schema.json's redacted branch
                // without replaying the event stream. For a Strand that is the
                // top-level Description pair *and* the Synthesis track's pair.
                strand.content = None;
                strand.encrypted_content = None;
                if let Some(synthesis) = strand.tracks.get_mut("synthesis") {
                    synthesis.content = None;
                    synthesis.encrypted_content = None;
                }
                strand.updated_by.clone_from(&updated_by);
                strand.updated_at = Some(operation.created_at);
                return ProjectionEffect::StrandLifecycle {
                    strand_id: object_ref,
                    new_state: ObjectLifecycleState::Redacted,
                };
            }
            if let Some(morph) = self.morphs.get_mut(&object_ref) {
                morph.state = ObjectLifecycleState::Redacted;
                morph.state_changed_at = Some(operation.created_at);
                // Same clearing obligation as the Strand branch above.
                morph.content = None;
                morph.encrypted_content = None;
                morph.updated_by.clone_from(&updated_by);
                morph.updated_at = Some(operation.created_at);
                return ProjectionEffect::MorphLifecycle {
                    morph_id: object_ref,
                    new_state: ObjectLifecycleState::Redacted,
                };
            }
            if object_ref.starts_with("ak:strand:") || object_ref.starts_with("ak:morph:") {
                return self.queue_pending_replay(
                    object_ref,
                    operation,
                    "redaction_object_unknown",
                );
            }
        }

        ProjectionEffect::MessageRedacted {
            event_id: resolved_message
                .map(|message| message.event_id)
                .unwrap_or(target),
        }
    }

    pub(crate) fn apply_reaction_add(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let event_id = reaction_target_event_id(operation).unwrap_or_default();
        let actor = operation
            .payload
            .get("actor")
            .and_then(|v| v.as_str())
            .map_or_else(|| operation.context.sender.to_string(), ToOwned::to_owned);
        let key = operation
            .payload
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if event_id.is_empty() || actor.is_empty() || key.is_empty() {
            return ProjectionEffect::Ignored;
        }

        let reaction = ReactionState {
            actor: actor.clone(),
            key: key.clone(),
            active: true,
            created_at: now,
        };
        self.reactions
            .entry(event_id.clone())
            .or_default()
            .entry(actor.clone())
            .or_default()
            .insert(key.clone(), reaction);

        ProjectionEffect::ReactionChanged {
            event_id,
            actor,
            key,
            active: true,
        }
    }

    pub(crate) fn apply_reaction_remove(&mut self, operation: &Operation) -> ProjectionEffect {
        let event_id = reaction_target_event_id(operation).unwrap_or_default();
        let actor = operation
            .payload
            .get("actor")
            .and_then(|v| v.as_str())
            .map_or_else(|| operation.context.sender.to_string(), ToOwned::to_owned);
        let key = operation
            .payload
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if event_id.is_empty() || actor.is_empty() || key.is_empty() {
            return ProjectionEffect::Ignored;
        }

        if let Some(event_reactions) = self.reactions.get_mut(&event_id)
            && let Some(actor_reactions) = event_reactions.get_mut(&actor)
        {
            actor_reactions.remove(&key);
        }

        ProjectionEffect::ReactionChanged {
            event_id,
            actor,
            key,
            active: false,
        }
    }

    pub(crate) fn apply_rsvp_set(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(event_ref) = operation.payload.get("event_ref").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "rsvp_event_ref_missing".to_owned(),
            };
        };
        let Some(entry) = operation.payload.get("entry") else {
            return ProjectionEffect::Rejected {
                reason: "rsvp_entry_missing".to_owned(),
            };
        };
        // The whole entry is the state model value, so it has to be a complete,
        // schema-valid object before it can become a register write.
        let parsed_entry = match serde_json::from_value::<
            arkret_models_collaboration::objects::productivity::RsvpEntry,
        >(entry.clone())
        {
            Ok(parsed) => parsed,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: "rsvp_entry_invalid".to_owned(),
                };
            }
        };
        if parsed_entry.validate().is_err() {
            return ProjectionEffect::Rejected {
                reason: "rsvp_entry_invalid".to_owned(),
            };
        }
        let _ = &parsed_entry;
        let Some(strand) = self.strands.get(event_ref) else {
            return self.queue_pending_replay(
                event_ref.to_owned(),
                operation,
                "rsvp_event_unknown",
            );
        };
        if strand.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "rsvp_event_not_active".to_owned(),
            };
        }
        if strand.realm_id != operation.realm_id.as_str() {
            return ProjectionEffect::Rejected {
                reason: "rsvp_event_cross_realm".to_owned(),
            };
        }
        if !strand
            .schema_refs
            .iter()
            .any(|schema| schema == arkret_wire::SchemaId::CALENDAR_EVENT_V1)
        {
            return ProjectionEffect::Rejected {
                reason: "rsvp_event_not_calendar".to_owned(),
            };
        }
        let occurrence = match operation.payload.get("occurrence") {
            Some(Value::Null) | None => None,
            Some(Value::String(value)) => Some(value.clone()),
            Some(_) => {
                return ProjectionEffect::Rejected {
                    reason: "rsvp_occurrence_invalid".to_owned(),
                };
            }
        };
        // The cell subject derives from the signed occurrence, so a
        // non-canonical key is rejected rather than repaired: rewriting it
        // here would address a different cell than the one the Event promised.
        if let Some(key) = &occurrence
            && arkret_models_collaboration::objects::productivity::validate_canonical_occurrence_key(
                key,
            )
            .is_err()
        {
            return ProjectionEffect::Rejected {
                reason: "rsvp_occurrence_not_canonical".to_owned(),
            };
        }
        let actor_id = operation_actor_id(operation);
        let key = (event_ref.to_owned(), occurrence.clone(), actor_id.clone());
        let source_identity_matches =
            arkret_wire::EventId::from_event_digest(&operation.context.canonical_event_digest)
                .is_ok_and(|derived| derived == operation.context.event_id);
        if !source_identity_matches {
            return ProjectionEffect::Rejected {
                reason: "rsvp_event_identity_mismatch".to_owned(),
            };
        }
        // Every RSVP for one `(event_ref, occurrence, actor_id)` rides the
        // same commit stream, so the newest accepted write is the current one.
        let source_event_id = operation.context.event_id.clone();
        self.rsvps.insert(
            key,
            RsvpProjection {
                event_ref: event_ref.to_owned(),
                occurrence: occurrence.clone(),
                actor_id: actor_id.clone(),
                entry: entry.clone(),
                source_event_id: source_event_id.clone(),
                source_event_digest: operation.context.canonical_event_digest.clone(),
                updated_at: now,
            },
        );

        ProjectionEffect::RsvpProjected {
            event_ref: event_ref.to_owned(),
            actor_id,
            occurrence,
            source_event_id: source_event_id.to_string(),
        }
    }

    pub(crate) fn apply_pin(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(pin_scope) = operation.payload.get("pin_scope") else {
            return ProjectionEffect::Rejected {
                reason: "pin_scope_missing".to_owned(),
            };
        };
        let Some(pin_scope_key) = pin_scope_key(pin_scope) else {
            return ProjectionEffect::Rejected {
                reason: "pin_scope_invalid".to_owned(),
            };
        };
        let Some(target_ref) = operation.payload.get("target_ref").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "pin_target_ref_missing".to_owned(),
            };
        };
        if let Err(reason) = self.check_pin_scope_safety(operation) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Err(reason) = validate_encrypted_projection_field(
            operation,
            "note",
            "pin_note_encrypted_payload_required",
        ) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let map_key = (pin_scope_key.clone(), target_ref.to_owned());
        let operation_kind = crate::kinds::canonical_kind_for_operation(operation);
        if operation_kind == Some(arkret_wire::EventKind::PinRemove) {
            if let Some(pin) = self.pins.get_mut(&map_key) {
                pin.active = false;
                pin.updated_at = now;
            }
            return ProjectionEffect::PinProjected {
                pin_scope_key,
                target_ref: target_ref.to_owned(),
                active: false,
            };
        }
        let Some(rank) = operation.payload.get("rank").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "pin_rank_missing".to_owned(),
            };
        };
        let previous = self.pins.get(&map_key);
        let note = if operation_kind == Some(arkret_wire::EventKind::PinReorder) {
            previous.and_then(|pin| pin.note.clone())
        } else {
            operation.payload.get("note").cloned()
        };
        self.pins.insert(
            map_key,
            PinProjection {
                pin_scope: pin_scope.clone(),
                target_ref: target_ref.to_owned(),
                rank: Some(rank.to_owned()),
                note,
                actor_id: operation_actor_id(operation),
                active: true,
                updated_at: now,
            },
        );
        ProjectionEffect::PinProjected {
            pin_scope_key,
            target_ref: target_ref.to_owned(),
            active: true,
        }
    }

    pub fn check_pin_scope_safety(&self, operation: &Operation) -> Result<(), &'static str> {
        if !crate::kinds::canonical_kind_for_operation(operation)
            .is_some_and(|kind| arkret_wire::events::kinds::is_pin_kind(&kind))
        {
            return Ok(());
        }
        let Some(pin_scope) = operation.payload.get("pin_scope") else {
            return Ok(());
        };
        let Some(target_ref) = operation.payload.get("target_ref").and_then(Value::as_str) else {
            return Ok(());
        };
        let Some(pin_home) = self.pin_scope_effective_scope(pin_scope) else {
            return Err("not_found");
        };
        let Some(target_scope) = self.pin_target_effective_scope(target_ref) else {
            return Err("not_found");
        };
        if pin_home.realm_id != target_scope.realm_id {
            return Err("not_found");
        }
        if let Some(target_circle_id) = target_scope.scope_circle_id.as_deref()
            && pin_home.scope_circle_id.as_deref() != Some(target_circle_id)
        {
            return Err("not_found");
        }
        Ok(())
    }

    pub fn pin_target_is_visible_for_projection(&self, target_ref: &str) -> bool {
        self.pin_target_effective_scope(target_ref).is_some()
    }

    fn pin_scope_effective_scope(&self, pin_scope: &Value) -> Option<PinEffectiveScope> {
        let (kind, id) = pin_scope_parts(pin_scope)?;
        match kind {
            "realm" => {
                let live =
                    self.realm_states.contains_key(id) || self.realm_create_log(id).is_some();
                (live && !self.realm_is_in_terminal_state(id)).then(|| PinEffectiveScope {
                    realm_id: id.to_owned(),
                    scope_circle_id: None,
                })
            }
            "circle" => {
                let circle = self.circles.get(id)?;
                (circle.state == CircleLifecycleState::Active).then(|| PinEffectiveScope {
                    realm_id: circle.realm_id.clone(),
                    scope_circle_id: Some(circle.circle_id.clone()),
                })
            }
            "strand" => {
                let strand = self.strands.get(id)?;
                (!strand.state.is_terminal()).then(|| PinEffectiveScope {
                    realm_id: strand.realm_id.clone(),
                    scope_circle_id: strand.scope_circle_id.clone(),
                })
            }
            "space" => {
                let space = self.space_containers.get(id)?;
                (space.state != SpaceContainerLifecycleState::Tombstoned).then(|| {
                    PinEffectiveScope {
                        realm_id: space.realm_id.clone(),
                        scope_circle_id: space.scope_circle_id.clone(),
                    }
                })
            }
            _ => None,
        }
    }

    fn pin_target_effective_scope(&self, target_ref: &str) -> Option<PinEffectiveScope> {
        if let Some(message) = self.message_by_target_ref(target_ref) {
            if self.pin_target_is_blocked_by_moderation(target_ref) {
                return None;
            }
            if message.redacted_at.is_some() {
                return None;
            }
            return Some(PinEffectiveScope {
                realm_id: message.realm_id.clone(),
                scope_circle_id: self.strand_scope_circle_id(&message.thread_id),
            });
        }
        if let Some(strand) = self.strands.get(target_ref) {
            if self.pin_target_is_blocked_by_moderation(target_ref) {
                return None;
            }
            return (!strand.state.is_terminal()).then(|| PinEffectiveScope {
                realm_id: strand.realm_id.clone(),
                scope_circle_id: strand.scope_circle_id.clone(),
            });
        }
        if let Some(space) = self.space_containers.get(target_ref) {
            if self.pin_target_is_blocked_by_moderation(target_ref) {
                return None;
            }
            return (space.state != SpaceContainerLifecycleState::Tombstoned).then(|| {
                PinEffectiveScope {
                    realm_id: space.realm_id.clone(),
                    scope_circle_id: space.scope_circle_id.clone(),
                }
            });
        }
        if let Some(morph) = self.morphs.get(target_ref) {
            if self.pin_target_is_blocked_by_moderation(target_ref) {
                return None;
            }
            return (!morph.state.is_terminal()).then(|| PinEffectiveScope {
                realm_id: morph.realm_id.clone(),
                scope_circle_id: None,
            });
        }
        if let Some(relation) = self.relations.get(target_ref) {
            if self.pin_target_is_blocked_by_moderation(target_ref) {
                return None;
            }
            return relation.is_active().then(|| PinEffectiveScope {
                realm_id: relation.realm_id.clone(),
                scope_circle_id: None,
            });
        }
        None
    }

    fn pin_target_is_blocked_by_moderation(&self, target_ref: &str) -> bool {
        self.effective_moderation_verdict(target_ref) != "none"
    }
}

fn validate_encrypted_projection_field(
    operation: &Operation,
    field: &str,
    reason: &'static str,
) -> Result<(), &'static str> {
    let Some(value) = operation.payload.get(field) else {
        return Ok(());
    };
    if encrypted_projection_field_matches_operation(value, operation) {
        Ok(())
    } else {
        Err(reason)
    }
}

fn encrypted_projection_field_matches_operation(value: &Value, operation: &Operation) -> bool {
    let Some(kind) = crate::kinds::canonical_kind_for_operation(operation) else {
        return false;
    };
    let Ok(envelope) = arkret_models_crypto::parse_and_validate_encrypted_envelope(value.clone())
    else {
        return false;
    };
    let reaction = matches!(
        kind.as_str(),
        arkret_wire::event_kind_str::REACTION_ADD | arkret_wire::event_kind_str::REACTION_REMOVE
    );
    envelope.encryption_context.routing_context().is_some() == reaction
}

struct PinEffectiveScope {
    realm_id: String,
    scope_circle_id: Option<String>,
}

/// Reduce one poll response against its poll definition.
///
/// JSON Schema cannot compare a response to the poll it references, so
/// `max_selection_count` and answer-id membership are checked here
/// (`content-block-poll.schema.json#/$defs/poll_body`).
fn validate_poll_selections(
    selections: &[String],
    valid: &BTreeSet<String>,
    max_selection_count: usize,
) -> std::result::Result<Vec<String>, &'static str> {
    if selections.is_empty() {
        return Err("poll_selection_empty");
    }
    if selections.len() > max_selection_count {
        return Err("poll_selection_over_max");
    }
    let mut selected = Vec::with_capacity(selections.len());
    let mut seen = BTreeSet::new();
    for selection in selections {
        if !valid.contains(selection) {
            return Err("poll_selection_unknown_answer");
        }
        if !seen.insert(selection.clone()) {
            return Err("poll_selection_duplicate");
        }
        selected.push(selection.clone());
    }
    Ok(selected)
}
