//! Read-only `ProjectionState` query helpers: message / reaction / poll /
//! relation / membership lookups plus the cell-keyed Realm policy readers.
//! Inherent-impl block on `ProjectionState`; methods resolve by type, so
//! cross-family `self.apply_*` / `self.check_*` calls are unaffected.

use arkret_models_collaboration::governance::membership_invite::JoinGateProof;

use super::*;

/// Internal hand-off from semantic preflight to the durable Event transaction.
///
/// This is deliberately not an authority result: it records only which
/// branch of the already-validated join-policy combinator still needs the
/// PostgreSQL transaction to supply the `parent_membership` verdict for.  The
/// digest pins the exact policy the proof-bearing gates were evaluated
/// against; storage must lock that policy and reject if it changed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeferredParentMembershipAdmission {
    pub policy_digest: arkret_wire::Hash,
    pub require_joined_source: bool,
}

impl ProjectionState {
    pub(crate) fn message_by_target_ref(&self, target_ref: &str) -> Option<&MessageState> {
        // Classify by canonical typed id, not by kind prefix: `ak:event:x` is
        // not an Event id, so it must not take the Event-keyed branch.
        if arkret_identifiers::MessageId::new(target_ref).is_ok() {
            return self
                .messages
                .values()
                .find(|message| message.message_id == target_ref)
                .or_else(|| self.messages.get(target_ref))
                .or_else(|| {
                    let event_id = message_event_id_from_ref(target_ref);
                    self.messages.get(&event_id)
                });
        }
        if arkret_identifiers::EventId::new(target_ref).is_ok() {
            return self.messages.get(target_ref);
        }
        self.messages.get(target_ref).or_else(|| {
            let event_id = message_event_id_from_ref(target_ref);
            self.messages.get(&event_id).or_else(|| {
                self.messages
                    .values()
                    .find(|message| message.message_id == target_ref)
            })
        })
    }

    pub fn redaction_cell_for_message(
        &self,
        message: &MessageState,
    ) -> Option<&RedactionCellValue> {
        self.redaction_cells
            .get(&message.event_id)
            .or_else(|| self.redaction_cells.get(&message.message_id))
            .or_else(|| {
                message
                    .revision_of
                    .as_deref()
                    .and_then(|original_id| self.redaction_cells.get(original_id))
            })
    }
}

impl ProjectionState {
    // ── Query helpers ──

    /// Get all non-redacted messages for a Realm, sorted by creation time.
    pub fn messages_for_realm(&self, realm_id: &str) -> Vec<&MessageState> {
        let superseded = self.superseded_message_ids();
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| {
                m.realm_id == realm_id
                    && !superseded.contains(m.event_id.as_str())
                    && self.redaction_cell_for_message(m).is_none()
            })
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    /// Get messages for a Realm including redacted rows, sorted by creation
    /// time. Superseded revisions are still dropped (only the latest revision
    /// of a message survives). The message stream (sync timeline) uses this so
    /// a redacted message keeps its slot and can be surfaced as a per-message
    /// tombstone (strand-and-message.md §9) instead of vanishing — the read
    /// path replaces its body with the redaction tombstone before emitting.
    pub fn messages_for_realm_including_redacted(&self, realm_id: &str) -> Vec<&MessageState> {
        let superseded = self.superseded_message_ids();
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| m.realm_id == realm_id && !superseded.contains(m.event_id.as_str()))
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    /// Get messages for a thread, sorted by creation time.
    pub fn messages_for_thread(&self, thread_id: &str) -> Vec<&MessageState> {
        let superseded = self.superseded_message_ids();
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| {
                m.thread_id == thread_id
                    && !superseded.contains(m.event_id.as_str())
                    && self.redaction_cell_for_message(m).is_none()
            })
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    fn superseded_message_ids(&self) -> std::collections::BTreeSet<&str> {
        self.messages
            .values()
            .filter_map(|message| message.revision_of.as_deref())
            .collect()
    }

    /// Resolve a Message's `(created_at, sender, thread_id)` by target ref,
    /// accepting either the `ak:event:` storage id or the `ak:message:`
    /// object-ref form. Used by the constraint-schema.md §14.2 edit/redact
    /// window evaluator, which needs the original Message `created_at` to
    /// measure the elapsed window. Returns `None` for unknown targets.
    pub fn message_origin(
        &self,
        target_ref: &str,
    ) -> Option<(chrono::DateTime<chrono::Utc>, String, String)> {
        let msg = self.message_by_target_ref(target_ref)?;
        Some((msg.created_at, msg.sender.clone(), msg.thread_id.clone()))
    }

    /// Resolve the `realm_id` (effective scope) of a Message by target ref,
    /// accepting the `ak:message:` object-ref or `ak:event:` storage id.
    /// Used by the strand-and-message.md §9.8.2 reaction scope check. Returns
    /// `None` for unknown targets (the reducer's dependency handling then
    /// keeps the reaction pending).
    pub fn message_realm(&self, target_ref: &str) -> Option<String> {
        self.message_by_target_ref(target_ref)
            .map(|msg| msg.realm_id.clone())
    }

    /// Resolve the Circle scope inherited by an event targeting a Message.
    pub fn message_circle_scope(&self, target_ref: &str) -> Option<String> {
        self.message_by_target_ref(target_ref)
            .and_then(|message| message.content.get("scope_circle_id"))
            .and_then(Value::as_str)
            .filter(|circle_id| circle_id.starts_with("ak:circle:"))
            .map(ToOwned::to_owned)
    }

    /// Projection-layer view of a single message that
    /// consults the parallel `redaction` cell. Returns:
    ///   - `Some(view)` with `content = Some(_)` for live messages (no redaction cell set, or set
    ///     back to null);
    ///   - `Some(view)` with `content = None` + `redaction = Some(_)` when the parallel cell is in
    ///     effect — caller renders the tombstone;
    ///   - `None` if no underlying [`MessageState`] is known.
    ///
    /// The ordered-log historical entry id is preserved unchanged so
    /// federation / sync replay still emits the same `event_id`.
    pub fn projected_message(
        &self,
        event_id: &str,
        viewer_is_author: bool,
    ) -> Option<ProjectedMessageView> {
        let msg = self.messages.get(event_id)?;
        let redaction = self.redaction_cell_for_message(msg).cloned();
        let content = match (&redaction, viewer_is_author) {
            // No redaction in effect — full payload visible.
            (None, _) => Some(msg.content.clone()),
            // Author keeps the audit-view of the original payload.
            (Some(_), true) => Some(msg.content.clone()),
            // Other members see the tombstone.
            (Some(_), false) => None,
        };
        Some(ProjectedMessageView {
            event_id: msg.event_id.clone(),
            realm_id: msg.realm_id.clone(),
            sender: msg.sender.clone(),
            thread_id: msg.thread_id.clone(),
            created_at: msg.created_at,
            content,
            redaction,
        })
    }

    /// Get active reactions for an event.
    pub fn reactions_for_event(&self, event_id: &str) -> Vec<&ReactionState> {
        self.reactions
            .get(event_id)
            .map(|by_actor| {
                by_actor
                    .values()
                    .flat_map(|by_key| by_key.values().filter(|r| r.active))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn poll(&self, poll_id: &str) -> Option<&PollState> {
        self.polls.get(&arkret_wire::MessageId::new(poll_id).ok()?)
    }

    /// Get members of a Realm currently in `state="join"`.
    /// For state-specific queries use [`members_in_state`].
    pub fn members_of_realm(&self, realm_id: &str) -> Vec<&ColandMembershipState> {
        self.members_in_state(realm_id, "join")
    }

    /// All `ColandMembershipState` entries for a Realm whose transition state matches
    /// `state` (`invite` / `join` / `leave` / `ban` / `knock`).
    pub fn members_in_state(&self, realm_id: &str, state: &str) -> Vec<&ColandMembershipState> {
        self.members
            .iter()
            .filter(|((sid, _), m)| sid == realm_id && m.state == state)
            .map(|(_, m)| m)
            .collect()
    }

    /// Look up a single `(realm_id, actor_id)` member entry.
    pub fn member(&self, realm_id: &str, actor_id: &str) -> Option<&ColandMembershipState> {
        self.members
            .get(&(realm_id.to_owned(), actor_id.to_owned()))
    }

    pub fn agent_membership_binding(
        &self,
        realm_id: &str,
        agent_id: &str,
    ) -> Option<
        &arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding,
    >{
        self.agent_membership_bindings
            .get(&(realm_id.to_owned(), agent_id.to_owned()))
    }

    /// Deterministic membership/lifecycle half of Agent
    /// effective membership. Callers that authorize Agent activity must also
    /// verify the durable provision/accountability binding owned by the
    /// identity service.
    pub fn effective_agent_membership_base(&self, realm_id: &str, agent_id: &str) -> bool {
        let Ok(arkret_wire::ActorId::Account { .. }) =
            serde_json::from_str::<arkret_wire::ActorId>(agent_id)
        else {
            return false;
        };
        let Some(agent) = self.member(realm_id, agent_id) else {
            return false;
        };
        if agent.state != "join"
            || self.agent_lifecycles.get(agent_id)
                != Some(&arkret_models_collaboration::agent_operations::AgentLifecycleState::Active)
        {
            return false;
        }
        let Some(binding) = self.agent_membership_binding(realm_id, agent_id) else {
            return false;
        };
        let controller_actor_key =
            arkret_wire::ActorId::account(binding.controller_account_id.clone()).to_string();
        let Some(controller) = self.member(realm_id, &controller_actor_key) else {
            return false;
        };
        controller.state == "join"
            && controller.membership_event_ref.as_deref()
                == Some(binding.controller_membership_generation_ref.as_str())
            && controller.member == controller_actor_key
    }

    /// Current membership transition state of one actor in one Realm.
    pub fn member_transition_state(&self, realm_id: &str, actor_id: &str) -> Option<String> {
        let actor = serde_json::from_str::<arkret_wire::ActorId>(actor_id).ok()?;
        let actor_key = actor.canonical_key().ok()?;
        self.facet_value(realm_id, &FacetRef::new(facet::MEMBER_STATE, actor_key))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    // ── Facet query helpers ──

    /// Settled value of a Realm-singleton facet.
    pub fn realm_facet_value(&self, realm_id: &str, facet: &str) -> Option<&Value> {
        self.facet_value(realm_id, &FacetRef::singleton(facet))
    }

    /// Cached value for this exact scope; absence is not an authorization proof.
    pub fn read_receipt_policy_value(&self, scope: &arkret_wire::ScopeRef) -> Option<&Value> {
        let realm = match scope {
            arkret_wire::ScopeRef::Realm { realm_id }
            | arkret_wire::ScopeRef::Circle { realm_id, .. } => realm_id,
            _ => return None,
        };
        let subject =
            String::from_utf8(arkret_canonical::canonical_json_bytes(scope).ok()?).ok()?;
        self.facet_value(
            realm.as_str(),
            &FacetRef::new(facet::SCOPE_READ_RECEIPT_POLICY, subject),
        )
    }

    // ── Realm lifecycle facet helpers ──

    /// Effective display profile of the Realm.
    pub fn realm_profile_value(&self, realm_id: &str) -> Option<&Value> {
        self.realm_facet_value(realm_id, facet::REALM_PROFILE)
    }

    /// Accepted `ak.realm.create` entries, oldest first.
    pub fn realm_create_log(&self, realm_id: &str) -> Option<&[Value]> {
        match self.realm_facet_value(realm_id, facet::REALM_CREATE)? {
            Value::Array(entries) => Some(entries.as_slice()),
            _ => None,
        }
    }

    /// Immutable identity/security genesis value projected by
    /// `ak.realm.create`.
    pub fn realm_genesis_value(&self, realm_id: &str) -> Option<&Value> {
        self.realm_facet_value(realm_id, facet::REALM_GENESIS)
    }

    /// Identifies the registered Direct Conversation Realm role from the
    /// immutable genesis singleton.
    /// Unknown, incomplete, or malformed role declarations fail closed and
    /// never fall back to member-count, title, category, or tag heuristics.
    pub fn realm_is_direct_conversation(&self, realm_id: &str) -> bool {
        self.realm_genesis_value(realm_id)
            .and_then(|object| object.get("purpose"))
            .and_then(Value::as_str)
            == Some("direct_conversation")
    }

    /// True once an accepted `ak.realm.destroy` has written the facet.
    pub fn realm_is_destroyed(&self, realm_id: &str) -> bool {
        self.realm_facet_value(realm_id, facet::REALM_DESTROY)
            .is_some()
    }

    /// True once an accepted `ak.realm.tombstone` has written the facet.
    pub fn realm_is_tombstoned(&self, realm_id: &str) -> bool {
        self.realm_facet_value(realm_id, facet::REALM_TOMBSTONE)
            .is_some()
    }

    /// Stream-F (Wave 1B) — true if the Realm is in ANY terminal state
    /// (tombstoned OR destroyed). The wire-layer
    /// `terminal_realm_check` consults this to reject non-audit
    /// writes against terminal Realms. Spec
    /// `realm-and-space.md` §2.5 / §2.5.1.
    pub fn realm_is_in_terminal_state(&self, realm_id: &str) -> bool {
        if let Some(s) = self.realm_states.get(realm_id)
            && s.terminal_state.is_some()
        {
            return true;
        }
        // Fall back to facet presence so a Station that hydrated the
        // projection without rebuilding `realm_states` still sees terminal
        // state.
        self.realm_is_tombstoned(realm_id) || self.realm_is_destroyed(realm_id)
    }

    /// A gate facet blocks unless it is absent or explicitly `false`. Any
    /// other shape fails closed.
    fn realm_facet_blocks(&self, realm_id: &str, facet: &str) -> bool {
        !matches!(
            self.realm_facet_value(realm_id, facet),
            None | Some(Value::Bool(false))
        )
    }

    pub fn realm_is_frozen(&self, realm_id: &str) -> bool {
        self.realm_facet_blocks(realm_id, facet::REALM_FREEZE)
    }

    pub fn realm_is_archived(&self, realm_id: &str) -> bool {
        self.realm_facet_blocks(realm_id, facet::REALM_ARCHIVE)
    }

    /// Unknown Realms and conflicting/malformed gates fail closed.
    pub fn realm_ordinary_writes_blocked(&self, realm_id: &str) -> bool {
        (!self.realm_states.contains_key(realm_id) && self.realm_genesis_value(realm_id).is_none())
            || self.realm_is_archived(realm_id)
            || self.realm_is_frozen(realm_id)
    }

    pub fn realm_policy_bundle_value(&self, realm_id: &str) -> Option<&Value> {
        self.realm_facet_value(realm_id, facet::REALM_POLICY_BUNDLE)
    }

    pub fn realm_join_policy_value(&self, realm_id: &str) -> Option<&Value> {
        self.realm_policy_bundle_value(realm_id)?.get("join_policy")
    }

    /// Submit-time and reducer-time hard gate for Join Policy.
    /// `principal_admission` and `cooldown` are non-bypassable
    /// preconditions; remaining gates are evaluated with `combinator`.
    pub fn check_membership_join_admission(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        self.check_membership_join_admission_with_parent_verdict(operation, false)
    }

    /// Validate every projection-owned join gate while deferring only the
    /// authoritative `parent_membership` read to the durable transaction.
    ///
    /// Running the deterministic policy evaluator with both possible parent
    /// verdicts tells persistence whether a joined source is decisive (`all`,
    /// or an `any` whose other proof gates failed) or whether only the durable
    /// dependency cut must be revalidated because another `any` branch passed.
    pub fn prepare_parent_membership_admission(
        &self,
        operation: &Operation,
    ) -> Result<Option<DeferredParentMembershipAdmission>, &'static str> {
        let Some(arkret_wire::EventKind::MemberState) =
            crate::kinds::canonical_kind_for_operation(operation)
        else {
            self.check_membership_join_admission(operation)?;
            return Ok(None);
        };
        let payload = operation
            .typed_payload::<arkret_wire::event_spec::MemberState>()
            .map_err(|_| "gate_check_failed")?;
        if payload.membership
            != arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join
            || self
                .member(operation.realm_id.as_str(), &payload.member_id.to_string())
                .is_some_and(|membership| membership.state == "join")
        {
            self.check_membership_join_admission(operation)?;
            return Ok(None);
        }
        let Some(join_policy) = self.realm_join_policy_value(operation.realm_id.as_str()) else {
            self.check_membership_join_admission(operation)?;
            return Ok(None);
        };
        let has_parent = join_policy
            .get("gates")
            .and_then(Value::as_array)
            .is_some_and(|gates| {
                gates.iter().any(|gate| {
                    gate.get("kind").and_then(Value::as_str) == Some("parent_membership")
                })
            });
        if !has_parent {
            self.check_membership_join_admission(operation)?;
            return Ok(None);
        }
        let policy_digest = arkret_canonical::canonical_sha256(join_policy)
            .map_err(|_| "gate_check_failed")
            .and_then(|digest| arkret_wire::Hash::new(digest).map_err(|_| "gate_check_failed"))?;
        let require_joined_source =
            match self.check_membership_join_admission_with_parent_verdict(operation, false) {
                Ok(()) => false,
                Err("gate_check_failed") => {
                    self.check_membership_join_admission_with_parent_verdict(operation, true)?;
                    true
                }
                Err(reason) => return Err(reason),
            };
        Ok(Some(DeferredParentMembershipAdmission {
            policy_digest,
            require_joined_source,
        }))
    }

    fn check_membership_join_admission_with_parent_verdict(
        &self,
        operation: &Operation,
        parent_membership_allows: bool,
    ) -> Result<(), &'static str> {
        let kind = crate::kinds::canonical_kind_for_operation(operation);
        let (member, hard_gates_only) = match &kind {
            Some(arkret_wire::EventKind::MemberState) => {
                let payload = operation
                    .typed_payload::<arkret_wire::event_spec::MemberState>()
                    .map_err(|_| "gate_check_failed")?;
                if payload.membership
                    != arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join
                {
                    return Ok(());
                }
                (Some(payload.member_id.to_string()), false)
            }
            Some(arkret_wire::EventKind::InviteCreate) => {
                let payload = operation
                    .typed_payload::<arkret_wire::event_spec::InviteCreate>()
                    .map_err(|_| "gate_check_failed")?;
                (
                    Some(arkret_wire::ActorId::account(payload.invitee_account_id).to_string()),
                    true,
                )
            }
            Some(arkret_wire::EventKind::InviteAccept) => {
                (Some(operation.context.sender.to_string()), true)
            }
            _ => return Ok(()),
        };
        let member = member.as_deref();
        let Some(member) = member else {
            return Err("gate_check_failed");
        };
        if kind == Some(arkret_wire::EventKind::MemberState)
            && self
                .member(operation.realm_id.as_str(), member)
                .is_some_and(|membership| membership.state == "join")
        {
            // `join -> join` updates an existing member; it is not a new Realm
            // entry and therefore does not re-run entry gates or the join rule.
            return Ok(());
        }
        self.check_join_request_gates_with_parent_verdict(
            operation.realm_id.as_str(),
            member,
            hard_gates_only,
            operation.context.sender.to_string() == member,
            operation
                .payload
                .get("gate_proofs")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            operation.created_at,
            parent_membership_allows,
        )
    }

    /// The same entry gates govern request-authorized bootstrap disclosure.
    pub fn check_join_request_gates(
        &self,
        realm_id: &str,
        member: &str,
        hard_gates_only: bool,
        is_self_authored: bool,
        raw_proofs: &[Value],
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), &'static str> {
        self.check_join_request_gates_with_parent_verdict(
            realm_id,
            member,
            hard_gates_only,
            is_self_authored,
            raw_proofs,
            now,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn check_join_request_gates_with_parent_verdict(
        &self,
        realm_id: &str,
        member: &str,
        hard_gates_only: bool,
        is_self_authored: bool,
        raw_proofs: &[Value],
        now: chrono::DateTime<chrono::Utc>,
        parent_membership_allows: bool,
    ) -> Result<(), &'static str> {
        let join_rule = (!hard_gates_only).then(|| self.realm_default_join_rule(realm_id));
        if join_rule.is_some_and(|rule| matches!(rule, "invite" | "closed")) && is_self_authored {
            return Err("gate_check_failed");
        }
        // join-policy.md 2: `restricted` and `knock_restricted` are the two
        // rules whose admitted set is defined by the automatic gates. Without
        // a policy carrying one, the declared rule admits exactly what `public`
        // admits, which is the silent degradation this fails closed on.
        let automatic_gate_required =
            join_rule.is_some_and(|rule| matches!(rule, "restricted" | "knock_restricted"));
        let Some(join_policy) = self.realm_join_policy_value(realm_id) else {
            return if automatic_gate_required {
                Err("gate_check_failed")
            } else {
                Ok(())
            };
        };
        if let Err(reason) = validate_join_policy_payload(join_policy) {
            return if reason == "join_policy_duplicate_gate_id" {
                Err("join_policy_duplicate_gate_id")
            } else {
                Err("gate_check_failed")
            };
        }
        let Some(gates) = join_policy.get("gates").and_then(Value::as_array) else {
            return Err("gate_check_failed");
        };
        // `gate_proofs[]` items are the registered closed `join_gate_proof`
        // carrier. Parsing them here rather than probing member names is what
        // makes two implementations agree on what a proof even is: the private
        // shape this used to accept was never in the schema.
        if raw_proofs.len() > 16 {
            return Err("gate_check_failed");
        }
        let mut proofs: Vec<JoinGateProof> = Vec::with_capacity(raw_proofs.len());
        let mut seen_gate_ids = std::collections::BTreeSet::new();
        for raw in raw_proofs {
            let Ok(proof) = serde_json::from_value::<JoinGateProof>(raw.clone()) else {
                return Err("gate_check_failed");
            };
            if !seen_gate_ids.insert(proof.gate_id.clone()) {
                return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
            }
            proofs.push(proof);
        }
        // The digest every proof binds itself to: the accepted policy component
        // this join is evaluated against. A proof minted under an earlier
        // revision cannot be replayed into this one.
        let Ok(policy_digest) = arkret_canonical::canonical_sha256(join_policy)
            .map_err(|_| ())
            .and_then(|digest| arkret_wire::Hash::new(digest).map_err(|_| ()))
        else {
            return Err("gate_check_failed");
        };
        let Ok(applicant_actor_id) = serde_json::from_str::<arkret_wire::ActorId>(member) else {
            return Err("gate_check_failed");
        };
        for gate in gates {
            let Some(gate) = gate.as_object() else {
                return Err("gate_check_failed");
            };
            match gate.get("kind").and_then(Value::as_str) {
                Some("principal_admission") => {
                    // DID-method admission must be evaluated from the frozen
                    // registration and origin-service admission evidence
                    // selected by the exact principal authority pair. A
                    // projection's current did is not a substitute for
                    // that accepted pair binding.
                    let actor = serde_json::from_str::<arkret_wire::ActorId>(member)
                        .map_err(|_| "gate_check_failed")?;
                    let subject_class = match &actor {
                        arkret_wire::ActorId::Service { .. } => {
                            PrincipalAdmissionSubjectClass::Service
                        }
                        arkret_wire::ActorId::Account { .. }
                            if self.agent_lifecycles.contains_key(member)
                                || self
                                    .agent_membership_bindings
                                    .contains_key(&(realm_id.to_owned(), member.to_owned())) =>
                        {
                            PrincipalAdmissionSubjectClass::Agent
                        }
                        arkret_wire::ActorId::Account { .. } => {
                            PrincipalAdmissionSubjectClass::Human
                        }
                    };
                    if !principal_admission_gate_allows(gate, member, subject_class, None) {
                        return Err("gate_check_failed");
                    }
                }
                Some("cooldown") if self.cooldown_gate_blocks_join(gate, realm_id, member, now) => {
                    return Err("gate_check_failed");
                }
                _ => {}
            }
        }
        if hard_gates_only {
            return Ok(());
        }
        if !join_rule
            .is_some_and(|rule| matches!(rule, "knock" | "restricted" | "knock_restricted"))
        {
            return Ok(());
        }
        let mut normal_gates = gates
            .iter()
            .filter_map(Value::as_object)
            .filter(|gate| {
                !matches!(
                    gate.get("kind").and_then(Value::as_str),
                    Some("principal_admission" | "cooldown")
                )
            })
            .peekable();
        if normal_gates.peek().is_none() {
            return if automatic_gate_required {
                Err("gate_check_failed")
            } else {
                Ok(())
            };
        }
        match join_policy.get("combinator").and_then(Value::as_str) {
            Some("all") => {
                for gate in normal_gates {
                    if !self.join_gate_allows(
                        gate,
                        &proofs,
                        member,
                        &applicant_actor_id,
                        &policy_digest,
                        realm_id,
                        now,
                        parent_membership_allows,
                    ) {
                        return Err("gate_check_failed");
                    }
                }
                Ok(())
            }
            Some("any") => {
                for gate in normal_gates {
                    if self.join_gate_allows(
                        gate,
                        &proofs,
                        member,
                        &applicant_actor_id,
                        &policy_digest,
                        realm_id,
                        now,
                        parent_membership_allows,
                    ) {
                        return Ok(());
                    }
                }
                Err("gate_check_failed")
            }
            _ => Err("gate_check_failed"),
        }
    }

    pub fn realm_default_join_rule(&self, realm_id: &str) -> &str {
        self.realm_join_rules
            .get(realm_id)
            .map(String::as_str)
            .unwrap_or("invite")
    }

    fn cooldown_gate_blocks_join(
        &self,
        gate: &serde_json::Map<String, Value>,
        realm_id: &str,
        member: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let Some(min_interval) = gate
            .get("min_interval_since_leave")
            .and_then(Value::as_str)
            .and_then(parse_iso8601_duration)
        else {
            return true;
        };
        let Some(previous) = self.member(realm_id, member) else {
            return false;
        };
        previous.state == "leave" && now.signed_duration_since(previous.updated_at) < min_interval
    }

    /// One automatic gate's verdict.
    ///
    /// `parent_membership` takes no caller proof, but projection state is not
    /// its authority source; until durable transactional admission handles it,
    /// this path fails closed.
    /// The two proof-bearing kinds each require an item naming this gate whose
    /// binding tuple holds against this Realm, applicant and policy revision;
    /// a missing item gives the same verdict as a failing one, which is what
    /// keeps the outward answer non-enumerable.
    #[allow(clippy::too_many_arguments)]
    fn join_gate_allows(
        &self,
        gate: &serde_json::Map<String, Value>,
        proofs: &[JoinGateProof],
        _member: &str,
        applicant_actor_id: &arkret_wire::ActorId,
        policy_digest: &arkret_wire::Hash,
        realm_id: &str,
        event_created_at: chrono::DateTime<chrono::Utc>,
        parent_membership_allows: bool,
    ) -> bool {
        let kind = gate.get("kind").and_then(Value::as_str);
        if kind == Some("parent_membership") {
            // The ordinary public method always passes false.  The HTTP
            // admission lane may pass true only to determine whether the
            // already-validated non-parent gates leave this gate decisive;
            // PostgreSQL still has to lock and re-evaluate the authoritative
            // policy/link/tenure/member rows before any write is possible.
            return parent_membership_allows;
        }
        let Some(proof) = gate
            .get("gate_id")
            .and_then(Value::as_str)
            .and_then(|gate_id| gate_proof_for_gate(proofs, gate_id))
        else {
            return false;
        };
        // `max_proof_age` is only declared by `challenge_response`; a gate that
        // declares one it cannot parse has no evaluable freshness bound.
        let max_proof_age = match kind {
            Some("challenge_response") => match gate_max_proof_age(gate) {
                Some(age) => Some(age),
                None => return false,
            },
            _ => None,
        };
        if !join_gate_proof_binding_holds(
            proof,
            realm_id,
            applicant_actor_id,
            policy_digest,
            event_created_at,
            max_proof_age,
        ) {
            return false;
        }
        match kind {
            Some("challenge_response") => challenge_response_gate_allows(gate, proof),
            Some("claim_required") => claim_required_gate_has_proof(gate, proof),
            _ => false,
        }
    }

    pub fn realm_search_policy_value(&self, realm_id: &str) -> Option<&Value> {
        self.realm_facet_value(realm_id, facet::REALM_SEARCH_POLICY)
    }

    /// R3.1 — query realm links by direction and optional link_kind
    /// allow-list. Returns a Vec sorted by `(target_realm_id, link_kind)`
    /// so the response is stable across calls.
    ///
    /// `direction` controls which side(s) of the edge to return:
    /// `outbound` → edges where `realm_id == realm_id`, `inbound` →
    /// edges where `target_realm_id == realm_id`, `both` → both
    /// (outbound first, inbound second).
    pub fn realm_links_query(
        &self,
        realm_id: &str,
        direction: arkret_models_collaboration::governance::realm_governance::RealmLinkDirection,
        link_kind_allow: Option<&[String]>,
    ) -> Vec<RealmLinkState> {
        use arkret_models_collaboration::governance::realm_governance::RealmLinkDirection;
        let filter = |row: &&RealmLinkState| {
            link_kind_allow
                .map(|allow| allow.iter().any(|k| k == &row.link_kind))
                .unwrap_or(true)
        };
        let mut out: Vec<RealmLinkState> = Vec::new();
        if matches!(
            direction,
            RealmLinkDirection::Outbound | RealmLinkDirection::Both
        ) && let Some(rows) = self.realm_links.get(realm_id)
        {
            out.extend(rows.iter().filter(filter).cloned());
        }
        if matches!(
            direction,
            RealmLinkDirection::Inbound | RealmLinkDirection::Both
        ) && let Some(rows) = self.realm_links_inbound.get(realm_id)
        {
            out.extend(rows.iter().filter(filter).cloned());
        }
        out.sort_by(|a, b| {
            a.target_realm_id
                .cmp(&b.target_realm_id)
                .then(a.link_kind.cmp(&b.link_kind))
                .then(a.realm_id.cmp(&b.realm_id))
        });
        out
    }

    /// Profiles the Realm object declares in `schema_refs[]`.
    pub fn realm_schema_refs(&self, realm_id: &str) -> Vec<String> {
        self.realm_genesis_value(realm_id)
            .and_then(|genesis| genesis.get("schema_refs"))
            .and_then(Value::as_array)
            .map(|refs| {
                refs.iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Create-locked digest suite of the Realm.
    ///
    /// `models/realm-and-space.md` line 123 marks `digest_algorithm` optional
    /// on the Realm object, locked at create and defaulting to `sha256`, and
    /// `realm-genesis.schema.json` is closed without the property, so a
    /// conformant genesis declares nothing and the Realm runs the baseline
    /// suite. `None` therefore means "this Realm has no genesis facet yet",
    /// never "the genesis left the suite unknown".
    pub fn realm_digest_algorithm(&self, realm_id: &str) -> Option<String> {
        let genesis = self.realm_genesis_value(realm_id)?;
        Some(
            genesis
                .get("digest_algorithm")
                .and_then(Value::as_str)
                .unwrap_or("sha256")
                .to_owned(),
        )
    }

    /// The canonical MLS group id an accepted `ak.mls.genesis` installed for a Circle scope.
    pub fn circle_scope_mls_group_id(&self, circle_id: &str) -> Option<&str> {
        self.circles
            .get(circle_id)
            .and_then(|circle| circle.mls_group_ref.as_deref())
    }

    /// Whether the named Circle scope has accepted its own `ak.mls.genesis`.
    pub fn circle_scope_is_mls_activated(&self, circle_id: &str) -> bool {
        self.circle_scope_mls_group_id(circle_id).is_some()
    }

    /// Effective Realm `history_access` projected from its dedicated cell.
    pub fn realm_history_access(&self, realm_id: &str) -> Option<String> {
        self.realm_facet_value(realm_id, facet::REALM_HISTORY_ACCESS)
            .and_then(|value| {
                value
                    .get("value")
                    .and_then(Value::as_str)
                    .or_else(|| value.as_str())
            })
            .map(ToOwned::to_owned)
    }

    /// Read the create-locked Realm `security_class` from genesis.
    pub fn realm_security_class(&self, realm_id: &str) -> Option<String> {
        // Security class is create-locked and has no mutable fallback.
        if let Some(genesis) = self.realm_genesis_value(realm_id)
            && let Some(s) = genesis.get("security_class").and_then(Value::as_str)
        {
            return Some(s.to_owned());
        }
        None
    }

    /// Read the effective Realm federation policy from the policy bundle.
    pub fn realm_federation_policy(&self, realm_id: &str) -> Option<String> {
        self.realm_policy_bundle_value(realm_id)
            .and_then(|value| value.get("federation_policy"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }
}

fn gate_proof_for_gate<'a>(
    proofs: &'a [JoinGateProof],
    gate_id: &str,
) -> Option<&'a JoinGateProof> {
    proofs.iter().find(|proof| proof.gate_id == gate_id)
}
