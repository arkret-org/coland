use super::*;

fn principal_genesis_resolution_value(
    operation: &Operation,
    payload_object: Option<&serde_json::Map<String, Value>>,
) -> Result<Option<Value>, &'static str> {
    let Some(object) = payload_object else {
        return Ok(None);
    };
    if !matches!(
        object.get("purpose").and_then(Value::as_str),
        Some("principal_control" | "agent_control" | "applet_managed_control")
    ) {
        return Ok(None);
    }
    let commitment = object
        .get("initial_resolution")
        .cloned()
        .ok_or("identity_resolution_missing")?;
    let did = commitment
        .get("did")
        .and_then(Value::as_str)
        .ok_or("identity_resolution_invalid")?;
    let did = arkret_wire::Did::new(did.to_owned()).map_err(|_| "identity_resolution_invalid")?;
    let projected =
        arkret_wire::project_did_to_core_id(&did).map_err(|_| "identity_resolution_invalid")?;
    if &projected != operation.context.sender.signing_principal_id()
        || commitment
            .get("method_history_head")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || commitment
            .get("version_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err("identity_resolution_invalid");
    }
    let mut projection = commitment
        .as_object()
        .cloned()
        .ok_or("identity_resolution_invalid")?;
    projection.insert(
        "resolution_event_ref".to_owned(),
        Value::String(operation.context.accepted_event_id.to_string()),
    );
    projection.insert(
        "updated_at".to_owned(),
        Value::String(utc_timestamp_z(operation.created_at)),
    );
    Ok(Some(Value::Object(projection)))
}

/// Re-derive the registered `ak.component.realm.authority_root.v1` genesis
/// value from an `ak.realm.create` payload.
///
/// `realm-and-space.md` §2.5 makes this the sixth genesis write and the only
/// authority a Realm has at genesis: there is no founding grant. The value is
/// recomputed through the SDK's own projection type instead of being read off a
/// producer field, so a receiver can never be talked into a different
/// controller, epoch, or generation than the signed create payload derives.
fn genesis_authority_root_value(
    payload_object: Option<&serde_json::Map<String, Value>>,
    created_by: &arkret_wire::ActorId,
    event_id: &arkret_wire::EventId,
) -> Result<Value, &'static str> {
    let object = payload_object.ok_or("realm_authority_root_missing")?;
    let _governance_station_id = object
        .get("governance_station_id")
        .and_then(Value::as_str)
        .ok_or("realm_authority_root_missing")?;
    serde_json::to_value(arkret_wire::RealmAuthorityRootValue {
        controller_actor_id: created_by.clone(),
        controller_epoch: 0,
        authority_generation: 0,
        authority_event_ref: event_id.clone(),
    })
    .map_err(|_| "realm_authority_root_missing")
}

impl ProjectionState {
    /// Current value of this Realm's authority-root facet.
    ///
    /// The controller named here holds effective `ak.realm.owner`
    /// (`authz/capabilities.md` §3.2). `realm_states[..].owner` is a
    /// discardable presentation mirror and MUST NOT be consulted for
    /// authorization.
    pub fn realm_authority_root(&self, realm_id: &str) -> Option<&Value> {
        self.realm_facet_value(realm_id, facet::REALM_AUTHORITY_ROOT)
    }

    /// Apply an authority-root CAS transition. Owner transfer rotates the
    /// controller binding; authority reset advances the delegation generation.
    /// Governance-Station handoff is owned by the authority-commit service and
    /// never reaches this typed-current-result helper.
    pub(crate) fn apply_realm_authority_transition(
        &mut self,
        operation: &Operation,
        kind: arkret_wire::EventKind,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(root) = self.realm_authority_root(&realm_id).cloned() else {
            return ProjectionEffect::Rejected {
                reason: "realm_authority_root_missing".to_owned(),
            };
        };
        let controller_actor_id = root
            .get("controller_actor_id")
            .cloned()
            .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok());
        if controller_actor_id.as_ref() != Some(&operation.context.sender) {
            return ProjectionEffect::Rejected {
                reason: "realm_authority_controller_mismatch".to_owned(),
            };
        }
        let controller_epoch = root
            .get("controller_epoch")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let authority_generation = root
            .get("authority_generation")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let mut root = match root {
            Value::Object(root) => root,
            _ => {
                return ProjectionEffect::Rejected {
                    reason: "realm_authority_root_conflict".to_owned(),
                };
            }
        };
        // Both authority-root transitions compare-and-swap against the exact
        // typed current result digest carried in their signature.
        if operation.payload.get("realm_id").and_then(Value::as_str) != Some(realm_id.as_str()) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }
        let expected_digest = match arkret_canonical::canonical_sha256(&root) {
            Ok(digest) => digest,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: "realm_authority_root_conflict".to_owned(),
                };
            }
        };
        if operation
            .payload
            .get("expected_state_digest")
            .and_then(Value::as_str)
            != Some(expected_digest.as_str())
        {
            return ProjectionEffect::Rejected {
                reason: "realm_authority_root_conflict".to_owned(),
            };
        }

        match &kind {
            arkret_wire::EventKind::RealmOwnerTransfer => {
                let typed =
                    operation.typed_payload::<arkret_wire::event_spec::RealmOwnerTransfer>();
                let Ok(payload) = typed else {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                };
                // `authz/capabilities.md` section 3.2: the successor counter is
                // bounded by the `encoding.md` section 1 JSON safe-integer
                // ceiling and an overflow MUST fail closed with
                // `realm_authority_root_conflict` rather than wrap, saturate
                // or keep the old value.
                let Ok(successor_epoch) =
                    arkret_models_collaboration::events_payloads::realm::RealmOwnerTransferPayload::successor_controller_epoch(
                        controller_epoch,
                    )
                else {
                    return ProjectionEffect::Rejected {
                        reason: "realm_authority_root_conflict".to_owned(),
                    };
                };
                if self
                    .member(&realm_id, &payload.patch.controller_actor_id.to_string())
                    .is_none_or(|member| member.state != "join")
                    || serde_json::to_value(&payload.successor_acceptance)
                        .ok()
                        .is_none_or(|proof| match proof {
                            Value::String(value) => value.is_empty(),
                            Value::Object(value) => value.is_empty(),
                            _ => true,
                        })
                {
                    return ProjectionEffect::Rejected {
                        reason: "realm_authority_controller_mismatch".to_owned(),
                    };
                }
                let Ok(controller) = serde_json::to_value(&payload.patch.controller_actor_id)
                else {
                    return ProjectionEffect::Rejected {
                        reason: "realm_authority_root_conflict".to_owned(),
                    };
                };
                root.insert("controller_actor_id".to_owned(), controller);
                root.insert("controller_epoch".to_owned(), successor_epoch.into());
            }
            arkret_wire::EventKind::RealmAuthorityReset => {
                // `event-kind-registry.json` registers exactly one write for
                // `ak.realm.authority.reset`: `allowed_paths` is empty, the
                // payload carries no patch. Its exact accepted Event replaces
                // the anchor with the derived `authority_generation` successor.
                // `controller_actor_id` and `controller_epoch` are preserved
                // verbatim from the pre-state the digest above froze. Advancing
                // this generation is what invalidates every `realm_root`-rooted
                // delegation at once (`authz/capabilities.md` section 10).
                if serde_json::from_value::<
                    arkret_models_collaboration::events_payloads::realm::RealmAuthorityResetPayload,
                >(operation.payload.clone())
                .is_err()
                {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                }
                // Same JSON safe-integer ceiling as the transfer epoch; the
                // registry note on this kind names `realm_authority_root_conflict`
                // as the fail-closed verdict.
                let Ok(successor_generation) =
                    arkret_models_collaboration::events_payloads::realm::RealmAuthorityResetPayload::successor_authority_generation(
                        authority_generation,
                    )
                else {
                    return ProjectionEffect::Rejected {
                        reason: "realm_authority_root_conflict".to_owned(),
                    };
                };
                root.insert(
                    "authority_generation".to_owned(),
                    successor_generation.into(),
                );
                root.insert(
                    "authority_event_ref".to_owned(),
                    Value::String(operation.context.accepted_event_id.to_string()),
                );
            }
            _ => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        }

        self.set_realm_facet(&realm_id, facet::REALM_AUTHORITY_ROOT, Value::Object(root));
        ProjectionEffect::RealmLifecycle {
            realm_id,
            action: kind
                .as_str()
                .strip_prefix("ak.realm.")
                .unwrap_or(kind.as_str())
                .to_owned(),
        }
    }

    pub(crate) fn apply_membership(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let payload = match serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::MembershipPayload,
        >(operation.payload.clone())
        {
            Ok(payload) => payload,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        let new_state = match payload.membership {
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join => "join",
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Knock => "knock",
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Leave => "leave",
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Ban => "ban",
        };
        let member = payload.member_id.to_string();
        let realm_id = operation.realm_id.to_string();
        let current_state = self
            .member(&realm_id, &member)
            .map(|membership| membership.state.as_str())
            .unwrap_or("leave");
        let transition_allowed = matches!(
            (current_state, new_state),
            ("leave", "knock" | "join" | "ban")
                | ("knock", "join" | "leave" | "ban")
                | ("join", "join" | "leave" | "ban")
                | ("ban", "leave")
        );
        if !transition_allowed {
            return ProjectionEffect::Rejected {
                reason: "invalid_membership_transition".to_owned(),
            };
        }

        // Delivery is derived from the exact ActorId. Membership carries no
        // parallel routing binding or server sidecar.
        if new_state == "join"
            && let Err(reason) = self.check_membership_join_admission(operation)
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }

        self.project_accepted_membership(
            operation,
            &operation.payload,
            now,
            new_state.to_owned(),
            member,
            realm_id,
        )
    }

    /// Project the final creator-membership slot of an already-validated
    /// ordinary Realm bootstrap unit.
    ///
    /// The closed unit validator has established that this is the genesis
    /// actor's own initial `null -> join` write. Re-running the ordinary join
    /// gate here would reject every invite-only Realm before it can acquire
    /// its first member. Keep the bypass narrow by independently checking the
    /// accepted envelope actor and the receiver-derived transition write before
    /// materializing the membership projection.
    pub fn apply_validated_realm_bootstrap_membership(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        if operation.event_kind != arkret_wire::EventKind::MemberState {
            return ProjectionEffect::Rejected {
                reason: "out_of_order_bootstrap".to_owned(),
            };
        }
        let Ok(payload) = serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::MembershipPayload,
        >(operation.payload.clone()) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        let member = payload.member_id.to_string();
        if operation.context.sender != payload.member_id
            || payload.membership
                != arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join
            || self.member(operation.realm_id.as_str(), &member).is_some()
        {
            return ProjectionEffect::Rejected {
                reason: "out_of_order_bootstrap".to_owned(),
            };
        }

        self.restore_accepted_membership(operation, operation.created_at)
    }

    /// Project either explicit membership slot of an already-validated Direct
    /// Conversation founding unit.
    ///
    /// Both Events are authored by the founder: one names the peer and the
    /// final genesis membership slot names the founder. The closed
    /// four-Event validator has already established those relationships and
    /// the exact pair. Keep this reducer-side bootstrap bypass scoped to that
    /// caller context and independently require the Direct Conversation Realm
    /// role, registered reason, absent prior membership and derived transition write.
    pub fn apply_validated_direct_conversation_bootstrap_membership(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        if operation.event_kind != arkret_wire::EventKind::MemberState
            || !self.realm_is_direct_conversation(operation.realm_id.as_str())
        {
            return ProjectionEffect::Rejected {
                reason: "out_of_order_bootstrap".to_owned(),
            };
        }
        let Ok(payload) = serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::MembershipPayload,
        >(operation.payload.clone()) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        let member = payload.member_id.to_string();
        if payload.membership
                != arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join
            || payload.reason.as_deref() != Some("direct_conversation_bootstrap")
            || self.member(operation.realm_id.as_str(), &member).is_some()
        {
            return ProjectionEffect::Rejected {
                reason: "out_of_order_bootstrap".to_owned(),
            };
        }

        self.restore_accepted_membership(operation, operation.created_at)
    }

    /// Restore an already-accepted canonical membership Event into the
    /// reducer's structured cache.
    ///
    /// Admission policy, exact member identity and gate checks ran before the Event
    /// became canonical. Hydration must materialize that accepted truth rather
    /// than re-evaluate it against a partially rebuilt policy projection.
    pub fn restore_accepted_membership(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Ok(typed) = serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::MembershipPayload,
        >(operation.payload.clone()) else {
            return ProjectionEffect::Ignored;
        };
        let new_state = match typed.membership {
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join => "join",
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Knock => "knock",
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Leave => "leave",
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Ban => "ban",
        };
        let member = typed.member_id.to_string();
        self.project_accepted_membership(
            operation,
            &operation.payload,
            now,
            new_state.to_owned(),
            member,
            operation.realm_id.to_string(),
        )
    }

    fn project_accepted_membership(
        &mut self,
        operation: &Operation,
        payload: &Value,
        now: chrono::DateTime<chrono::Utc>,
        new_state: String,
        member: String,
        realm_id: String,
    ) -> ProjectionEffect {
        // Side-band data: `role` lives outside the transition cell and is captured
        // here for the structured cache. `joined_at` is set on the first
        // `join` transition; subsequent transitions preserve the original.
        let role = payload
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("member")
            .to_owned();
        let key = (realm_id.clone(), member.clone());
        let previous = self.members.get(&key);
        let invited_at = previous.and_then(|member| member.invited_at);
        let joined_at = match (new_state.as_str(), previous) {
            ("join", Some(previous)) if previous.state == "join" => previous.joined_at,
            ("join", _) => now,
            (_, Some(previous)) => previous.joined_at,
            _ => now,
        };
        let event_ref = Some(operation.context.event_id.to_string());

        if new_state == "join" {
            let binding = payload
                .get("agent_controller_binding")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok());
            match binding {
                Some(binding) => {
                    self.agent_membership_bindings.insert(key.clone(), binding);
                }
                None => {
                    self.agent_membership_bindings.remove(&key);
                }
            }
        } else if let Some(binding) = payload
            .get("agent_controller_binding")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
        {
            self.agent_membership_bindings.insert(key.clone(), binding);
        }

        // Update the structured cache with side-band + transition state mirror.
        self.members.insert(
            key.clone(),
            ColandMembershipState {
                member: member.clone(),
                realm_id: realm_id.clone(),
                state: new_state.to_owned(),
                role,
                membership_event_ref: event_ref,
                invited_at,
                joined_at,
                updated_at: now,
                reason: payload
                    .get("reason")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned),
            },
        );
        if matches!(new_state.as_str(), "leave" | "ban") {
            self.invalidate_realm_member_circle_visibility(&realm_id, &member);
        }

        // The facet subject is the complete tagged actor key (including its
        // Station binding); the Realm is the facet map's other key half.
        if let Ok(actor) = serde_json::from_value::<arkret_wire::ActorId>(
            payload.get("member_id").cloned().unwrap_or(Value::Null),
        ) && let Ok(actor_key) = actor.canonical_key()
        {
            self.set_facet(
                &realm_id,
                FacetRef::new(facet::MEMBER_STATE, actor_key),
                Value::String(new_state.to_owned()),
            );
        }

        // join-policy.md §7 — project the candidate profile-private
        // application / review / cancel sub-payloads carried on this
        // `ak.member.state` event into the application-review workflow cache.

        ProjectionEffect::MembershipChanged {
            realm_id,
            member,
            action: new_state.to_owned(),
        }
    }

    fn invalidate_realm_member_circle_visibility(&mut self, realm_id: &str, member: &str) {
        // Only the derived active set changes. Canonical Circle membership,
        // join provenance and Circle metadata remain authored by Circle Events.
        for circle in self
            .circles
            .values_mut()
            .filter(|circle| circle.realm_id == realm_id)
        {
            circle.members.remove(member);
        }
    }

    /// COT-06-004 — apply `ak.realm.set_default_strand`. Points the Realm's
    /// `default_strand_id` at `payload.strand_id`. The named Strand MUST already be
    /// projected in this Realm (else `failed_precondition` — no dangling
    /// pointer). Optional `expected_default_strand_id` is an optimistic-
    /// concurrency CAS guard: when present it MUST equal the current
    /// `default_strand_id` (or both null), else `cas_mismatch`.
    ///
    /// Authorization (actor holds `ak.realm.set_default_strand` / `ak.realm.admin`
    /// on the Realm, or owns it) is enforced at ingest in
    /// `routing::events::operations::policy::validate_set_default_strand_policy`,
    /// mirroring the ban / moderation capability gates. The reducer does the
    /// structural acceptance check only.
    pub(crate) fn apply_realm_set_default_strand(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(strand_id) = operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "set_default_strand_strand_id_missing".to_owned(),
            };
        };

        // failed_precondition: the target Strand MUST already be projected in
        // this Realm. Prevents a dangling default pointer.
        match self.strands.get(&strand_id) {
            Some(strand) if strand.realm_id == realm_id => {}
            Some(_) => {
                return ProjectionEffect::Rejected {
                    reason: "set_default_strand_strand_realm_mismatch".to_owned(),
                };
            }
            None => {
                return ProjectionEffect::Rejected {
                    reason: "failed_precondition".to_owned(),
                };
            }
        }

        // Optimistic-concurrency CAS guard. `expected_default_strand_id` is
        // `oneOf[strand_id, null]`: when the field is present (including an
        // explicit JSON null), it MUST match the current pointer.
        if let Some(expected) = operation.payload.get("expected_default_strand_id") {
            let current = self
                .realm_states
                .get(&realm_id)
                .and_then(|realm| realm.default_strand_id.as_deref());
            let expected = expected.as_str();
            if expected != current {
                return ProjectionEffect::Rejected {
                    reason: "cas_mismatch".to_owned(),
                };
            }
        }

        // Structured cache: set the Realm default-Strand pointer. Create a
        // minimal Realm row if we somehow haven't projected a create yet
        // (federation backfill ordering tolerance).
        let realm = self
            .realm_states
            .entry(realm_id.clone())
            .or_insert_with(|| ColandRealmState {
                realm_id: realm_id.clone(),
                owner: None,
                title: None,
                deleted: false,

                created_at: now,
                updated_at: now,
                trust_domain: None,
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
            });
        realm.default_strand_id = Some(strand_id.clone());
        realm.updated_at = now;

        ProjectionEffect::RealmDefaultStrandSet {
            realm_id,
            strand_id,
        }
    }

    /// Apply display and lifecycle caches from accepted Realm Events.
    /// Protocol conflict and current selection remain bound to RealmCommit.
    /// Apply a `ak.realm.*` lifecycle event. Stream-F (Wave 1B) rewrite
    /// of the former Realm lifecycle reducer: the function is now
    /// restricted to the canonical Realm lifecycle kinds
    /// (`ak.realm.create`, `ak.realm.profile`, `ak.realm.archive`,
    /// `ak.realm.tombstone`, `ak.realm.destroy`). Space-container lifecycle
    /// (`ak.space.create` / `update` / `parent` / `archive` / `restore`
    /// / `tombstone`) is handled by `apply_space_container_*`
    /// in this same impl block — they were already separate methods
    /// before this rename, so no extraction was needed.
    ///
    /// Spec seals:
    ///   - `realm-and-space.md` §2.5 (terminal state distinction: tombstone vs destroy)
    ///   - `realm-and-space.md` §2.5.1 (destroy cascade rules)
    ///   - `realm-and-space.md` §2.5.2 (erasure receipt fanout — reducer leg only; the actual
    ///     federation push lives outside)
    pub(crate) fn apply_realm_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        kind: arkret_wire::EventKind,
    ) -> ProjectionEffect {
        // Defensive: only canonical Realm-lifecycle kinds may
        // reach this function. The dispatch table enforces this; the
        // assertion keeps internal callers honest.
        debug_assert!(
            matches!(
                &kind,
                arkret_wire::EventKind::RealmCreate
                    | arkret_wire::EventKind::RealmProfile
                    | arkret_wire::EventKind::RealmArchive
                    | arkret_wire::EventKind::RealmRestore
                    | arkret_wire::EventKind::RealmFreeze
                    | arkret_wire::EventKind::RealmUnfreeze
                    | arkret_wire::EventKind::RealmTombstone
                    | arkret_wire::EventKind::RealmDestroy
            ),
            "apply_realm_lifecycle dispatched with non-realm kind: {kind}",
        );

        // Keep the structured cache and the canonical cells map in sync.
        //
        // Per spec event-kind-registry, each ak.realm.* lifecycle event
        // writes a distinct cell family with its own state model:
        //   ak.realm.create     → ak.component.realm.create.v1  (genesis singleton)
        //   ak.realm.profile    → ak.component.realm.profile.v1 (registered state model, singleton)
        //   ak.realm.archive    → ak.component.realm.archive.v1 (registered state model, singleton)
        //   ak.realm.freeze     → ak.component.realm.freeze.v1 (registered state model, singleton)
        //   ak.realm.tombstone  → ak.component.realm.tombstone.v1 (registered state model,
        // singleton)   ak.realm.destroy    → ak.component.realm.destroy.v1 (registered
        // state model, singleton)
        //
        // Stream-F (Wave 1B): tombstone and destroy are both terminal but
        // write distinct cell families. Bottom = reject; a second
        // terminal-state write rejects with `realm_already_terminal`.
        let payload_object = operation.payload.get("object").and_then(Value::as_object);
        let realm_id = operation.realm_id.to_string();
        let agent_status = if kind == arkret_wire::EventKind::RealmCreate
            && payload_object
                .and_then(|object| object.get("purpose"))
                .and_then(Value::as_str)
                == Some("agent_control")
        {
            if operation.context.sender.as_account_id().is_none() {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
            let actor_key = match operation.context.sender.canonical_key() {
                Ok(actor_key) => actor_key,
                Err(_) => {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                }
            };
            let status = FacetRef::new(facet::AGENT_STATUS, actor_key.as_str());
            if self
                .facet_value(operation.realm_id.as_str(), &status)
                .is_some()
                || self.agent_lifecycles.contains_key(&actor_key)
            {
                return ProjectionEffect::Rejected {
                    reason: "invalid_agent_lifecycle_transition".to_owned(),
                };
            }
            Some((actor_key, status))
        } else {
            None
        };
        // The Realm genesis author is the initial authority-root controller;
        // `realm_create_payload` carries no separate owner field.
        let creator =
            (kind == arkret_wire::EventKind::RealmCreate).then(|| operation.context.sender.clone());
        // `realm_create_payload` is `{object}` with `additionalProperties:false`,
        // so `ak.realm.create` cannot carry a top-level `owner`: the owning
        // principal is the genesis authority-root controller.
        let owner = creator.as_ref().map(ToString::to_string);
        // `ak.realm.profile` is the one Realm facet payload that carries the
        // human-readable title (`zh/models/realm-and-space.md`); no other kind
        // handled here declares it.
        let title = operation
            .payload
            .get("title")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        // Security class, trust domain and digest suite are create-locked
        // genesis state. `realm_create_payload` is the closed `{object}`
        // envelope, and `realm-genesis.schema.json` requires both fields in
        // that object. No other Realm lifecycle kind may populate or validate
        // them.
        let payload_trust_domain = if kind == arkret_wire::EventKind::RealmCreate {
            let Some(trust_domain) = payload_object
                .and_then(|object| object.get("trust_domain"))
                .and_then(Value::as_str)
            else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            };
            // `realm-genesis.schema.json` is a closed object
            // (`additionalProperties: false`) whose required set is `[schema,
            // purpose, genesis_salt, trust_domain, security_class,
            // governance_station_id, initial_join_rule,
            // initial_history_access, initial_discoverability]`;
            // `digest_algorithm` is not even a declared property there.
            // `models/realm-and-space.md` line 123 places it on the Realm
            // object as optional, create-locked and defaulting to `sha256`,
            // and `realm.schema.json` carries the same `"default": "sha256"`.
            // A genesis that declares nothing therefore runs the baseline
            // suite; only a declared value that names no active digest-suite
            // row is refused.
            if let Some(declared) = payload_object.and_then(|object| object.get("digest_algorithm"))
            {
                let supported = declared
                    .as_str()
                    .is_some_and(|algorithm| arkret_canonical::digest_suite(algorithm).is_ok());
                if !supported {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::UNSUPPORTED_DIGEST_ALGORITHM.to_owned(),
                    };
                }
            }
            Some(trust_domain.to_owned())
        } else {
            None
        };
        if let Some(ref new_td) = payload_trust_domain {
            // Shape MUST be `ak:trust_domain:<scope>` — delegate to SDK
            // typed id validator.
            if arkret_identifiers::TrustDomainId::new(new_td.clone()).is_err() {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
            // Compare against any prior locked value. Any mismatch is a
            // cross-domain replay attempt: a peer is trying to relabel a
            // Realm into a different trust domain.
            if let Some(existing) = self.realm_states.get(&realm_id)
                && let Some(locked_td) = existing.trust_domain.as_deref()
                && locked_td != new_td.as_str()
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::CROSS_DOMAIN_REPLAY_REJECTED.to_owned(),
                };
            }
        }

        // Stream-F (Wave 1B): terminal-state preflight. A Realm already
        // in `tombstoned` or `destroyed` state MUST NOT accept another
        // terminal-state write (cell family is registered state model with
        // bottom=reject; the structured cache mirrors that).
        if let Some(existing) = self.realm_states.get(&realm_id)
            && existing.terminal_state.is_some()
            && matches!(
                &kind,
                arkret_wire::EventKind::RealmTombstone | arkret_wire::EventKind::RealmDestroy
            )
        {
            return ProjectionEffect::Rejected {
                reason: "realm_already_terminal".to_owned(),
            };
        }

        // Stream-F (Wave 1B): ak.realm.tombstone preconditions. The
        // event MUST carry a syntactically valid `successor_realm_id`
        // pointing at a `ak:realm:<44-char-token>` distinct from the
        // terminating Realm. Absent → `missing_successor`; malformed →
        // `schema_violation`; self-reference → `successor_self_reference`.
        let payload_successor_realm_id = operation
            .payload
            .get("successor_realm_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if kind == arkret_wire::EventKind::RealmTombstone {
            match payload_successor_realm_id.as_deref() {
                None => {
                    return ProjectionEffect::Rejected {
                        reason: "missing_successor".to_owned(),
                    };
                }
                Some(id) => {
                    if arkret_identifiers::RealmId::new(id).is_err() {
                        return ProjectionEffect::Rejected {
                            reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                        };
                    }
                    if id == realm_id {
                        return ProjectionEffect::Rejected {
                            reason: "successor_self_reference".to_owned(),
                        };
                    }
                }
            }
        }
        // ak.realm.destroy MUST NOT carry successor_realm_id (spec §2.5).
        if kind == arkret_wire::EventKind::RealmDestroy && payload_successor_realm_id.is_some() {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }

        if kind == arkret_wire::EventKind::RealmCreate && self.realm_create_log(&realm_id).is_some()
        {
            return ProjectionEffect::Rejected {
                reason: "realm_already_exists".to_owned(),
            };
        }

        // `realm-and-space.md` §2.5 — genesis registers five cell writes and
        // the authority root is one of them. Derive it before any structured
        // cache mutation so a create that cannot establish an authority root
        // rejects the whole atomic bootstrap unit instead of materializing a
        // Realm nobody can govern.
        let authority_root = match creator.as_ref() {
            Some(creator) => match genesis_authority_root_value(
                payload_object,
                creator,
                &operation.context.accepted_event_id,
            ) {
                Ok(value) => Some(value),
                Err(reason) => {
                    return ProjectionEffect::Rejected {
                        reason: reason.to_owned(),
                    };
                }
            },
            None => None,
        };
        let principal_genesis_resolution = if kind == arkret_wire::EventKind::RealmCreate {
            match principal_genesis_resolution_value(operation, payload_object) {
                Ok(value) => value,
                Err(reason) => {
                    return ProjectionEffect::Rejected {
                        reason: reason.to_owned(),
                    };
                }
            }
        } else {
            None
        };

        // Structured cache mirror.
        let realm = self
            .realm_states
            .entry(realm_id.clone())
            .or_insert_with(|| ColandRealmState {
                realm_id: realm_id.clone(),
                owner: owner.clone(),
                title: title.clone(),
                deleted: false,

                created_at: now,
                updated_at: now,
                trust_domain: payload_trust_domain.clone(),
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
            });
        // Lock trust_domain on first observation (ak.realm.create). The
        // mismatch case is already rejected above; here we only set the
        // value when it has not yet been captured.
        if realm.trust_domain.is_none()
            && let Some(td) = payload_trust_domain.clone()
        {
            realm.trust_domain = Some(td);
        }
        // Stream-F (Wave 1B): both terminal-state events flip the
        // summary `deleted` flag. The richer `terminal_state` /
        // `successor_realm_id` fields are the source of truth.
        if kind == arkret_wire::EventKind::RealmDestroy
            || kind == arkret_wire::EventKind::RealmTombstone
        {
            realm.deleted = true;
        }
        if kind == arkret_wire::EventKind::RealmTombstone {
            realm.terminal_state = Some("tombstoned".to_owned());
            realm.successor_realm_id = payload_successor_realm_id.clone();
        } else if kind == arkret_wire::EventKind::RealmDestroy {
            realm.terminal_state = Some("destroyed".to_owned());
            realm.successor_realm_id = None;
        }
        if owner.is_some() {
            realm.owner.clone_from(&owner);
        }
        if title.is_some() {
            realm.title.clone_from(&title);
        }
        realm.updated_at = now;

        // Facet writes for this canonical kind.
        match &kind {
            arkret_wire::EventKind::RealmCreate => {
                self.set_realm_facet(
                    &realm_id,
                    facet::REALM_CREATE,
                    Value::Array(vec![Value::String(realm_id.clone())]),
                );
                if let Some(genesis) = payload_object {
                    self.set_realm_facet(
                        &realm_id,
                        facet::REALM_GENESIS,
                        Value::Object(genesis.clone()),
                    );
                }
                if let Some(history_access) = payload_object.and_then(|object| {
                    object
                        .get("history_access")
                        .and_then(Value::as_str)
                        .or_else(|| {
                            matches!(
                                object.get("purpose").and_then(Value::as_str),
                                Some(
                                    "direct_conversation"
                                        | "principal_control"
                                        | "agent_control"
                                        | "applet_managed_control"
                                )
                            )
                            .then_some("since_join")
                        })
                }) {
                    self.set_realm_facet(
                        &realm_id,
                        facet::REALM_HISTORY_ACCESS,
                        Value::String(history_access.to_owned()),
                    );
                }
                if let Some(authority_root) = authority_root {
                    self.set_realm_facet(&realm_id, facet::REALM_AUTHORITY_ROOT, authority_root);
                }
                if let Some(resolution) = principal_genesis_resolution {
                    self.set_realm_facet(&realm_id, facet::IDENTITY_RESOLUTION, resolution);
                }
                // The Agent PCR genesis is the sole transition from
                // the internal transition state `uninitialized` to the first public
                // state `active`. Provision admission only reserves/declares
                // the future PCR and must never activate this cell early.
                if let Some((agent_actor_id, status)) = agent_status {
                    self.set_facet(&realm_id, status, Value::String("active".to_owned()));
                    self.agent_lifecycles
                        .insert(agent_actor_id, AgentLifecycleState::Active);
                }
            }
            arkret_wire::EventKind::RealmProfile => {
                self.set_realm_facet(&realm_id, facet::REALM_PROFILE, operation.payload.clone());
            }
            arkret_wire::EventKind::RealmArchive | arkret_wire::EventKind::RealmRestore => {
                self.set_realm_facet(
                    &realm_id,
                    facet::REALM_ARCHIVE,
                    Value::Bool(kind == arkret_wire::EventKind::RealmArchive),
                );
            }
            arkret_wire::EventKind::RealmFreeze | arkret_wire::EventKind::RealmUnfreeze => {
                self.set_realm_facet(
                    &realm_id,
                    facet::REALM_FREEZE,
                    Value::Bool(kind == arkret_wire::EventKind::RealmFreeze),
                );
            }
            arkret_wire::EventKind::RealmTombstone => {
                // The tombstone facet carries `successor_realm_id` so a
                // Station hydrating from facets alone can distinguish
                // migration from destroy.
                let value = serde_json::json!({
                    "terminal_kind": "tombstoned",
                    "tombstoned": true,
                    "successor_realm_id": payload_successor_realm_id,
                    "at": arkret_canonical::format_timestamp_canonical(now),
                    "operation_id": operation.operation_id.as_str(),
                });
                self.set_realm_facet(&realm_id, facet::REALM_TOMBSTONE, value);
                self.cascade_realm_terminal(&realm_id);
            }
            arkret_wire::EventKind::RealmDestroy => {
                // Terminal facet: {destroyed: true, at: ts}.
                let value = serde_json::json!({
                    "terminal_kind": "destroyed",
                    "destroyed": true,
                    "at": arkret_canonical::format_timestamp_canonical(now),
                    "operation_id": operation.operation_id.as_str(),
                });
                self.set_realm_facet(&realm_id, facet::REALM_DESTROY, value);
                // Destroy cascade per spec §2.5.1 ¶6 + ¶7.
                self.cascade_realm_terminal(&realm_id);
            }
            _ => {}
        }

        ProjectionEffect::RealmLifecycle {
            realm_id,
            action: kind
                .as_str()
                .strip_prefix("ak.realm.")
                .unwrap_or(kind.as_str())
                .to_owned(),
        }
    }

    /// Stream-F (Wave 1B + Wave 2C) — `ak.realm.destroy` child-cascade.
    /// Spec `realm-and-space.md` §2.5.1:
    ///   ¶6 child Space-container placement (same Realm) → mark
    ///      `realm_destroyed_orphan` (locked read-only projection).
    /// AKP-0007: `Strand.discussion_realm_ref` is a removed wire field.
    /// Intra-Realm discussion boundaries now live on a Circle
    /// (`scope_circle_id`) and never cross the Realm frontier, so no
    /// cross-Realm discussion cascade is required here.
    ///
    /// The terminal-state admission check (event_log.rs) prevents
    /// further writes against the destroyed Realm itself, which is the
    /// load-bearing safety property; this cascade applies the
    /// projection-side downgrade so UI / navigation surfaces honour
    /// the destroy frontier without a fresh query against the
    /// terminated Realm.
    pub(crate) fn cascade_realm_terminal(&mut self, terminal_realm_id: &str) {
        // ¶6 same-Realm child Space-container cascade.
        let mut orphaned_count = 0_usize;
        for container in self.space_containers.values_mut() {
            if container.realm_id == terminal_realm_id && !container.orphaned {
                container.orphaned = true;
                orphaned_count += 1;
            }
        }

        // AKP-0007: no cross-Realm discussion edges to sever — Circles
        // are intra-Realm and `ak.realm.destroy` already tombstones their
        // parent Realm; further Circle writes fall under the terminal
        // admission check in `event_log::validate_event_envelope`.

        tracing::info!(
            terminal_realm_id = %terminal_realm_id,
            orphaned_space_containers = orphaned_count,
            "Realm terminal navigation fence applied"
        );
    }
}
