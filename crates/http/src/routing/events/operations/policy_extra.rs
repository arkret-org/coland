use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::Value;

use super::*;

/// The complete member ActorId named by a membership operation's closed payload.
pub(crate) fn membership_target(operation: &Operation) -> Option<arkret_wire::ActorId> {
    operation
        .payload
        .get("member_id")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .ok()
        .flatten()
}

pub(crate) async fn validate_audience_mention_operation_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        kinds::canonical_kind_for_operation(operation),
        Some(arkret_wire::EventKind::MessageCreate | arkret_wire::EventKind::MessageRevise)
    ) {
        return Ok(());
    }
    validate_sidecar_mention_subjects(state, operation).await?;
    let mentions = operation_audience_mentions(operation)?;
    if mentions.is_empty() {
        return Ok(());
    }
    let actor = &operation.context.sender;
    let realm_id = operation.realm_id.as_str();
    let resource = operation
        .payload
        .get("strand_id")
        .or_else(|| operation.payload.get("target_ref"))
        .and_then(Value::as_str)
        .unwrap_or(realm_id);
    let members = realm_members(state, realm_id);
    // `strand-and-message.md` §9.4.4: the broadcast grant is judged by the one
    // constraint evaluator, whose registry row requires the rate quota, and
    // must also be time-bounded. The owner aggregate is not such a grant. A
    // quota-bound grant is reserved only where its Event is admitted.
    let Some(target) = arkret_wire::RealmId::new(realm_id.to_owned())
        .ok()
        .and_then(|realm| {
            crate::authz::resource_selector(&realm, resource).map(|target| (realm, target))
        })
    else {
        return Err("ak.message.mention.broadcast required for audience_mention");
    };
    let authorization =
        crate::authz::actor_realm_authorization(state, &target.0, actor, operation.created_at)
            .await
            .map_err(|error| {
                tracing::error!(?error, %realm_id, "capability authorization read failed");
                arkret_wire::ErrorCode::INTERNAL_ERROR
            })?;
    let facts = coland_storage::OperationFacts {
        strand_id: operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        object_kind: Some("message".to_owned()),
        track: Some("discussion".to_owned()),
        ..coland_storage::OperationFacts::default()
    };
    match authorization.evaluate(
        &[arkret_wire::CapabilityActionId::MESSAGE_MENTION_BROADCAST],
        &target.1,
        &facts,
    ) {
        coland_storage::GrantEvaluation::Allowed(satisfied)
            if satisfied.iter().any(|grant| {
                coland_storage::capability_grant_expires_at(grant.grant).is_some()
            }) => {}
        coland_storage::GrantEvaluation::Unnamed => {
            return Err("ak.message.mention.broadcast required for audience_mention");
        }
        _ => {
            return Err(
                "ak.message.mention.broadcast grant requires temporal and rate_limiting constraints",
            );
        }
    }

    let Some(policy) = effective_audience_mention_policy_for_realm(state, realm_id).await else {
        return Err("audience_mention_policy_missing");
    };
    for mention in mentions {
        let audience = mention.audience.as_wire();
        let count = estimate_audience_recipient_count(audience, &members, operation, state);
        audience_mention_policy_allows(&policy, audience, count)?;
    }
    Ok(())
}

async fn validate_sidecar_mention_subjects(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let sidecar_id = operation.payload.get("sidecar_id").and_then(Value::as_str);
    let Some((controller_account_id, realm_id)) = sidecar_id.and_then(|sidecar_id| {
        let projection = state.projections().snapshot();
        projection.sidecars.get(sidecar_id).map(|sidecar| {
            (
                sidecar.controller_account_id.clone(),
                sidecar.realm_id.clone(),
            )
        })
    }) else {
        return Ok(());
    };
    let subjects = match operation.payload.get("content") {
        Some(content) => {
            arkret_models_collaboration::events_payloads::collect_mention_subject_actor_ids(content)
                .map_err(|error| error.message())?
        }
        None => Vec::new(),
    };
    if subjects.is_empty() {
        return Ok(());
    }
    let controller = arkret_wire::ActorId::account(controller_account_id);
    let controller_account = controller
        .as_account_id()
        .ok_or("addressed_agent_not_eligible")?;
    let desired = crate::routing::identity::agents::sidecar::derive_sidecar_desired_agent_ids(
        state,
        &realm_id,
        controller_account,
    )
    .await
    .map_err(|_| "addressed_agent_not_eligible")?;
    // A Sidecar's desired agents are hosted at the controller's own Station,
    // so the eligible set is the complete account of each desired agent. An
    // addressed account that only shares the principal component with a
    // desired agent MUST NOT pass (identity-handles.md §3.8).
    let eligible = desired
        .iter()
        .filter_map(|agent_id| arkret_wire::DidCoreId::new(agent_id.clone()).ok())
        .map(|principal_id| {
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id,
                controller_account.station_id.clone(),
            ))
        })
        .collect::<std::collections::BTreeSet<_>>();
    if subjects.iter().any(|subject| !eligible.contains(subject)) {
        Err("addressed_agent_not_eligible")
    } else {
        Ok(())
    }
}

/// The joined Actor members of `realm_id` in the event-policy projection,
/// excluding Agents whose membership base has lapsed. Used to size audience
/// fanout; never an authorization source.
pub(crate) fn realm_members(state: &AppState, realm_id: &str) -> Vec<String> {
    let projection = state.projections().snapshot();
    projection
        .members_of_realm(realm_id)
        .into_iter()
        .filter(|member| serde_json::from_str::<arkret_wire::ActorId>(&member.member).is_ok())
        .filter(|member| {
            projection
                .agent_membership_binding(realm_id, &member.member)
                .is_none()
                || projection.effective_agent_membership_base(realm_id, &member.member)
        })
        .map(|member| member.member.clone())
        .collect()
}

/// The single Realm-governance predicate every review surface uses: `actor`
/// holds one of `actions` over the whole Realm in the durable authorization
/// cut, through a covering grant or the effective `ak.realm.owner` aggregate
/// (`authz/capabilities.md` §3.2). Realm membership and the discardable
/// `realm_states[..].owner` presentation mirror are never inputs.
pub(crate) async fn actor_governs_realm(
    state: &AppState,
    realm_id: &str,
    actor: &arkret_wire::ActorId,
    actions: &[&str],
    evaluation_basis: chrono::DateTime<chrono::Utc>,
) -> Result<bool, &'static str> {
    crate::authz::actor_may(state, realm_id, actor, actions, realm_id, evaluation_basis).await
}

pub(crate) async fn effective_audience_mention_policy_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Option<Value> {
    let events = state
        .event_queries()
        .realm_events_newest_first(realm_id)
        .await
        .ok()?;
    events.into_iter().find_map(|record| {
        record
            .envelope
            .pointer("/payload/object/audience_mention_policy")
            .or_else(|| record.envelope.pointer("/payload/audience_mention_policy"))
            .or_else(|| {
                record
                    .envelope
                    .pointer("/payload/object/notification_policy/audience_mentions")
            })
            .or_else(|| {
                record
                    .envelope
                    .pointer("/payload/notification_policy/audience_mentions")
            })
            .cloned()
    })
}

pub(crate) fn estimate_audience_recipient_count(
    audience: &str,
    members: &[String],
    operation: &Operation,
    state: &AppState,
) -> usize {
    match audience {
        "strand_participants" => operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .map(|strand_id| {
                {
                    let projection = state.projections().snapshot();
                    Some({
                        projection
                            .messages_for_thread(strand_id)
                            .into_iter()
                            .map(|message| message.sender.as_str())
                            .collect::<std::collections::BTreeSet<_>>()
                            .len()
                    })
                }
                .unwrap_or(members.len())
            })
            .unwrap_or(members.len()),
        // Conservative upper bound: when the dispatcher cannot cheaply derive
        // watchers / assigned actors at policy time, use the readable member
        // set size so max_recipients never underestimates fanout.
        _ => members.len(),
    }
}

pub(crate) fn audience_mention_policy_allows(
    policy: &Value,
    audience: &str,
    recipient_count: usize,
) -> Result<(), &'static str> {
    if policy.get("enabled").and_then(Value::as_bool) == Some(false) {
        return Err("audience_mention_policy_disabled");
    }
    let audience_policy = policy
        .get("audiences")
        .and_then(|audiences| audiences.get(audience));
    let listed = policy
        .get("allowed_audiences")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .any(|item| item == audience)
        });
    if audience_policy.is_none() && !listed {
        return Err("audience_mention_audience_not_allowed");
    }
    if audience_policy
        .and_then(|entry| entry.get("enabled"))
        .and_then(Value::as_bool)
        == Some(false)
    {
        return Err("audience_mention_audience_not_allowed");
    }
    let max_recipients = audience_policy
        .and_then(|entry| entry.get("max_recipients"))
        .or_else(|| policy.get("max_recipients"))
        .and_then(Value::as_u64)
        .ok_or("audience_mention_max_recipients_missing")?;
    if recipient_count as u64 > max_recipients {
        return Err("audience_mention_recipient_count_exceeds_limit");
    }
    if !policy_declares_audience_quota(policy, audience_policy) {
        return Err("audience_mention_policy_quota_missing");
    }
    Ok(())
}

fn policy_declares_audience_quota(policy: &Value, audience_policy: Option<&Value>) -> bool {
    [audience_policy, Some(policy)]
        .into_iter()
        .flatten()
        .any(|entry| {
            let quota = entry.get("quota").unwrap_or(entry);
            quota
                .get("max_operation_count")
                .and_then(Value::as_u64)
                .is_some_and(|value| value > 0)
                && quota
                    .get("period")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
        })
}

#[cfg(test)]
mod actor_membership_context_tests {
    use super::*;

    #[tokio::test]
    async fn authorization_context_does_not_promote_directory_principals_into_accounts() {
        let state = AppState::new(
            crate::config::AppConfig {
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            coland_storage_postgres::Db { pool: None },
        );
        let realm_id = "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b";
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            state.service_core_id(),
        ));
        let mut directory = coland_services::events::RealmDirectoryEntry::new(
            arkret_wire::RealmId::new(realm_id).unwrap(),
            "discovery",
            coland_services::events::DirectoryProvenance::LocalOnly,
        );
        directory.members.insert(principal);
        state.realm_directory().upsert(directory);
        assert!(realm_members(&state, realm_id).is_empty());
        let now = chrono::Utc::now();
        state.test_projection().lock().members.insert(
            (realm_id.to_owned(), actor.to_string()),
            coland_domain::reducer::ColandMembershipState {
                member: actor.to_string(),
                realm_id: realm_id.to_owned(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                membership_event_ref: None,
                invited_at: None,
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );
        assert_eq!(realm_members(&state, realm_id), vec![actor.to_string()]);
    }
}
