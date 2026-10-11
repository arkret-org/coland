//! Capability authorization for HTTP surfaces.
//!
//! Every decision reads the durable `realm_authority_root` and
//! `capability_grant` typed current results of one Realm in one snapshot and
//! evaluates them with the same evaluator that admits capability-gated Events
//! (`authz/capabilities.md` §18). A grant exists only once the accepting
//! RealmCommit wrote its current result; there is no process-local index.
//! Membership is never an authorization source.

use arkret_wire::{ActorId, RealmId, WireResourceSelector};
use coland_http::error::AppError;
pub(crate) use coland_services::authorization::CapabilityVerdict;
use coland_storage::ActorRealmAuthorization;

use crate::state::AppState;

const REASON_CAPABILITY_ACTION_UNKNOWN: &str = "capability_action_unknown";
const REASON_CAPABILITY_ACTION_INVALID: &str = "capability_action_invalid";
const REASON_CAPABILITY_ACTION_WILDCARD_FORBIDDEN: &str = "capability_action_wildcard_forbidden";

/// Read `actor`'s authorization inputs in `realm_id` at `at`.
pub(crate) async fn actor_realm_authorization(
    state: &AppState,
    realm_id: &RealmId,
    actor: &ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<ActorRealmAuthorization, AppError> {
    state
        .persistence()
        .actor_realm_authorization(realm_id, actor, at)
        .await
        .map_err(|error| AppError::internal(format!("authorization cut read failed: {error}")))
}

/// Whether `actor` may exercise one of `actions` on `resource` in `realm_id`
/// at `at`. A Realm id or resource that does not parse authorizes nothing.
pub(crate) async fn authorize(
    state: &AppState,
    realm_id: &str,
    actor: &ActorId,
    actions: &[&str],
    resource: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<CapabilityVerdict, AppError> {
    let Ok(realm_id) = RealmId::new(realm_id.to_owned()) else {
        return Ok(CapabilityVerdict::Denied);
    };
    let Some(target) = resource_selector(&realm_id, resource) else {
        return Ok(CapabilityVerdict::Denied);
    };
    let authorization = actor_realm_authorization(state, &realm_id, actor, at).await?;
    Ok(coland_services::authorization::evaluate(
        &authorization,
        actions,
        &target,
        &coland_storage::OperationFacts::default(),
    ))
}

/// [`authorize`] for the Event-policy gates, whose refusals are wire reason
/// codes. A storage failure is `internal_error`, never a capability refusal.
pub(crate) async fn actor_may(
    state: &AppState,
    realm_id: &str,
    actor: &ActorId,
    actions: &[&str],
    resource: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, &'static str> {
    authorize(state, realm_id, actor, actions, resource, at)
        .await
        .map(|verdict| verdict.allowed())
        .map_err(|error| {
            tracing::error!(?error, %realm_id, "capability authorization read failed");
            arkret_wire::ErrorCode::INTERNAL_ERROR
        })
}

/// The resource selector a typed Arkret id names inside `realm_id`. The Realm
/// id itself names the Realm; an id of another Realm-contained kind names that
/// object; anything else is an opaque object reference.
pub(crate) fn resource_selector(
    realm_id: &RealmId,
    resource: &str,
) -> Option<WireResourceSelector> {
    if resource.starts_with("ak:realm:") {
        return (resource == realm_id.as_str())
            .then(|| WireResourceSelector::realm(realm_id.clone()));
    }
    let typed = [
        ("ak:space:", "space", "space_id"),
        ("ak:circle:", "circle", "circle_id"),
        ("ak:strand:", "strand", "strand_id"),
        ("ak:message:", "message", "message_id"),
        ("ak:morph:", "morph", "morph_id"),
        ("ak:relation:", "relation", "relation_id"),
        ("ak:view:", "view", "view_id"),
        ("ak:event:", "event", "event_id"),
        ("ak:invite:", "invite", "invite_id"),
    ];
    let value = match typed
        .iter()
        .find(|(prefix, ..)| resource.starts_with(prefix))
    {
        Some((_, kind, field)) => serde_json::json!({
            "kind": kind,
            "realm_id": realm_id,
            *field: resource,
        }),
        None => serde_json::json!({
            "kind": "object",
            "realm_id": realm_id,
            "object_ref": resource,
        }),
    };
    serde_json::from_value(value).ok()
}

/// Structural and registry validity of an action named by a caller.
pub(crate) fn validate_runtime_capability_action(action: &str) -> Result<(), &'static str> {
    if action.contains('*') {
        return Err(REASON_CAPABILITY_ACTION_WILDCARD_FORBIDDEN);
    }
    let mut segments = action.split('.');
    if segments.next() != Some("ak") {
        return Err(REASON_CAPABILITY_ACTION_INVALID);
    }
    let mut saw_segment = false;
    for segment in segments {
        saw_segment = true;
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(REASON_CAPABILITY_ACTION_INVALID);
        }
    }
    if !saw_segment {
        return Err(REASON_CAPABILITY_ACTION_INVALID);
    }
    arkret_schema::capability_action(action)
        .map(|_| ())
        .ok_or(REASON_CAPABILITY_ACTION_UNKNOWN)
}

/// The refusal reason for an action nothing authorizes.
pub(crate) fn default_deny_reason(action: &str) -> &'static str {
    match action {
        arkret_wire::CapabilityActionId::MESSAGE_CREATE => "no_strand_track_message_grant",
        _ => "capability_denied",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM: &str = "ak:realm:ARib7U2kHFo1ErdwrDDP0057R6D3jtBM74RcEz4Pw4Jy";

    fn realm() -> RealmId {
        RealmId::new(REALM.to_owned()).unwrap()
    }

    #[test]
    fn typed_ids_name_their_own_selector_kind() {
        let circle = "ak:circle:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M";
        let strand = "ak:strand:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";
        assert_eq!(
            serde_json::to_value(resource_selector(&realm(), REALM).unwrap()).unwrap(),
            serde_json::json!({"kind": "realm", "realm_id": REALM})
        );
        assert_eq!(
            serde_json::to_value(resource_selector(&realm(), circle).unwrap()).unwrap(),
            serde_json::json!({"kind": "circle", "realm_id": REALM, "circle_id": circle})
        );
        assert_eq!(
            serde_json::to_value(resource_selector(&realm(), strand).unwrap()).unwrap(),
            serde_json::json!({"kind": "strand", "realm_id": REALM, "strand_id": strand})
        );
        assert_eq!(
            serde_json::to_value(resource_selector(&realm(), "document:summary").unwrap()).unwrap(),
            serde_json::json!({"kind": "object", "realm_id": REALM, "object_ref": "document:summary"})
        );
    }

    #[test]
    fn another_realm_names_nothing() {
        assert!(
            resource_selector(
                &realm(),
                "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"
            )
            .is_none()
        );
    }

    #[test]
    fn runtime_actions_must_be_registered_and_literal() {
        assert_eq!(validate_runtime_capability_action("ak.realm.admin"), Ok(()));
        assert_eq!(
            validate_runtime_capability_action("ak.realm.*"),
            Err(REASON_CAPABILITY_ACTION_WILDCARD_FORBIDDEN)
        );
        assert_eq!(
            validate_runtime_capability_action("realm.admin"),
            Err(REASON_CAPABILITY_ACTION_INVALID)
        );
        assert_eq!(
            validate_runtime_capability_action("ak.realm.nonexistent"),
            Err(REASON_CAPABILITY_ACTION_UNKNOWN)
        );
    }
}
