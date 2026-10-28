use super::*;

mod agent_lifecycle;
mod call_state;
mod cells_realm;
mod circle_encryption;
mod circle_history;
mod moderation;
mod pending_replay;
mod pin_rsvp_encryption;
mod pin_scope_safety;
mod poll;
mod realm_authority;
mod redaction_message;
mod space_container;
mod stage_axis;
mod strand_morph;

pub(super) fn account_actor(principal_id: &str) -> arkret_wire::ActorId {
    let principal_id = arkret_identifiers::DidCoreId::new(principal_id).unwrap();
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal_id.clone(),
        principal_id,
    ))
}

pub(super) fn account_actor_string(principal_id: &str) -> String {
    account_actor(principal_id).to_string()
}

/// The facet subject a member-scoped facet is keyed by.
///
/// Production keys every actor-scoped facet by the ActorId's canonical key
/// (see `ProjectionState::member_transition_state`), so a test addresses the
/// same subject through the same projection.
pub(super) fn actor_facet_subject(actor: &arkret_wire::ActorId) -> String {
    actor.canonical_key().unwrap()
}

/// The generation-0 governance Station every reducer fixture Realm is created
/// under. `realm-genesis.schema.json` requires it and the create reducer folds
/// it into the authority-root facet.
pub(super) const FIXTURE_GOVERNANCE_STATION: &str = "ak:did_core:web:reducer-test.example";

pub(super) fn make_operation(
    object_kind: impl AsRef<str>,
    realm_id: &str,
    mut payload: Value,
) -> Operation {
    // The production Event→Operation adapter injects the accepted event_id.
    // Unit tests commonly construct only the create object's typed id, so
    // mirror that adapter by retyping the same complete event token when the id-kind registry
    // declares the object Event-derived.
    let derived_event_id = payload
        .get("object")
        .and_then(Value::as_object)
        .and_then(|object| object.get("id"))
        .and_then(Value::as_str)
        .and_then(|object_id| object_id.rsplit_once(':'))
        .and_then(|(kind, event_token)| {
            let prefix = format!("{kind}:");
            arkret_identifiers::EVENT_DERIVED_ID_KIND_PREFIXES
                .contains(&prefix.as_str())
                .then(|| format!("ak:event:{event_token}"))
        });
    if payload.get("event_id").is_none()
        && let Some(event_id) = derived_event_id
    {
        payload
            .as_object_mut()
            .expect("operation payload object")
            .insert("event_id".to_owned(), Value::String(event_id));
    }
    arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(realm_id).unwrap(),
        object_kind.as_ref(),
        payload,
    )
}

/// The content-bound Event id a receiver derives for this `kind + payload`,
/// built through the SDK's own authoring path.
///
/// The id is an output, not an input. An Event id is the digest of the Event's
/// own content, so no caller can choose one; a test that pinned an id would be
/// asserting against an identity the content never produced. Tests read it here
/// because the Event to Operation adapter injects it into the projection
/// payload, because Event-derived object ids retype this exact token, and
/// because list-valued facet entries carry it as their `tag_id`.
///
/// `distinct_seq` is the honest way to make two otherwise identical Events
/// distinct. The envelope carries no producer sequence any more, so the only
/// remaining lever is `created_at`: same kind, Realm, payload and timestamp is
/// the *same* Event and therefore the same id.
pub(super) fn derived_event_id_at_seq(
    object_kind: impl AsRef<str>,
    realm_id: &str,
    distinct_seq: u64,
    payload: &Value,
) -> arkret_identifiers::EventId {
    let actor_id = arkret_wire::project_did_to_core_id(
        &arkret_identifiers::Did::new("did:web:reducer-test.example").unwrap(),
    )
    .unwrap();
    derived_event_id_for_actor(object_kind, realm_id, distinct_seq, payload, actor_id)
}

pub(super) fn derived_event_id_for_actor(
    object_kind: impl AsRef<str>,
    realm_id: &str,
    distinct_seq: u64,
    payload: &Value,
    actor_id: arkret_identifiers::DidCoreId,
) -> arkret_identifiers::EventId {
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
        + chrono::Duration::milliseconds(
            i64::try_from(distinct_seq).expect("fixture distinguishing sequence fits in i64"),
        );
    arkret_wire::test_support::raw_event_at(
        object_kind.as_ref(),
        arkret_wire::event_envelope::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id).unwrap(),
        },
        actor_id.clone(),
        actor_id,
        payload.clone(),
        created_at,
    )
    .expect("event envelope")
    .event_id
}
