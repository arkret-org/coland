//! Ordinary source-Event notification fanout (private-objects.md sections
//! 3.3-3.6, push-notifications.md section 4.3.2).
//!
//! A recipient's own Station materializes its ordinary notification rows
//! once the source Event's Commit is durable: the governing Station right
//! after its accepting unit, a member Station right after it stores the
//! committed replica. Every recipient fact -- membership, Strand scope,
//! Circle membership, watch level and active assignment -- is read from the
//! typed current results at that cut ([`NotificationFanoutBasis`]); the
//! in-process reducer projection is not a notification source. The rows are
//! a rebuildable derived projection, so a fanout failure is logged and never
//! changes the Commit outcome.
//!
//! Direct mentions keep the AKP-0016 third-party agent gate: a native Agent
//! is notified of a third-party mention (author != its controller) only when
//! its effective `third_party_mention_delivery_allowed` bit (selection intersected
//! with ceiling) is true for the message scope.

use std::collections::BTreeSet;

use arkret_models_collaboration::objects::read_receipts::{
    Notification, NotificationEventSource, NotificationSchema, NotificationSource,
    NotificationSourceRef,
};
use arkret_wire::events::EventKind;
use arkret_wire::{
    AccountId, ActorId, DidCoreId, EventId, NotificationKind, NotificationPriority,
    NotificationState, RealmId, StrandId,
};
use coland_services::delivery::NotificationFanoutBasis;
use serde_json::Value;

use crate::routing::agent_participation::{
    circle_scope_key, realm_scope_key, resolve_agent_participation_for_scope_keys, strand_scope_key,
};
use crate::state::AppState;

/// The explicit watch level that subscribes to every ordinary message.
const WATCH_ALL: &str = "all";
/// The explicit watch level whose dispatch gate suppresses every wakeup.
const WATCH_MUTED: &str = "muted";

/// The committed source Event facts a fanout reads.
struct CommittedSource<'a> {
    realm_id: &'a RealmId,
    event_id: &'a EventId,
    sender: &'a ActorId,
    kind: &'a EventKind,
    payload: &'a Value,
}

/// One notification row the fanout decided to materialize.
#[derive(Debug)]
struct PlannedNotification {
    recipient: ActorId,
    notification_kind: NotificationKind,
    source_ref: String,
    strand_id: StrandId,
    track_name: Option<String>,
    preview: Option<Value>,
}

/// Materialize the ordinary notifications a freshly committed source Event
/// derives for this Station's own accounts.
///
/// Call only after the Event's Commit is durable and only for a Commit this
/// call site stored itself, never for an exact replay.
pub(crate) async fn dispatch_committed_event_notifications(
    state: &AppState,
    event: &arkret_wire::Event,
) {
    if !matches!(
        event.kind,
        EventKind::MessageCreate | EventKind::RelationCreate | EventKind::StrandUpdate
    ) {
        return;
    }
    let payload = match serde_json::to_value(&event.payload) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(%error, event_id = %event.event_id, "notification source payload is invalid");
            return;
        }
    };
    let source = CommittedSource {
        realm_id: &event.realm_id,
        event_id: &event.event_id,
        sender: &event.actor_id,
        kind: &event.kind,
        payload: &payload,
    };
    let Some(strand_id) = source_strand_id(&source) else {
        return;
    };
    let basis = match state
        .deliveries()
        .notification_fanout_basis(source.realm_id, Some(&strand_id))
        .await
    {
        Ok(basis) => basis,
        Err(error) => {
            tracing::warn!(%error, event_id = %event.event_id, "notification fanout current is unavailable");
            return;
        }
    };
    fan_out(state, &source, &basis).await;
}

async fn fan_out(state: &AppState, source: &CommittedSource<'_>, basis: &NotificationFanoutBasis) {
    for planned in plan(source, basis, &state.service_core_id()) {
        if !mention_passes_agent_gate(state, source, basis, &planned).await {
            continue;
        }
        put_notification(state, source, planned).await;
    }
}

/// The Strand a source Event's notification is routed through.
fn source_strand_id(source: &CommittedSource<'_>) -> Option<StrandId> {
    let value = match source.kind {
        EventKind::MessageCreate => source.payload.get("strand_id"),
        EventKind::RelationCreate => source.payload.pointer("/relation/from_ref"),
        EventKind::StrandUpdate => source.payload.get("target_ref"),
        _ => None,
    }?;
    StrandId::new(value.as_str()?.to_owned()).ok()
}

fn plan(
    source: &CommittedSource<'_>,
    basis: &NotificationFanoutBasis,
    local_station: &DidCoreId,
) -> Vec<PlannedNotification> {
    let Some(strand_id) = source_strand_id(source) else {
        return Vec::new();
    };
    let gate = RecipientGate {
        source,
        basis,
        local_station,
    };
    match source.kind {
        EventKind::MessageCreate => plan_message(&gate, strand_id),
        EventKind::RelationCreate => plan_assignment(&gate, strand_id).into_iter().collect(),
        EventKind::StrandUpdate => plan_schedule(&gate, strand_id),
        _ => Vec::new(),
    }
}

/// The access, locality and mute gates applied before any row exists
/// (private-objects.md section 3.4: no stub for an actor without access or
/// with `level=muted`).
struct RecipientGate<'a> {
    source: &'a CommittedSource<'a>,
    basis: &'a NotificationFanoutBasis,
    local_station: &'a DidCoreId,
}

impl RecipientGate<'_> {
    fn admits(&self, actor: &ActorId) -> bool {
        // Only the recipient's own Station materializes its row
        // (private-objects.md section 3.3). Matching compares both account
        // components, so the same principal at another Station is a
        // different recipient.
        let local = actor
            .as_account_id()
            .is_some_and(|account| account.station_id == *self.local_station);
        local
            && actor != self.source.sender
            && self.basis.joined_members.contains(actor)
            && self.basis.strand.as_ref().is_some_and(|strand| {
                strand.realm_id == *self.source.realm_id
                    && (strand.scope_circle_id.is_none() || strand.circle_members.contains(actor))
            })
            && self.basis.watch_levels.get(actor).map(String::as_str) != Some(WATCH_MUTED)
    }

    fn watches_all(&self, actor: &ActorId) -> bool {
        self.basis.watch_levels.get(actor).map(String::as_str) == Some(WATCH_ALL)
    }
}

/// `ak.message.create`: one `mention` per addressed account and one
/// `message` per other `watch=all` watcher (private-objects.md sections 3.3
/// and 3.4). A mentioned watcher receives only the more specific `mention`.
fn plan_message(gate: &RecipientGate<'_>, strand_id: StrandId) -> Vec<PlannedNotification> {
    let payload = gate.source.payload;
    let mentioned = payload
        .get("content")
        .and_then(|content| {
            crate::routing::events::operations::mention_subject_account_ids(content).ok()
        })
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeSet<AccountId>>();
    let source_ref = arkret_identifiers::MessageId::from_event_id(gate.source.event_id).to_string();
    let track_name = payload
        .get("track_name")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    // Only a plaintext Content Block has a body; E2EE content never yields a
    // server-generated preview.
    let preview = payload
        .pointer("/content/body")
        .and_then(Value::as_str)
        .map(|body| serde_json::json!({ "body": body }));
    let row = |recipient: ActorId, notification_kind| PlannedNotification {
        recipient,
        notification_kind,
        source_ref: source_ref.clone(),
        strand_id: strand_id.clone(),
        track_name: track_name.clone(),
        preview: preview.clone(),
    };
    let mut planned = mentioned
        .iter()
        .map(|account| ActorId::account(account.clone()))
        .filter(|actor| gate.admits(actor))
        .map(|actor| row(actor, NotificationKind::Mention))
        .collect::<Vec<_>>();
    planned.extend(
        gate.basis
            .watch_levels
            .keys()
            .filter(|actor| {
                gate.watches_all(actor)
                    && !actor
                        .as_account_id()
                        .is_some_and(|account| mentioned.contains(account))
                    && gate.admits(actor)
            })
            .map(|actor| row(actor.clone(), NotificationKind::Message)),
    );
    planned
}

/// `ak.relation.create` of an `assigned_to` Relation from an active Strand
/// notifies its `to_ref` actor (private-objects.md section 3.5).
fn plan_assignment(gate: &RecipientGate<'_>, strand_id: StrandId) -> Option<PlannedNotification> {
    let relation = gate.source.payload.get("relation")?;
    if relation.get("relation_kind").and_then(Value::as_str) != Some("assigned_to") {
        return None;
    }
    let assignee = serde_json::from_value::<ActorId>(relation.get("to_ref")?.clone()).ok()?;
    if !gate
        .basis
        .strand
        .as_ref()
        .is_some_and(|strand| strand.active)
        || !gate.admits(&assignee)
    {
        return None;
    }
    // `relation_create_object` bans `id`: the Relation id is the retyped
    // creating Event id.
    let source_ref =
        arkret_identifiers::RelationId::from_event_id(gate.source.event_id).to_string();
    Some(PlannedNotification {
        recipient: assignee,
        notification_kind: NotificationKind::Assignment,
        source_ref,
        strand_id,
        track_name: None,
        preview: None,
    })
}

/// `ak.strand.update` of `metadata.fields.due_at` notifies the Strand's
/// active assignees and `watch=all` watchers (private-objects.md section
/// 3.6). Extension schedule fields belong to their own server profile.
fn plan_schedule(gate: &RecipientGate<'_>, strand_id: StrandId) -> Vec<PlannedNotification> {
    if !patch_touches_due_schedule(gate.source.payload) {
        return Vec::new();
    }
    let mut recipients = gate.basis.active_assignees.clone();
    recipients.extend(
        gate.basis
            .watch_levels
            .keys()
            .filter(|actor| gate.watches_all(actor))
            .cloned(),
    );
    recipients
        .into_iter()
        .filter(|actor| gate.admits(actor))
        .map(|recipient| PlannedNotification {
            recipient,
            notification_kind: NotificationKind::Schedule,
            source_ref: strand_id.to_string(),
            strand_id: strand_id.clone(),
            track_name: None,
            preview: None,
        })
        .collect()
}

fn patch_touches_due_schedule(payload: &Value) -> bool {
    let Some(patch) = payload.get("patch").and_then(Value::as_object) else {
        return false;
    };
    patch.iter().any(|(path, value)| {
        if path == "metadata.fields.due_at" {
            return true;
        }
        if path == "metadata.fields" {
            return canonical_patch_set_value(value)
                .and_then(Value::as_object)
                .is_some_and(|fields| fields.contains_key("due_at"));
        }
        if path == "metadata" {
            return canonical_patch_set_value(value)
                .and_then(|metadata| metadata.get("fields"))
                .and_then(Value::as_object)
                .is_some_and(|fields| fields.contains_key("due_at"));
        }
        false
    })
}

/// Resolve the two shapes admitted by `patch.schema.json`: a direct value or
/// an explicit `{ "$op": "set" | "add", "value": ... }` operation.
/// Unset/remove operations carry no replacement value and cannot introduce a
/// due-date field.
fn canonical_patch_set_value(value: &Value) -> Option<&Value> {
    let Some(object) = value.as_object() else {
        return Some(value);
    };
    let Some(op) = object.get("$op").and_then(Value::as_str) else {
        return Some(value);
    };
    matches!(op, "set" | "add")
        .then(|| object.get("value"))
        .flatten()
}

/// AKP-0016 section 9.4.5: a native Agent receives a third-party mention only
/// when its effective `third_party_mention_delivery_allowed` bit for the message scope
/// is true. A mention by its controller always passes.
async fn mention_passes_agent_gate(
    state: &AppState,
    source: &CommittedSource<'_>,
    basis: &NotificationFanoutBasis,
    planned: &PlannedNotification,
) -> bool {
    let agent = planned.recipient.signing_principal_id().as_str();
    let agent_record = match state.agent_pairings().agent(agent).await {
        Ok(Some(record)) => record,
        Ok(None) => return true,
        Err(error) => {
            tracing::warn!(%error, "notification Agent lookup failed");
            return false;
        }
    };
    let Ok(controller) =
        crate::routing::identity::agent_pcr::agent_controller_account(state, &agent_record).await
    else {
        return false;
    };
    let Some(agent_account) = planned.recipient.as_account_id() else {
        return false;
    };
    if state
        .authority_commits()
        .agent_owner_direct_scope(source.realm_id, agent_account, &controller)
        .await
        .unwrap_or(false)
    {
        return *source.sender == ActorId::account(controller);
    }
    let mode = state
        .authority_commits()
        .current_agent_result(
            source.realm_id,
            &arkret_wire::CurrentSelector::AgentInteraction {
                agent_account_id: agent_account.clone(),
            },
        )
        .await;
    let public = matches!(mode, Ok(Some(arkret_wire::CurrentState::Value { source_stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id }, value, .. })) if realm_id == *source.realm_id && serde_json::from_value::<arkret_models_collaboration::agent_interaction::AgentInteractionCurrentValue>(value.clone()).is_ok_and(|v| v.controller_account_id == controller && v.interaction_mode == arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public));
    if !public {
        return false;
    }
    if *source.sender == ActorId::account(controller) {
        return true;
    }
    let realm_id = source.realm_id.as_str();
    let mut scope_keys = vec![realm_scope_key(realm_id)];
    if let Some(circle_id) = basis
        .strand
        .as_ref()
        .and_then(|strand| strand.scope_circle_id.as_ref())
    {
        scope_keys.push(circle_scope_key(realm_id, circle_id.as_str()));
    }
    scope_keys.push(strand_scope_key(realm_id, planned.strand_id.as_str()));
    resolve_agent_participation_for_scope_keys(state, agent, &scope_keys)
        .await
        .is_some_and(|resolved| resolved.effective.third_party_mention_delivery_allowed)
}

async fn put_notification(
    state: &AppState,
    source: &CommittedSource<'_>,
    planned: PlannedNotification,
) {
    let created_at = crate::routing::events::now();
    let record = (|| {
        let preview = planned
            .preview
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("notification preview is invalid: {error}"))?;
        let ordinary_kind =
            arkret_wire::OrdinaryNotificationKind::try_from(&planned.notification_kind)
                .map_err(|error| error.to_string())?;
        let id =
            arkret_models_collaboration::objects::read_receipts::derive_notification_projection_id(
                planned
                    .recipient
                    .as_account_id()
                    .ok_or("notification recipient must be an account")?,
                source.realm_id,
                source.event_id,
                ordinary_kind,
            )
            .map_err(|error| error.to_string())?;
        let notification = Notification {
            id: id.into(),
            schema: NotificationSchema::V1,
            actor_id: planned.recipient,
            source: NotificationSource::Event(NotificationEventSource {
                source_event_id: source.event_id.clone(),
                realm_id: Some(source.realm_id.clone()),
                source_ref: Some(NotificationSourceRef::new(planned.source_ref).map_err(
                    |error| format!("notification source reference is invalid: {error}"),
                )?),
                strand_id: Some(planned.strand_id),
                track_name: planned.track_name,
            }),
            notification_kind: planned.notification_kind,
            priority: NotificationPriority::Normal,
            state: NotificationState::Unread,
            preview,
            created_at,
            updated_at: Some(created_at),
        };
        notification
            .validate()
            .map_err(|error| format!("notification is invalid: {error}"))?;
        Ok::<_, String>(coland_services::delivery::RecipientNotificationRecord {
            notification,
            event_kind: source.kind.clone(),
            source_actor_id: Some(source.sender.clone()),
        })
    })();
    let record = match record {
        Ok(record) => record,
        Err(error) => {
            tracing::warn!(%error, "failed to materialize typed notification");
            return;
        }
    };
    if let Err(error) = state
        .deliveries()
        .store_notification(coland_services::delivery::StoreNotificationCommand { record })
        .await
    {
        tracing::warn!(%error, "failed to persist notification");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use coland_services::delivery::NotificationStrandScope;
    use coland_storage_postgres::Db;
    use serde_json::{Value, json};

    use super::*;

    const REALM: &str = "ak:realm:AS1XvoEwEve7yjNY6nVsquBYDGIKDIrmFJeSCVjzcASh";
    const STRAND: &str = "ak:strand:AYzqeQ1hbLexQxBuFmhDzV2R1jsnUEvB0ELJR10hOgtK";
    const CIRCLE: &str = "ak:circle:Aecu1rM_o2niy2h_rtK9KBChw8L-QoAsngbVoP1bpNrl";
    const ALICE: &str = "ak:did_core:web:alice.example";
    const BOB: &str = "ak:did_core:web:bob.example";
    const CAROL: &str = "ak:did_core:web:carol.example";
    const DAVE: &str = "ak:did_core:web:dave.example";
    const AGENT: &str = "ak:did_core:webvh:z6mkalicesummary";
    const OTHER_STATION: &str = "ak:did_core:web:other-station.example";

    fn test_config() -> crate::config::AppConfig {
        crate::config::AppConfig {
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("coland-agent-notify-test-blobs"),
            ),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            notary_signing_key_seed: Some([9u8; 32]),
            seed_demo_data: true,
            ..crate::config::AppConfig::test_default()
        }
    }

    /// A fixture state whose persistence is a leased PostgreSQL database.
    fn test_state() -> AppState {
        AppState::new(test_config(), Db { pool: None })
    }

    fn local_station() -> DidCoreId {
        crate::test_event::station_id()
    }

    fn actor(principal: &str) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(principal).unwrap(),
            local_station(),
        ))
    }

    fn actor_at(principal: &str, station: &str) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new(station).unwrap(),
        ))
    }

    fn realm_id() -> RealmId {
        RealmId::new(REALM.to_owned()).unwrap()
    }

    fn fixture_event_id(seed: &str) -> EventId {
        let digest = arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(seed))
            .expect("fixture digest is typed");
        EventId::from_event_digest(&digest).expect("SHA-256 is a registered Event digest suite")
    }

    /// One committed source Event as the fanout reads it.
    struct Fixture {
        realm_id: RealmId,
        event_id: EventId,
        sender: ActorId,
        kind: EventKind,
        payload: Value,
    }

    impl Fixture {
        fn new(seed: &str, sender: ActorId, kind: EventKind, payload: Value) -> Self {
            Self {
                realm_id: realm_id(),
                event_id: fixture_event_id(seed),
                sender,
                kind,
                payload,
            }
        }

        fn source(&self) -> CommittedSource<'_> {
            CommittedSource {
                realm_id: &self.realm_id,
                event_id: &self.event_id,
                sender: &self.sender,
                kind: &self.kind,
                payload: &self.payload,
            }
        }

        fn plan(&self, basis: &NotificationFanoutBasis) -> Vec<(ActorId, NotificationKind)> {
            plan(&self.source(), basis, &local_station())
                .into_iter()
                .map(|planned| (planned.recipient, planned.notification_kind))
                .collect()
        }
    }

    fn message(seed: &str, sender: ActorId, mentions: &[&ActorId]) -> Fixture {
        let mut content = json!({"kind": "ak.content.text", "body": "hello", "format": "plain"});
        if !mentions.is_empty() {
            content["mentions"] = mentions
                .iter()
                .map(|subject| {
                    json!({
                        "kind": "mention",
                        "subject_account_id": subject.as_account_id().unwrap(),
                        "mention_text_original": "@subject",
                    })
                })
                .collect();
        }
        Fixture::new(
            seed,
            sender,
            EventKind::MessageCreate,
            json!({"strand_id": STRAND, "track_name": "discussion", "content": content}),
        )
    }

    fn assignment(seed: &str, sender: ActorId, assignee: &ActorId) -> Fixture {
        Fixture::new(
            seed,
            sender,
            EventKind::RelationCreate,
            json!({
                "primary_conflict_domain": {
                    "domain_kind": "tuple",
                    "relation_kind": "assigned_to",
                    "from_ref": STRAND,
                    "to_ref": assignee,
                },
                "expected_revision": null,
                "relation": {"relation_kind": "assigned_to", "from_ref": STRAND, "to_ref": assignee},
            }),
        )
    }

    fn strand_update(seed: &str, sender: ActorId, patch: Value) -> Fixture {
        Fixture::new(
            seed,
            sender,
            EventKind::StrandUpdate,
            json!({"target_ref": STRAND, "patch": patch}),
        )
    }

    /// A Realm-scope active Strand with `members` joined.
    fn basis(members: &[&ActorId]) -> NotificationFanoutBasis {
        NotificationFanoutBasis {
            joined_members: members.iter().map(|member| (*member).clone()).collect(),
            strand: Some(NotificationStrandScope {
                realm_id: realm_id(),
                active: true,
                scope_circle_id: None,
                circle_members: BTreeSet::new(),
            }),
            watch_levels: BTreeMap::new(),
            active_assignees: BTreeSet::new(),
        }
    }

    fn watching(
        mut basis: NotificationFanoutBasis,
        watches: &[(&ActorId, &str)],
    ) -> NotificationFanoutBasis {
        for (watcher, level) in watches {
            basis
                .watch_levels
                .insert((*watcher).clone(), (*level).to_owned());
        }
        basis
    }

    #[test]
    fn plain_message_does_not_notify_unwatched_members() {
        let (alice, bob, carol) = (actor(ALICE), actor(BOB), actor(CAROL));
        let basis = watching(basis(&[&alice, &bob, &carol]), &[(&carol, "participating")]);
        assert!(
            message("000000009971", alice.clone(), &[])
                .plan(&basis)
                .is_empty()
        );
    }

    #[test]
    fn plain_message_notifies_only_joined_local_all_watchers() {
        let (alice, bob, carol, dave) = (actor(ALICE), actor(BOB), actor(CAROL), actor(DAVE));
        let bob_elsewhere = actor_at(BOB, OTHER_STATION);
        let basis = watching(
            basis(&[&alice, &bob, &carol, &bob_elsewhere]),
            &[
                (&alice, "all"),
                (&bob, "all"),
                (&carol, "participating"),
                (&dave, "all"),
                (&bob_elsewhere, "all"),
            ],
        );
        assert_eq!(
            message("000000009953", alice.clone(), &[]).plan(&basis),
            vec![(bob, NotificationKind::Message)],
            "the sender, a non-watcher, a non-member and another Station's account get no row"
        );
    }

    #[test]
    fn message_without_a_current_strand_fails_closed() {
        let (alice, bob) = (actor(ALICE), actor(BOB));
        let mut basis = watching(basis(&[&alice, &bob]), &[(&bob, "all")]);
        basis.strand = None;
        assert!(
            message("000000009956", alice.clone(), &[&bob])
                .plan(&basis)
                .is_empty()
        );
    }

    #[test]
    fn mention_is_the_only_row_for_a_mentioned_watcher() {
        let (alice, bob) = (actor(ALICE), actor(BOB));
        let basis = watching(basis(&[&alice, &bob]), &[(&bob, "all")]);
        assert_eq!(
            message("000000009973", alice.clone(), &[&bob]).plan(&basis),
            vec![(bob, NotificationKind::Mention)]
        );
    }

    #[test]
    fn muted_watch_suppresses_a_direct_mention() {
        let (alice, bob) = (actor(ALICE), actor(BOB));
        let basis = watching(basis(&[&alice, &bob]), &[(&bob, "muted")]);
        assert!(
            message("000000009975", alice.clone(), &[&bob])
                .plan(&basis)
                .is_empty()
        );
    }

    /// `strand-and-message.md` section 9.4.2: the mention target is one
    /// complete account. The same principal joined from another Station is a
    /// different subject and is never mentioned by it.
    #[test]
    fn mention_does_not_reach_the_same_principal_at_another_station() {
        let (alice, bob) = (actor(ALICE), actor(BOB));
        let bob_elsewhere = actor_at(BOB, OTHER_STATION);
        let basis = basis(&[&alice, &bob, &bob_elsewhere]);
        assert_eq!(
            message("000000009974", alice.clone(), &[&bob]).plan(&basis),
            vec![(bob, NotificationKind::Mention)]
        );
    }

    #[test]
    fn circle_scoped_strand_reaches_only_circle_members() {
        let (alice, bob, carol) = (actor(ALICE), actor(BOB), actor(CAROL));
        let mut basis = watching(basis(&[&alice, &bob, &carol]), &[(&carol, "all")]);
        basis.strand = Some(NotificationStrandScope {
            realm_id: realm_id(),
            active: true,
            scope_circle_id: Some(arkret_wire::CircleId::new(CIRCLE).unwrap()),
            circle_members: [alice.clone(), bob.clone()].into_iter().collect(),
        });
        assert_eq!(
            message("000000009976", alice.clone(), &[&bob, &carol]).plan(&basis),
            vec![(bob, NotificationKind::Mention)],
            "a mentioned or watching Realm member outside the Circle gets no row"
        );
    }

    #[test]
    fn assignment_notifies_a_visible_unmuted_assignee_of_an_active_strand() {
        let (alice, bob) = (actor(ALICE), actor(BOB));
        let members = basis(&[&alice, &bob]);
        assert_eq!(
            assignment("000000009994", alice.clone(), &bob).plan(&members),
            vec![(bob.clone(), NotificationKind::Assignment)]
        );
        assert!(
            assignment("000000009995", bob.clone(), &bob)
                .plan(&members)
                .is_empty(),
            "self-assignment does not notify"
        );
        let muted = watching(members.clone(), &[(&bob, "muted")]);
        assert!(
            assignment("000000009996", alice.clone(), &bob)
                .plan(&muted)
                .is_empty()
        );
        let mut archived = members;
        archived.strand.as_mut().unwrap().active = false;
        assert!(
            assignment("000000009993", alice.clone(), &bob)
                .plan(&archived)
                .is_empty()
        );
    }

    #[test]
    fn due_date_update_notifies_assignees_and_all_watchers() {
        let (alice, bob, carol, dave) = (actor(ALICE), actor(BOB), actor(CAROL), actor(DAVE));
        let mut basis = watching(
            basis(&[&alice, &bob, &carol, &dave]),
            &[(&carol, "all"), (&dave, "participating")],
        );
        basis.active_assignees = [alice.clone(), bob.clone()].into_iter().collect();
        let update = strand_update(
            "000000009998",
            alice.clone(),
            json!({"metadata.fields.due_at": {"$op": "set", "value": "2026-07-06T00:00:00.000Z"}}),
        );
        let mut planned = update.plan(&basis);
        planned.sort_by_key(|(recipient, _)| recipient.to_string());
        let mut expected = vec![
            (bob, NotificationKind::Schedule),
            (carol, NotificationKind::Schedule),
        ];
        expected.sort_by_key(|(recipient, _)| recipient.to_string());
        assert_eq!(planned, expected);
    }

    #[test]
    fn non_due_date_changes_never_emit_a_schedule_notification() {
        let (alice, bob) = (actor(ALICE), actor(BOB));
        let mut basis = basis(&[&alice, &bob]);
        basis.active_assignees = [bob.clone()].into_iter().collect();
        let calendar = strand_update(
            "000000009933",
            alice.clone(),
            json!({"metadata.fields.calendar": {"$op": "set", "value": {"start": "2026-07-06T09:00:00"}}}),
        );
        assert!(calendar.plan(&basis).is_empty());
        let rsvp = Fixture::new(
            "000000009948",
            alice.clone(),
            EventKind::RsvpSet,
            json!({"event_ref": STRAND}),
        );
        assert!(rsvp.plan(&basis).is_empty());
    }

    #[test]
    fn due_date_patch_detection_accepts_only_canonical_patch_values() {
        assert!(patch_touches_due_schedule(&json!({
            "patch": {"metadata.fields": {
                "$op": "set",
                "value": {"due_at": "2026-09-01T00:00:00.000Z"}
            }}
        })));
        assert!(patch_touches_due_schedule(&json!({
            "patch": {"metadata": {"fields": {"due_at": "2026-09-01T00:00:00.000Z"}}}
        })));
        assert!(!patch_touches_due_schedule(&json!({
            "patch": {"metadata.fields": {"$op": "unset", "value": {"due_at": null}}}
        })));
        assert!(!patch_touches_due_schedule(&json!({
            "patch": {"metadata.fields": {"fields": {"due_at": "unstructured"}}}
        })));
    }

    async fn notifications_for(state: &AppState, recipient: &ActorId) -> Vec<Value> {
        state
            .deliveries()
            .list_recipient_notifications(
                coland_services::delivery::ListRecipientNotificationsQuery {
                    recipient_id: recipient.to_string(),
                },
            )
            .await
            .expect("notification query")
            .into_iter()
            .map(|record| {
                serde_json::to_value(record.notification).expect("encode typed notification")
            })
            .collect()
    }

    #[tokio::test]
    async fn watch_all_message_row_is_persisted_with_its_source_identity() {
        let state = test_state();
        let (alice, bob) = (actor(ALICE), actor(BOB));
        let basis = watching(basis(&[&alice, &bob]), &[(&bob, "all")]);
        let delivered = message("000000009952", alice.clone(), &[]);
        fan_out(&state, &delivered.source(), &basis).await;

        let rows = notifications_for(&state, &bob).await;
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row["notification_kind"], "message");
        assert_eq!(row["strand_id"], STRAND);
        assert_eq!(row["track_name"], "discussion");
        assert_eq!(row["source_event_id"], delivered.event_id.as_str());
        assert_eq!(
            row["source_ref"],
            arkret_identifiers::MessageId::from_event_id(&delivered.event_id).as_str()
        );
        assert_eq!(row["preview"]["body"], "hello");
        assert!(notifications_for(&state, &alice).await.is_empty());
    }

    async fn put_agent(state: &AppState, agent: &str, controller: &str, verification_method: &str) {
        let controller_account = actor(controller).as_account_id().unwrap().clone();
        state
            .identities()
            .save_account(coland_services::identity::AccountProfileState {
                // The store assigns the primary key.
                pk: coland_storage::AccountPk(0),
                principal_id: controller_account.principal_id.clone(),
                account_id: controller_account.clone(),
                localpart: "controller".to_owned(),
                display_name: None,
                biography: None,
                avatar_blob_ref: None,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let mut record = coland_services::identity::AgentPairingState::new(
            agent.to_owned(),
            controller.to_owned(),
            REALM.to_owned(),
            arkret_wire::DidUrl::new(verification_method.to_owned()).unwrap(),
            arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
            chrono::Utc::now(),
        );
        record.agent_slug = Some("summary".to_owned());
        record.display_name = Some("Summary".to_owned());
        record.controller_account_pk = Some(
            state
                .identities()
                .account(&controller_account)
                .await
                .expect("controller account lookup")
                .expect("controller account was just saved")
                .pk,
        );
        state
            .agent_pairings()
            .save_agent(record)
            .await
            .expect("agent record");
    }

    async fn set_selection(
        state: &AppState,
        scope: Value,
        scope_kind: &str,
        scope_key: String,
        third_party_mention_delivery_allowed: bool,
        expected_version: u64,
    ) {
        assert!(
            state
                .agent_participations()
                .compare_and_swap_selection(
                    json!({
                        "agent_id": AGENT,
                        "scope_kind": scope_kind,
                        "scope_key": scope_key,
                        "realm_id": REALM,
                        "scope": scope,
                        "version": expected_version + 1,
                        "message_creation_allowed": true,
                        "reaction_addition_allowed": false,
                        "reaction_removal_allowed": false,
                        "third_party_mention_delivery_allowed": third_party_mention_delivery_allowed,
                        "acting_on_behalf_allowed": false,
                    }),
                    expected_version
                )
                .await
                .expect("agent participation selection")
        );
    }

    async fn set_realm_selection(state: &AppState, accept: bool, expected_version: u64) {
        set_selection(
            state,
            json!({"kind": "realm", "realm_id": REALM}),
            "realm",
            realm_scope_key(REALM),
            accept,
            expected_version,
        )
        .await;
    }

    #[tokio::test]
    async fn selection_changes_do_not_replay_mentions_or_supply_missing_accepted_current() {
        let state = test_state();
        let (controller, third_party, agent) = (actor(ALICE), actor(BOB), actor(AGENT));
        let basis = basis(&[&controller, &third_party, &agent]);
        put_agent(
            &state,
            AGENT,
            ALICE,
            "did:webvh:z6mkalicesummary:agents.example#managed-controller",
        )
        .await;
        set_realm_selection(&state, false, 0).await;

        let suppressed = message("000000009982", third_party.clone(), &[&agent]);
        fan_out(&state, &suppressed.source(), &basis).await;
        assert!(notifications_for(&state, &agent).await.is_empty());

        let by_controller = message("000000009983", controller.clone(), &[&agent]);
        fan_out(&state, &by_controller.source(), &basis).await;
        assert!(notifications_for(&state, &agent).await.is_empty());

        let foreign_controller = message("000000009986", actor_at(ALICE, OTHER_STATION), &[&agent]);
        fan_out(&state, &foreign_controller.source(), &basis).await;
        assert_eq!(
            notifications_for(&state, &agent).await.len(),
            0,
            "the same principal at another Station does not bypass the third-party mention gate"
        );

        set_realm_selection(&state, true, 1).await;
        let after_flip = notifications_for(&state, &agent).await;
        assert_eq!(
            after_flip.len(),
            0,
            "a flipped selection is not retroactive"
        );

        let delivered = message("000000009984", third_party.clone(), &[&agent]);
        fan_out(&state, &delivered.source(), &basis).await;
        let rows = notifications_for(&state, &agent).await;
        assert!(
            rows.is_empty(),
            "selection alone cannot supply accepted PCR and governance current"
        );
        assert!(
            !rows
                .iter()
                .any(|row| row["source_event_id"] == suppressed.event_id.as_str())
        );
    }

    #[tokio::test]
    async fn circle_selection_cannot_supply_missing_accepted_governance_for_strand_mentions() {
        let state = test_state();
        let (controller, third_party, agent) = (actor(ALICE), actor(BOB), actor(AGENT));
        let mut basis = basis(&[&controller, &third_party, &agent]);
        basis.strand = Some(NotificationStrandScope {
            realm_id: realm_id(),
            active: true,
            scope_circle_id: Some(arkret_wire::CircleId::new(CIRCLE).unwrap()),
            circle_members: [controller.clone(), third_party.clone(), agent.clone()]
                .into_iter()
                .collect(),
        });
        put_agent(
            &state,
            AGENT,
            ALICE,
            "did:webvh:z6mkalicesummary:agents.example#managed-controller",
        )
        .await;
        set_realm_selection(&state, false, 0).await;
        set_selection(
            &state,
            json!({"kind": "circle", "realm_id": REALM, "circle_id": CIRCLE}),
            "circle",
            circle_scope_key(REALM, CIRCLE),
            true,
            0,
        )
        .await;

        let delivered = message("000000009990", third_party.clone(), &[&agent]);
        fan_out(&state, &delivered.source(), &basis).await;
        assert!(notifications_for(&state, &agent).await.is_empty());
        set_selection(
            &state,
            json!({"kind": "circle", "realm_id": REALM, "circle_id": CIRCLE}),
            "circle",
            circle_scope_key(REALM, CIRCLE),
            false,
            1,
        )
        .await;
        let capped = message("000000009991", third_party.clone(), &[&agent]);
        fan_out(&state, &capped.source(), &basis).await;
        let rows = notifications_for(&state, &agent).await;
        assert!(rows.is_empty());
        assert!(
            !rows
                .iter()
                .any(|row| row["source_event_id"] == capped.event_id.as_str())
        );
    }
}
