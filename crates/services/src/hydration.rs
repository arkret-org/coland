use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::EventPayloadExt as _;
use arkret_identifiers::{CircleId, DidCoreId, RealmId};
use arkret_models_collaboration::events_payloads::{ContentBlock, RealmPurpose};
use arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload;
use arkret_models_collaboration::objects::space::ChildScopePolicy;
use arkret_wire::{CommitStreamRef, Event, PlaintextDataClassKind};
use coland_domain::reducer::ProjectionState;
use coland_storage::{CanonicalEventRecord, RealmMetaRecord};
use serde_json::Value;

use crate::events::{DirectoryProvenance, RealmDirectoryEntry, RealmDirectoryIndex};

pub trait HydrationProjectionAdapter: Send + Sync {
    fn operation_from_canonical_record(
        &self,
        record: &crate::events::AcceptedEvent,
    ) -> Option<arkret_event_draft::ProjectedEventOperation>;
}

fn application_canonical_event(record: &CanonicalEventRecord) -> crate::events::AcceptedEvent {
    record.clone()
}

fn plaintext_service_classes_from_value(
    payload: &Value,
) -> BTreeMap<String, BTreeSet<PlaintextDataClassKind>> {
    let mut by_service = BTreeMap::new();
    if let Some(items) = payload.get("services").and_then(Value::as_array) {
        merge_typed_plaintext_services(items, &mut by_service);
    }
    if let Some(items) = payload
        .get("plaintext_visible_services")
        .and_then(Value::as_array)
    {
        merge_typed_plaintext_services(items, &mut by_service);
    }
    by_service
}

fn merge_typed_plaintext_services(
    items: &[Value],
    by_service: &mut BTreeMap<String, BTreeSet<PlaintextDataClassKind>>,
) {
    let typed = serde_json::to_value(serde_json::json!({ "services": items }))
        .ok()
        .and_then(|value| serde_json::from_value::<PlaintextVisibleServicesPayload>(value).ok());
    if let Some(typed) = typed {
        for service in typed.services {
            by_service
                .entry(service.service_id.as_str().to_owned())
                .or_default()
                .extend(service.data_classes);
        }
        return;
    }
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        let Some(service_id) = object
            .get("service_id")
            .and_then(Value::as_str)
            .filter(|value| DidCoreId::new((*value).to_owned()).is_ok())
        else {
            continue;
        };
        let classes = object
            .get("data_classes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|value| {
                serde_json::from_value::<PlaintextDataClassKind>(value.clone()).ok()
            })
            .collect::<BTreeSet<_>>();
        if !classes.is_empty() {
            by_service
                .entry(service_id.to_owned())
                .or_default()
                .extend(classes);
        }
    }
}

fn canonical_value_digest(value: &Value) -> Option<String> {
    arkret_canonical::canonical_sha256(value).ok()
}

pub fn parse_child_scope_policy(
    kind: Option<&str>,
    scope_circle_id: Option<&str>,
) -> Result<Option<ChildScopePolicy>, &'static str> {
    let policy = match (kind, scope_circle_id) {
        (None, None) => return Ok(None),
        (Some("allow_any"), None) => ChildScopePolicy::AllowAny {},
        (Some("require_e2ee"), None) => ChildScopePolicy::RequireE2ee {},
        (Some("require_same_scope"), None) => ChildScopePolicy::RequireSameScope {},
        (Some("require_scope_circle_id"), Some(scope_circle_id)) => {
            let scope_circle_id =
                CircleId::new(scope_circle_id.to_owned()).map_err(|_| "invalid_scope_circle_id")?;
            ChildScopePolicy::RequireScopeCircleId { scope_circle_id }
        }
        _ => return Err("invalid_child_scope_policy"),
    };
    Ok(Some(policy))
}

fn operation_from_hydration_record(
    projection_adapter: &dyn HydrationProjectionAdapter,
    record: &CanonicalEventRecord,
    projection_name: &str,
) -> coland_storage::PersistenceResult<arkret_event_draft::ProjectedEventOperation> {
    projection_adapter
        .operation_from_canonical_record(&application_canonical_event(record))
        .ok_or_else(|| {
            coland_storage::PersistenceError::Internal(format!(
                "{projection_name} canonical Event {} cannot be projected",
                record.event_id
            ))
        })
}

fn replay_hydration_record(
    projection_adapter: &dyn HydrationProjectionAdapter,
    proj: &mut ProjectionState,
    record: CanonicalEventRecord,
    hydration_hlc: &coland_domain::hlc::ServerHlc,
    projection_name: &str,
) -> coland_storage::PersistenceResult<()> {
    replay_hydration_record_with_commit(
        projection_adapter,
        proj,
        record,
        hydration_hlc,
        projection_name,
        None,
    )
}

fn replay_hydration_record_with_commit(
    projection_adapter: &dyn HydrationProjectionAdapter,
    proj: &mut ProjectionState,
    record: CanonicalEventRecord,
    hydration_hlc: &coland_domain::hlc::ServerHlc,
    projection_name: &str,
    committed_ref: Option<arkret_wire::CommittedEventRef>,
) -> coland_storage::PersistenceResult<()> {
    let mut operation =
        operation_from_hydration_record(projection_adapter, &record, projection_name)?;
    if let Some(reference) = committed_ref {
        operation = operation
            .with_committed_ref(reference)
            .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))?;
    }
    let effect = match operation.event_kind {
        arkret_wire::EventKind::CircleCreate => {
            proj.restore_accepted_circle_create(&operation, operation.created_at)
        }
        arkret_wire::EventKind::CircleMemberState => {
            proj.restore_accepted_circle_membership(&operation, operation.created_at)
        }
        _ => proj.apply(&operation, hydration_hlc),
    };
    if let coland_domain::reducer::ProjectionEffect::Rejected { reason } = effect {
        return Err(coland_storage::PersistenceError::Internal(format!(
            "{projection_name} projection event {} failed deterministic hydration: {reason}",
            record.event_id
        )));
    }
    Ok(())
}

/// Project the durable Sidecar lifecycle column back onto the SDK enum.
///
/// The durable column is deliberately service-local: a Sidecar's lifecycle is
/// settled on its own commit stream and is not a producer Event field, so the
/// two enums are converted at this boundary rather than aliased.
fn sidecar_projection_state(
    state: coland_storage::SidecarLifecycleState,
) -> arkret_models_collaboration::agent_sidecar::AgentSidecarState {
    use arkret_models_collaboration::agent_sidecar::AgentSidecarState;

    match state {
        coland_storage::SidecarLifecycleState::Active => AgentSidecarState::Active,
        coland_storage::SidecarLifecycleState::Suspended => AgentSidecarState::Suspended,
        coland_storage::SidecarLifecycleState::Tombstoned => AgentSidecarState::Tombstoned,
    }
}

pub async fn hydrate_sidecar_projections(
    persistence: &dyn coland_storage::PersistenceStore,
    proj: &mut ProjectionState,
    _hydration_hlc: &coland_domain::hlc::ServerHlc,
) -> coland_storage::PersistenceResult<()> {
    use coland_domain::reducer::SidecarProjection;

    let records = persistence.sidecars().snapshot_all().await?;
    for record in records {
        proj.sidecars.insert(
            record.sidecar_id.clone(),
            SidecarProjection {
                sidecar_id: record.sidecar_id,
                realm_id: record.realm_id,
                controller_account_id: record.controller_account_id,
                state: sidecar_projection_state(record.state),
                state_changed_at: record.state_changed_at,
                created_at: record.created_at,
                updated_at: record.updated_at,
            },
        );
    }

    let events = hydration_replay_records(persistence).await?;
    for event in events {
        if event.kind == arkret_wire::EventKind::SidecarCreate.as_str() {
            let Ok(event_id) = arkret_wire::EventId::new(event.event_id.clone()) else {
                continue;
            };
            let sidecar_id = arkret_wire::SidecarId::from_event_id(&event_id).into_string();
            if proj.sidecars.contains_key(&sidecar_id) {
                proj.sidecar_create_refs.insert(sidecar_id, event.event_id);
            }
        }
    }
    Ok(())
}

pub async fn hydrate_sidecar_context_projections(
    persistence: &dyn coland_storage::PersistenceStore,
    proj: &mut ProjectionState,
    hydration_hlc: &coland_domain::hlc::ServerHlc,
    projection_adapter: &dyn HydrationProjectionAdapter,
) -> coland_storage::PersistenceResult<()> {
    let events = hydration_replay_records(persistence).await?;
    for event in events {
        if event.kind == arkret_wire::EventKind::SidecarContextAttach.as_str() {
            replay_hydration_record(
                projection_adapter,
                proj,
                event,
                hydration_hlc,
                "sidecar-context-attach",
            )?;
        }
    }
    Ok(())
}

/// Every committed canonical Event replays, in commit-stream order.
///
/// The retired dual plane split this selection into a confirmed command
/// prefix and an independently published ordinary tail. A canonical Event is
/// committed only because a `RealmCommit` named it on its Realm, Circle or
/// Sidecar stream, so there is no second plane to reconcile and no timeline
/// publication check left to apply.
async fn hydration_replay_records(
    persistence: &dyn coland_storage::PersistenceStore,
) -> coland_storage::PersistenceResult<Vec<CanonicalEventRecord>> {
    let records = persistence.events().snapshot_all().await?;
    ordered_hydration_replay_records(persistence, records).await
}

async fn ordered_hydration_replay_records(
    persistence: &dyn coland_storage::PersistenceStore,
    records: Vec<CanonicalEventRecord>,
) -> coland_storage::PersistenceResult<Vec<CanonicalEventRecord>> {
    let mut ordered = BTreeMap::new();
    for record in records {
        let id = arkret_wire::EventId::new(record.event_id.clone())
            .map_err(coland_storage::PersistenceError::database)?;
        let accepted = persistence
            .authority_commits()
            .committed_event(&id)
            .await?
            .ok_or_else(|| {
                coland_storage::PersistenceError::Internal(
                    "hydration canonical Event has no accepting Commit".to_owned(),
                )
            })?;
        // The accepting Event may be decoded from the same canonical mirror;
        // compare its content-derived identity with the Commit's frozen ref.
        accepted
            .event
            .verify_event_id_matches_content_with_digest_suite(record.digest_suite)
            .map_err(|_| {
                coland_storage::PersistenceError::Internal(
                    "hydration canonical Event differs from its Commit binding".to_owned(),
                )
            })?;
        if serde_json::to_value(&accepted.event)
            .map_err(coland_storage::PersistenceError::database)?
            != record.envelope
        {
            return Err(coland_storage::PersistenceError::Internal(
                "hydration canonical Event differs from its Commit binding".to_owned(),
            ));
        }
        let stream = arkret_canonical::canonical_json_bytes(&accepted.commit.stream_ref)
            .map_err(coland_storage::PersistenceError::database)?;
        if ordered
            .insert((stream, accepted.commit.stream_position), record)
            .is_some()
        {
            return Err(coland_storage::PersistenceError::Internal(
                "hydration contains two Events at one Commit stream position".to_owned(),
            ));
        }
    }
    Ok(ordered.into_values().collect())
}

fn install_relation_current_states(
    proj: &mut ProjectionState,
    records: Vec<coland_storage::RelationCurrentStateRecord>,
) -> coland_storage::PersistenceResult<()> {
    use arkret_wire::RelationState;
    use coland_domain::reducer::{ColandRelationState, RelationCurrentStateProjection};

    let mut staged_relations = std::collections::BTreeMap::new();
    let mut staged_current = std::collections::BTreeMap::new();
    let mut staged_metadata = std::collections::BTreeMap::new();
    for record in records {
        let relation = record.relation;
        let relation_id = relation.id.clone().ok_or_else(|| {
            coland_storage::PersistenceError::Internal(
                "durable Relation current value has no derived id".to_owned(),
            )
        })?;
        let source_event_id = arkret_wire::EventId::from_token_bytes(relation_id.token_bytes())
            .map_err(|error| {
                coland_storage::PersistenceError::Internal(format!(
                    "durable Relation id cannot be retyped as its create Event: {error}"
                ))
            })?;
        let state = match relation.state {
            Some(RelationState::Active) => "active",
            Some(RelationState::Tombstoned) => "tombstoned",
            None => {
                return Err(coland_storage::PersistenceError::Internal(
                    "durable Relation current value has no lifecycle state".to_owned(),
                ));
            }
        };
        let relation_id = relation_id.to_string();
        let current_key = (record.realm_id.to_string(), record.domain_key);
        if staged_current.contains_key(&current_key) || staged_relations.contains_key(&relation_id)
        {
            return Err(coland_storage::PersistenceError::Internal(
                "durable Relation current results contain duplicate identity".to_owned(),
            ));
        }
        staged_current.insert(current_key.clone(), relation_id.clone());
        staged_metadata.insert(
            current_key,
            RelationCurrentStateProjection {
                relation_id: relation_id.clone(),
                primary_conflict_domain: record.primary_conflict_domain,
                revision: record.revision,
            },
        );
        staged_relations.insert(
            relation_id.clone(),
            ColandRelationState {
                relation_id,
                realm_id: record.realm_id.to_string(),
                relation_kind: relation.relation_kind.as_str().to_owned(),
                scope_circle_id: relation.scope_circle_id.map(|id| id.to_string()),
                from_ref: Some(relation.from_ref),
                to_ref: Some(relation.to_ref),
                rank: relation.rank,
                fields: relation.fields,
                state: state.to_owned(),
                source_event_id: Some(source_event_id.to_string()),
                source_event_digest: Some(source_event_id.event_digest().to_string()),
                created_at: relation.created_at,
                updated_at: relation.updated_at.unwrap_or(relation.created_at),
            },
        );
    }
    let previous_current_ids = proj
        .relation_current
        .values()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if staged_relations
        .keys()
        .any(|id| proj.relations.contains_key(id) && !previous_current_ids.contains(id))
    {
        return Err(coland_storage::PersistenceError::Internal(
            "durable Relation current result collides with a non-current projection".to_owned(),
        ));
    }
    // Preserve derived Relation edges and canonical history already rebuilt by
    // other reducers. Only replace the prior direct-current cache.
    proj.relations
        .retain(|relation_id, _| !previous_current_ids.contains(relation_id));
    proj.relations.extend(staged_relations);
    proj.relation_current = staged_current;
    proj.relation_current_metadata = staged_metadata;
    Ok(())
}

/// Rebuild ordinary Realm genesis from its exact confirmed command unit.
/// Raw admission, actor sequence and timestamps confer no execution outcome.
async fn hydrate_canonical_realm_bootstraps(
    persistence: &dyn coland_storage::PersistenceStore,
    proj: &mut ProjectionState,
    hydration_hlc: &coland_domain::hlc::ServerHlc,
    projection_adapter: &dyn HydrationProjectionAdapter,
) -> coland_storage::PersistenceResult<()> {
    use coland_domain::reducer::ProjectionEffect;

    let records = hydration_replay_records(persistence).await?;
    for create in records
        .iter()
        .filter(|record| record.kind == arkret_wire::EventKind::RealmCreate.as_str())
    {
        // PCR and Agent control Realms have their own closed genesis
        // protocols. They are durable canonical Events too, but they are not
        // ordinary Realm bootstrap transactions and must never be fed to the
        // ordinary Realm validator/reducer below.
        //
        // Decode the shared wire DTO before selecting the hydration branch.
        // Inspecting an untyped JSON field here previously let the live and
        // restart paths silently grow different interpretations.
        let create_event =
            serde_json::from_value::<Event>(create.envelope.clone()).map_err(|error| {
                coland_storage::PersistenceError::Internal(format!(
                    "canonical Realm create failed SDK Event decode: {error}"
                ))
            })?;
        let create_payload = create_event
            .typed_payload::<arkret_wire::event_spec::RealmCreate>()
            .map_err(|error| {
                coland_storage::PersistenceError::Internal(format!(
                    "canonical Realm create failed typed payload decode: {error}"
                ))
            })?;
        if matches!(
            create_payload.object.purpose,
            RealmPurpose::PrincipalControl | RealmPurpose::AgentControl
        ) {
            continue;
        }

        // A current ordinary bootstrap is one confirmed Realm stream prefix.
        // `snapshot_all` orders by receive time and Event id, neither of which
        // proves the order of Events committed in an atomic bootstrap. Read
        // the first stream positions instead and restore every facet before
        // the later membership replay. Legacy single-Event genesis remains
        // on the established path below.
        if let Some(facets) =
            confirmed_ordinary_bootstrap_facets(persistence, &records, &create_event).await?
        {
            let operations = facets
                .iter()
                .map(|record| {
                    projection_adapter
                        .operation_from_canonical_record(&application_canonical_event(record))
                        .ok_or_else(|| {
                            coland_storage::PersistenceError::Internal(format!(
                                "ordinary bootstrap Event {} cannot rebuild its projection operation",
                                record.event_id
                            ))
                        })
                })
                .collect::<coland_storage::PersistenceResult<Vec<_>>>()?;
            let mut staged = proj.clone();
            crate::projection::ProjectionService::apply_realm_bootstrap_to_state(
                &mut staged,
                &operations,
                false,
                hydration_hlc,
            )
            .map_err(|error| {
                coland_storage::PersistenceError::Internal(format!(
                    "confirmed ordinary bootstrap failed deterministic hydration at slot {}: {}",
                    error.operation_index, error.reason
                ))
            })?;
            *proj = staged;
            continue;
        }

        // Realm creation is one producer-signed `ak.realm.create` Event. The
        // multi-Event bootstrap unit and the confirmed-order selector that
        // rebuilt it no longer exist: ordering and predecessor binding are
        // properties of the Realm commit stream, so hydration validates the
        // genesis Event itself and leaves every later genesis facet to the
        // ordinary replay paths that already own those Event kinds.
        arkret_policy::realm_bootstrap::validate_realm_genesis_event(&create_event).map_err(
            |error| {
                coland_storage::PersistenceError::Internal(format!(
                    "canonical Realm genesis failed deterministic validation: {error}"
                ))
            },
        )?;

        let Some(operation) = projection_adapter
            .operation_from_canonical_record(&application_canonical_event(create))
        else {
            return Err(coland_storage::PersistenceError::Internal(format!(
                "Realm genesis Event {} cannot rebuild its projection operation",
                create.event_id
            )));
        };
        let mut staged = proj.clone();
        match staged.apply_projected(&operation, hydration_hlc) {
            ProjectionEffect::Rejected { reason } => {
                return Err(coland_storage::PersistenceError::Internal(format!(
                    "Realm genesis Event {} failed deterministic hydration: {reason}",
                    create.event_id
                )));
            }
            ProjectionEffect::Ignored => {
                return Err(coland_storage::PersistenceError::Internal(format!(
                    "Realm genesis Event {} was ignored during deterministic hydration",
                    create.event_id
                )));
            }
            _ => {}
        }
        *proj = staged;
    }
    Ok(())
}

async fn confirmed_ordinary_bootstrap_facets(
    persistence: &dyn coland_storage::PersistenceStore,
    records: &[CanonicalEventRecord],
    create: &Event,
) -> coland_storage::PersistenceResult<Option<Vec<CanonicalEventRecord>>> {
    use arkret_schema::{
        RealmBootstrapPresence, RealmBootstrapProfile, realm_bootstrap_profile_descriptor,
    };
    use arkret_wire::{CommitStreamRef, StreamScanDirection, StreamScanRequestBody};

    let request = StreamScanRequestBody {
        realm_id: create.realm_id.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: create.realm_id.clone(),
        },
        direction: StreamScanDirection::After(None),
        limit: 9,
    };
    let scan = persistence
        .authority_commits()
        .scan_stream(&request)
        .await?;
    scan.validate_for_request(&request).map_err(|error| {
        coland_storage::PersistenceError::Internal(format!(
            "ordinary bootstrap confirmed stream is invalid: {error}"
        ))
    })?;
    let items = &scan.committed_events;
    if items
        .first()
        .is_none_or(|item| item.commit().event_ref != create.event_id)
    {
        return Ok(None);
    }
    if items.get(1).is_none_or(|item| {
        item.reducer_input()
            .is_none_or(|event| event.kind != arkret_wire::EventKind::RealmProfile)
    }) {
        return Ok(None);
    }
    let mut prefix = Vec::new();
    for (position, item) in items.iter().enumerate() {
        if item.commit().stream_position != position as u64 {
            return Err(coland_storage::PersistenceError::Internal(
                "ordinary bootstrap confirmed positions are discontinuous".to_owned(),
            ));
        }
        let event = item.reducer_input().ok_or_else(|| {
            coland_storage::PersistenceError::Internal(
                "ordinary bootstrap confirmed Event was withheld".to_owned(),
            )
        })?;
        if event.actor_id != create.actor_id || event.realm_id != create.realm_id {
            return Err(coland_storage::PersistenceError::Internal(
                "ordinary bootstrap confirmed actor or Realm changed".to_owned(),
            ));
        }
        prefix.push(event);
        if event.kind == arkret_wire::EventKind::MemberState {
            break;
        }
    }
    let slots = realm_bootstrap_profile_descriptor(RealmBootstrapProfile::OrdinaryCollaboration)
        .ordered_slots;
    let mut cursor = prefix.iter().peekable();
    for slot in slots {
        if cursor
            .peek()
            .is_some_and(|event| event.kind.as_str() == slot.event_kind)
        {
            cursor.next();
        } else if slot.presence == RealmBootstrapPresence::Required {
            return Err(coland_storage::PersistenceError::Internal(format!(
                "confirmed ordinary bootstrap is missing required slot {}",
                slot.event_kind
            )));
        }
    }
    if cursor.next().is_some()
        || prefix
            .last()
            .is_none_or(|event| event.kind != arkret_wire::EventKind::MemberState)
    {
        return Err(coland_storage::PersistenceError::Internal(
            "confirmed ordinary bootstrap has an unregistered or incomplete prefix".to_owned(),
        ));
    }
    // Membership is rebuilt once by `hydrate_canonical_realm_memberships`,
    // after every Realm genesis has been installed. Apply the other facets in
    // exact Commit order here.
    prefix.pop();
    let by_id = records
        .iter()
        .map(|record| (record.event_id.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    prefix
        .into_iter()
        .map(|event| {
            by_id
                .get(event.event_id.as_str())
                .map(|record| (*record).clone())
                .ok_or_else(|| {
                    coland_storage::PersistenceError::Internal(format!(
                        "confirmed ordinary bootstrap Event {} is missing from canonical snapshot",
                        event.event_id
                    ))
                })
        })
        .collect::<coland_storage::PersistenceResult<Vec<_>>>()
        .map(Some)
}

/// Rebuild Agent and Applet-managed PCR state from canonical Events.
///
/// These PCRs deliberately do not enter the ordinary Realm bootstrap unit:
/// their genesis is admitted inside a closed Agent or Applet aggregate.
/// Once accepted, however, the canonical genesis and its ordinary
/// `ak.identity.resolution.update` successors are the sole source of current
/// identity state. Replay therefore derives the same registered cells in
/// confirmed command order. Agent lifecycle must be restored before
/// ordinary Realm membership is replayed.
async fn hydrate_managed_pcr_identity(
    persistence: &dyn coland_storage::PersistenceStore,
    proj: &mut ProjectionState,
    hydration_hlc: &coland_domain::hlc::ServerHlc,
    projection_adapter: &dyn HydrationProjectionAdapter,
) -> coland_storage::PersistenceResult<()> {
    use coland_domain::reducer::ProjectionEffect;

    let records = hydration_replay_records(persistence).await?;
    let mut managed_pcr_realms = BTreeSet::new();
    for record in records
        .iter()
        .filter(|record| record.kind == arkret_wire::EventKind::RealmCreate.as_str())
    {
        let event = serde_json::from_value::<Event>(record.envelope.clone()).map_err(|error| {
            coland_storage::PersistenceError::Internal(format!(
                "canonical Managed PCR create failed SDK Event decode: {error}"
            ))
        })?;
        let payload = event
            .typed_payload::<arkret_wire::event_spec::RealmCreate>()
            .map_err(|error| {
                coland_storage::PersistenceError::Internal(format!(
                    "canonical Managed PCR create failed typed payload decode: {error}"
                ))
            })?;
        if matches!(payload.object.purpose, RealmPurpose::AgentControl) {
            managed_pcr_realms.insert(record.realm_id.clone());
        }
    }

    let lineage = records
        .into_iter()
        .filter(|record| {
            managed_pcr_realms.contains(&record.realm_id)
                && matches!(
                    arkret_wire::EventKind::from_wire(&record.kind),
                    arkret_wire::EventKind::RealmCreate
                        | arkret_wire::EventKind::IdentityResolutionUpdate
                        | arkret_wire::EventKind::SelfAgentPause
                        | arkret_wire::EventKind::SelfAgentResume
                        | arkret_wire::EventKind::SelfAgentDeactivate
                )
        })
        .collect::<Vec<_>>();

    let mut genesis_by_realm = BTreeMap::new();
    let mut current_by_realm = BTreeMap::new();
    for record in lineage {
        let typed = serde_json::from_value::<Event>(record.envelope.clone()).map_err(|error| {
            coland_storage::PersistenceError::Internal(format!(
                "Managed PCR Event {} failed SDK Event decode: {error}",
                record.event_id
            ))
        })?;
        let operation = projection_adapter
            .operation_from_canonical_record(&application_canonical_event(&record))
            .ok_or_else(|| {
                coland_storage::PersistenceError::Internal(format!(
                    "Managed PCR Event {} cannot rebuild its projection operation",
                    record.event_id
                ))
            })?;
        match proj.apply_projected(&operation, hydration_hlc) {
            ProjectionEffect::Rejected { reason } => {
                return Err(coland_storage::PersistenceError::Internal(format!(
                    "Managed PCR Event {} failed deterministic hydration: {reason}",
                    record.event_id
                )));
            }
            ProjectionEffect::Ignored => {
                return Err(coland_storage::PersistenceError::Internal(format!(
                    "Managed PCR Event {} was ignored during deterministic hydration",
                    record.event_id
                )));
            }
            _ => {}
        }
        if typed.kind == arkret_wire::EventKind::RealmCreate {
            genesis_by_realm.insert(typed.realm_id.clone(), typed.clone());
        }
        if matches!(
            typed.kind,
            arkret_wire::EventKind::RealmCreate | arkret_wire::EventKind::IdentityResolutionUpdate
        ) {
            current_by_realm.insert(typed.realm_id.clone(), typed);
        }
    }

    // Repair the durable read index from the same canonical lineage. This is
    // intentionally part of startup hydration: a transient post-commit mirror
    // failure must not leave public current-resolution reads permanently empty
    // or make the next rotation unable to find its PCR lineage.
    for (pcr_realm_id, current_event) in current_by_realm {
        let genesis_event = genesis_by_realm
            .get(&pcr_realm_id)
            .cloned()
            .ok_or_else(|| {
                coland_storage::PersistenceError::Internal(format!(
                    "Managed PCR {} has no canonical genesis during hydration",
                    pcr_realm_id
                ))
            })?;
        let projection_value = proj
            .principal_resolution_for_realm(pcr_realm_id.as_str())
            .cloned()
            .ok_or_else(|| {
                coland_storage::PersistenceError::Internal(format!(
                    "Managed PCR {} did not materialize current resolution during hydration",
                    pcr_realm_id
                ))
            })?;
        let projection = serde_json::from_value(projection_value).map_err(|error| {
            coland_storage::PersistenceError::Internal(format!(
                "Managed PCR {} materialized invalid resolution: {error}",
                pcr_realm_id
            ))
        })?;
        let existing = persistence
            .principal_resolutions()
            .for_realm(&pcr_realm_id)
            .await?;
        if existing
            .as_ref()
            .is_some_and(|record| record.current_event.event_id == current_event.event_id)
        {
            continue;
        }
        let expected = existing
            .as_ref()
            .map(|record| record.current_event.event_id.as_str());
        let account_id = genesis_event
            .actor_id
            .as_account_id()
            .cloned()
            .ok_or_else(|| {
                coland_storage::PersistenceError::Internal(format!(
                    "Managed PCR {} genesis actor is not an AccountId",
                    pcr_realm_id
                ))
            })?;
        let expected_current_event_id = current_event.event_id.clone();
        let next = coland_storage::PrincipalResolutionRecord {
            account_id,
            pcr_realm_id: pcr_realm_id.clone(),
            genesis_event,
            current_event,
            projection,
        };
        match persistence
            .principal_resolutions()
            .compare_and_set(expected, next)
            .await?
        {
            coland_storage::PrincipalResolutionCasResult::Applied(_) => {}
            coland_storage::PrincipalResolutionCasResult::Conflict(Some(record))
                if record.current_event.event_id == expected_current_event_id => {}
            coland_storage::PrincipalResolutionCasResult::Conflict(_) => {
                return Err(coland_storage::PersistenceError::Internal(format!(
                    "Managed PCR {} read-index repair CAS conflict",
                    pcr_realm_id
                )));
            }
        }
    }
    Ok(())
}

/// Rebuild the reducer's Realm membership cache from canonical
/// `ak.member.state` and `ak.invite.accept` Events.
///
/// The Realm directory has its own replay path because it is a query index,
/// but MLS claims, Circle admission and the sidecar membership predicate read
/// `ProjectionState::member`. Replaying only the directory leaves those two
/// views disagreeing after every restart: the member is visible in Realm
/// rosters while the Circle reducer rejects it as a non-member.
pub async fn hydrate_canonical_realm_memberships(
    persistence: &dyn coland_storage::PersistenceStore,
    proj: &mut ProjectionState,
    projection_adapter: &dyn HydrationProjectionAdapter,
) -> coland_storage::PersistenceResult<()> {
    use coland_domain::reducer::ProjectionEffect;

    let all_records = hydration_replay_records(persistence).await?;
    let invite_times = all_records
        .iter()
        .filter(|record| record.kind == arkret_wire::EventKind::InviteCreate.as_str())
        .filter_map(|record| {
            let event = serde_json::from_value::<Event>(record.envelope.clone()).ok()?;
            Some((
                (
                    event.realm_id.to_string(),
                    arkret_wire::InviteId::from_event_id(&event.event_id).to_string(),
                ),
                event.created_at,
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let records = all_records
        .into_iter()
        .filter(|record| {
            matches!(
                arkret_wire::EventKind::from_wire(&record.kind),
                arkret_wire::EventKind::MemberState | arkret_wire::EventKind::InviteAccept
            )
        })
        .collect::<Vec<_>>();

    for record in records {
        let Some(operation) = projection_adapter
            .operation_from_canonical_record(&application_canonical_event(&record))
        else {
            return Err(coland_storage::PersistenceError::Internal(format!(
                "Realm membership Event {} cannot rebuild its projection operation",
                record.event_id
            )));
        };
        if operation.event_kind == arkret_wire::EventKind::InviteAccept {
            let accepted = operation
                .typed_payload::<arkret_wire::event_spec::InviteAccept>()
                .map_err(|error| {
                    coland_storage::PersistenceError::Internal(format!(
                        "accepted invite {} cannot rebuild membership: {error}",
                        record.event_id
                    ))
                })?;
            if operation.context.sender.as_account_id().is_none()
                || accepted.invitee_account_id.as_ref().is_some_and(|account| {
                    operation.context.sender.as_account_id() != Some(account)
                })
            {
                return Err(coland_storage::PersistenceError::Internal(format!(
                    "accepted invite {} has a mismatched account",
                    record.event_id
                )));
            }
            let invited_at = invite_times
                .get(&(
                    operation.realm_id.to_string(),
                    accepted.invite_id.to_string(),
                ))
                .copied()
                .unwrap_or(operation.created_at);
            crate::projection::restore_invite_acceptance_membership(
                proj,
                operation.realm_id.as_str(),
                &operation.context.sender.to_string(),
                invited_at,
                &operation,
            );
            continue;
        }
        match proj.restore_accepted_membership(&operation, operation.created_at) {
            ProjectionEffect::Rejected { reason } => {
                return Err(coland_storage::PersistenceError::Internal(format!(
                    "Realm membership Event {} failed deterministic hydration: {reason}",
                    record.event_id
                )));
            }
            ProjectionEffect::Ignored => {
                return Err(coland_storage::PersistenceError::Internal(format!(
                    "Realm membership Event {} was ignored during deterministic hydration",
                    record.event_id
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Rebuild the process-local reducer cache from durable state at startup.
/// Registered Space and Strand values come from RealmCommit-backed typed
/// current rows; their old mirror tables cannot resurrect stale state.
pub async fn hydrate_projections_from_persistence(
    persistence: &dyn coland_storage::PersistenceStore,
    proj: &mut ProjectionState,
    projection_adapter: &dyn HydrationProjectionAdapter,
) -> coland_storage::PersistenceResult<()> {
    use coland_domain::reducer::{
        MorphProjection, ObjectLifecycleState, SpaceContainerLifecycleState,
        SpaceContainerProjection, StrandProjection, object_stage_from_wire_value,
    };

    let hydration_hlc = coland_domain::hlc::ServerHlc::new("coland:projection-hydration");

    hydrate_managed_pcr_identity(persistence, proj, &hydration_hlc, projection_adapter).await?;
    hydrate_canonical_realm_bootstraps(persistence, proj, &hydration_hlc, projection_adapter)
        .await?;
    hydrate_canonical_realm_memberships(persistence, proj, projection_adapter).await?;
    hydrate_sidecar_projections(persistence, proj, &hydration_hlc).await?;

    // Agent key authorization is consulted by sidecar eligibility and has no
    // mirror-table integration, so restore it from the durable event stream.
    // Agent authorize/revoke transitions must retain confirmed command order;
    // querying each kind independently would lose their relative ordering.
    let events = hydration_replay_records(persistence).await?;
    for event in events.iter().cloned() {
        let projection_name = match arkret_wire::EventKind::from_wire(&event.kind) {
            arkret_wire::EventKind::AgentKeyAuthorize | arkret_wire::EventKind::AgentKeyRevoke => {
                "agent-key"
            }
            _ => continue,
        };
        replay_hydration_record(
            projection_adapter,
            proj,
            event,
            &hydration_hlc,
            projection_name,
        )?;
    }

    fn parse_object_state(value: &str) -> Option<ObjectLifecycleState> {
        match value {
            "active" => Some(ObjectLifecycleState::Active),
            "archived" => Some(ObjectLifecycleState::Archived),
            "redacted" => Some(ObjectLifecycleState::Redacted),
            _ => None,
        }
    }
    // Realm metadata is the durable mirror used by the regular Realm index.
    // Restore the reducer-side Realm cache from the same source as well: the
    // capability reducer reads `realm_states.owner` when checking a root
    // grant issuer's effective upper bound. Without this hydration, an
    // already-existing controller self Realm is visible to `ensure_self_realm`
    // after restart but has no owner in the reducer, so a legitimate
    // controller-authored agent grant is rejected as
    // `grant_exceeds_issuer_authority`.
    if let Ok(rows) = persistence.realm_meta().list().await {
        for (realm_id, record) in rows {
            match proj.realm_states.entry(realm_id.clone()) {
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    // Canonical Event replay owns fields that exist on the
                    // wire (including title and trust-domain).  The durable
                    // mirror may advance operational flags, but must not
                    // replace that richer projection with placeholder data.
                    let realm = entry.get_mut();
                    realm.owner = Some(record.owner);
                    realm.deleted = record.deleted;
                    realm.updated_at = realm.updated_at.max(record.updated_at);
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(coland_domain::reducer::ColandRealmState {
                        realm_id,
                        owner: Some(record.owner),
                        title: None,
                        deleted: record.deleted,

                        created_at: record.created_at,
                        updated_at: record.updated_at,
                        trust_domain: None,
                        terminal_state: None,
                        successor_realm_id: None,
                        default_strand_id: None,
                    });
                }
            }
        }
    }

    // Rebuild the process-local Space/Strand compatibility cache from the same
    // RealmCommit-backed typed current rows used by canonical list reads.
    // The retired projection_spaces/projection_strands mirrors must never
    // resurrect stale state after a restart.
    let current_objects = persistence.object_current_snapshot().snapshot().await?;
    for space in current_objects.spaces {
        let id = space.id.ok_or_else(|| {
            coland_storage::PersistenceError::Internal(
                "registered Space current has no id".to_owned(),
            )
        })?;
        let state = match space.state.ok_or_else(|| {
            coland_storage::PersistenceError::Internal(
                "registered Space current has no lifecycle state".to_owned(),
            )
        })? {
            arkret_wire::SpaceState::Active => SpaceContainerLifecycleState::Active,
            arkret_wire::SpaceState::Archived => SpaceContainerLifecycleState::Archived,
            arkret_wire::SpaceState::Tombstoned => SpaceContainerLifecycleState::Tombstoned,
        };
        proj.space_containers.insert(
            id.to_string(),
            SpaceContainerProjection {
                container_space_id: id.to_string(),
                realm_id: space.realm_id.to_string(),
                kind: space.kind,
                title: space.title.unwrap_or_default(),
                fields: space.fields,
                scope_circle_id: space.scope_circle_id.map(|id| id.to_string()),
                child_scope_policy: space.child_scope_policy,
                parent_ref: space.parent_space_id.map(|id| id.to_string()),
                rank: space.rank,
                state,
                state_changed_at: space.state_changed_at,
                created_by: space.created_by.to_string(),
                created_at: space.created_at,
                updated_by: space.updated_by.map(|id| id.to_string()),
                updated_at: space.updated_at,
                orphaned: false,
            },
        );
    }
    let mut canonical_strands = BTreeMap::new();
    for strand in current_objects.strands {
        let id = strand.id.ok_or_else(|| {
            coland_storage::PersistenceError::Internal(
                "registered Strand current has no id".to_owned(),
            )
        })?;
        let state = match strand.state.ok_or_else(|| {
            coland_storage::PersistenceError::Internal(
                "registered Strand current has no lifecycle state".to_owned(),
            )
        })? {
            arkret_wire::ObjectState::Active => ObjectLifecycleState::Active,
            arkret_wire::ObjectState::Archived => ObjectLifecycleState::Archived,
            arkret_wire::ObjectState::Redacted => ObjectLifecycleState::Redacted,
        };
        let metadata = strand.metadata.unwrap_or_default();
        canonical_strands.insert(
            id.to_string(),
            StrandProjection {
                strand_id: id.to_string(),
                realm_id: strand.realm_id.to_string(),
                tracks: strand.tracks,
                title: metadata.title.unwrap_or_default(),
                summary: metadata.summary,
                content: strand
                    .content
                    .map(serde_json::to_value)
                    .transpose()
                    .map_err(coland_storage::PersistenceError::database)?,
                encrypted_content: strand
                    .encrypted_content
                    .map(serde_json::to_value)
                    .transpose()
                    .map_err(coland_storage::PersistenceError::database)?,
                fields: metadata.fields,
                state,
                state_changed_at: strand.state_changed_at,
                stage: strand.stage,
                stage_changed_at: strand.stage_changed_at,
                created_by: strand.created_by.to_string(),
                created_at: strand.created_at,
                updated_by: strand.updated_by.map(|id| id.to_string()),
                updated_at: strand.updated_at,
                schema_refs: strand.schema_refs.unwrap_or_default(),
                schedule_revision_source: None,
                scope_circle_id: strand.scope_circle_id.map(|id| id.to_string()),
            },
        );
    }
    proj.strands.extend(canonical_strands.clone());
    // The legacy projection_circles mirror can be absent or stale after
    // direct Circle admission. Rebuild this process-local cache only from exact
    // accepted Event/Commit pairs. Each Circle's transitions are ordered by
    // its own authority stream position, never by Event reception time.
    let mut circle_creates = BTreeMap::new();
    let mut circle_transitions = BTreeMap::new();
    for record in events.iter().filter(|record| {
        matches!(
            arkret_wire::EventKind::from_wire(&record.kind),
            arkret_wire::EventKind::CircleCreate
                | arkret_wire::EventKind::CircleUpdate
                | arkret_wire::EventKind::CircleArchive
                | arkret_wire::EventKind::CircleRestore
                | arkret_wire::EventKind::CircleTombstone
                | arkret_wire::EventKind::CircleHistoryAccess
                | arkret_wire::EventKind::CircleMemberState
        )
    }) {
        let id = arkret_wire::EventId::new(record.event_id.clone())
            .map_err(coland_storage::PersistenceError::database)?;
        let accepted = persistence
            .authority_commits()
            .committed_event(&id)
            .await?
            .ok_or_else(|| {
                coland_storage::PersistenceError::Internal(
                    "Circle hydration has no accepting Commit".to_owned(),
                )
            })?;
        if serde_json::to_value(&accepted.event)
            .map_err(coland_storage::PersistenceError::database)?
            != record.envelope
        {
            return Err(coland_storage::PersistenceError::Internal(
                "Circle hydration canonical Event differs from its Commit binding".to_owned(),
            ));
        }
        if record.kind == arkret_wire::EventKind::CircleCreate.as_str() {
            let circle_id = CircleId::from_event_id(&id);
            if !matches!(
                &accepted.commit.stream_ref,
                CommitStreamRef::Realm { realm_id } if realm_id == &accepted.event.realm_id
            ) || accepted.event.scope_ref
                != (arkret_wire::ScopeRef::Realm {
                    realm_id: accepted.event.realm_id.clone(),
                })
                || circle_creates.insert(circle_id, record.clone()).is_some()
            {
                return Err(coland_storage::PersistenceError::Internal(
                    "Circle create hydration has an invalid or duplicate Realm-stream source"
                        .to_owned(),
                ));
            }
        } else {
            let CommitStreamRef::Circle {
                realm_id,
                circle_id,
            } = &accepted.commit.stream_ref
            else {
                return Err(coland_storage::PersistenceError::Internal(
                    "Circle transition hydration is outside its Circle stream".to_owned(),
                ));
            };
            let declared_circle = accepted
                .event
                .payload
                .get("circle_id")
                .or_else(|| accepted.event.payload.get("target_ref"))
                .and_then(Value::as_str);
            if accepted.event.realm_id != *realm_id
                || accepted.event.scope_ref
                    != (arkret_wire::ScopeRef::Circle {
                        realm_id: realm_id.clone(),
                        circle_id: circle_id.clone(),
                    })
                || declared_circle != Some(circle_id.as_str())
                || circle_transitions
                    .insert(
                        (circle_id.clone(), accepted.commit.stream_position),
                        record.clone(),
                    )
                    .is_some()
            {
                return Err(coland_storage::PersistenceError::Internal(
                    "Circle transition hydration has a conflicting Commit position".to_owned(),
                ));
            }
        }
    }
    let rebuilt_circle_ids = circle_creates
        .keys()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    if circle_transitions
        .keys()
        .any(|(circle_id, _)| !rebuilt_circle_ids.contains(circle_id.as_str()))
    {
        return Err(coland_storage::PersistenceError::Internal(
            "Circle transition hydration has no accepted create".to_owned(),
        ));
    }
    for circle_id in &rebuilt_circle_ids {
        proj.circles.remove(circle_id);
    }
    proj.circle_memberships
        .retain(|(circle_id, _), _| !rebuilt_circle_ids.contains(circle_id));
    for record in circle_creates
        .into_values()
        .chain(circle_transitions.into_values())
    {
        replay_hydration_record(
            projection_adapter,
            proj,
            record,
            &hydration_hlc,
            "accepted-circle",
        )?;
    }
    for circle_id in rebuilt_circle_ids {
        let circle = proj.circles.get_mut(&circle_id).ok_or_else(|| {
            coland_storage::PersistenceError::Internal(
                "accepted Circle create did not rebuild its projection".to_owned(),
            )
        })?;
        let realm_id = RealmId::new(circle.realm_id.clone())
            .map_err(coland_storage::PersistenceError::database)?;
        let scope = arkret_wire::ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: CircleId::new(circle_id)
                .map_err(coland_storage::PersistenceError::database)?,
        };
        let group = persistence.mls_groups().current(&scope).await?;
        if group
            .as_ref()
            .is_some_and(|group| group.realm_id != realm_id || group.value.effective_scope != scope)
        {
            return Err(coland_storage::PersistenceError::Internal(
                "Circle MLS current has a mismatched effective scope".to_owned(),
            ));
        }
        circle.mls_group_ref = group
            .map(|_| {
                scope
                    .canonical_mls_group_id()
                    .map(|id| id.to_string())
                    .map_err(coland_storage::PersistenceError::database)
            })
            .transpose()?;
    }
    if let Ok(rows) = persistence.morph_projections().snapshot_all().await {
        for record in rows {
            let Some(state) = parse_object_state(&record.state) else {
                tracing::warn!(
                    morph_id = %record.morph_id,
                    state = %record.state,
                    "skipping morph projection row with unknown state during hydrate"
                );
                continue;
            };
            let content = match record.content.map(ContentBlock::from_value).transpose() {
                Ok(content) => content,
                Err(error) => {
                    tracing::warn!(
                        morph_id = %record.morph_id,
                        error = %error,
                        "skipping morph projection row with undecodable content during hydrate"
                    );
                    continue;
                }
            };
            proj.morphs.insert(
                record.morph_id.clone(),
                MorphProjection {
                    morph_id: record.morph_id,
                    realm_id: record.realm_id,
                    scope_circle_id: record.scope_circle_id,
                    morph_kind: record.morph_kind,
                    title: record.title,
                    fields: serde_json::from_value(record.fields).unwrap_or_default(),
                    schema_refs: serde_json::from_value(record.schema_refs).unwrap_or_default(),
                    facets: serde_json::from_value(record.facets).unwrap_or_default(),
                    versions: serde_json::from_value(record.versions).unwrap_or_default(),
                    content,
                    encrypted_content: record.encrypted_content,
                    state,
                    state_changed_at: record.state_changed_at,
                    stage: record
                        .stage
                        .as_deref()
                        .and_then(object_stage_from_wire_value),
                    stage_changed_at: record.stage_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                },
            );
        }
    }
    // MLS KeyPackage projection — the claim selector reads ONLY this in-memory
    // map (`routing/mls.rs`), so without this rehydration the admin can never
    // claim a joined invitee_id's KeyPackage after a restart and admission stalls
    // ("waiting for a Welcome"). The durable `mls_key_packages` table is the
    // authoritative store; mirror it back 1:1.
    if let Ok(rows) = persistence.mls_key_packages().snapshot_all().await {
        for row in rows {
            proj.mls_key_packages.insert(
                row.id.clone(),
                crate::projection::key_package_projection_from_record(row),
            );
        }
    }

    // Replay retained histories in their actual Commit stream order to rebuild
    // Calendar revision sources, RSVP heads, Poll state and moderation indexes.
    // Since-join replicas can have a complete canonical Strand current without
    // its create history; their materialized state must not be rewound by
    // reapplying old transitions against the latest lifecycle state.
    let replayable_strands = events
        .iter()
        .filter(|record| record.kind == arkret_wire::EventKind::StrandCreate.as_str())
        .map(|record| {
            let id = arkret_wire::EventId::new(record.event_id.clone())
                .map_err(coland_storage::PersistenceError::database)?;
            Ok(arkret_wire::StrandId::from_event_id(&id).to_string())
        })
        .collect::<coland_storage::PersistenceResult<BTreeSet<_>>>()?;
    let default_strand_realms = events
        .iter()
        .filter(|event| event.kind == arkret_wire::EventKind::RealmSetDefaultStrand.as_str())
        .map(|event| {
            let realm_id = event.realm_id.as_ref().ok_or_else(|| {
                coland_storage::PersistenceError::Internal(
                    "confirmed default Strand Event has no Realm".to_owned(),
                )
            })?;
            RealmId::new(realm_id.clone()).map_err(|error| {
                coland_storage::PersistenceError::Internal(format!(
                    "confirmed default Strand Realm is invalid: {error}"
                ))
            })
        })
        .collect::<coland_storage::PersistenceResult<BTreeSet<_>>>()?;
    let replay_events = events
        .into_iter()
        .filter(|event| {
            if matches!(
                arkret_wire::EventKind::from_wire(&event.kind),
                arkret_wire::EventKind::StrandUpdate
                    | arkret_wire::EventKind::StrandArchive
                    | arkret_wire::EventKind::StrandRestore
            ) && event
                .envelope
                .pointer("/payload/target_ref")
                .and_then(Value::as_str)
                .is_some_and(|id| {
                    canonical_strands.contains_key(id) && !replayable_strands.contains(id)
                })
            {
                return false;
            }
            matches!(
                arkret_wire::EventKind::from_wire(&event.kind),
                arkret_wire::EventKind::StrandCreate
                    | arkret_wire::EventKind::StrandUpdate
                    | arkret_wire::EventKind::StrandArchive
                    | arkret_wire::EventKind::StrandRestore
                    | arkret_wire::EventKind::RsvpSet
                    | arkret_wire::EventKind::MessageCreate
                    | arkret_wire::EventKind::ModerationDecision
                    | arkret_wire::EventKind::ModerationDecisionLift
            )
        })
        .collect::<Vec<_>>();
    let (poll_events, replay_events): (Vec<_>, Vec<_>) =
        replay_events.into_iter().partition(|event| {
            event.kind == arkret_wire::EventKind::MessageCreate.as_str()
                && matches!(
                    event
                        .envelope
                        .pointer("/payload/content/kind")
                        .and_then(Value::as_str),
                    Some("ak.content.poll" | "ak.content.poll.response")
                )
        });
    for event in replay_events {
        replay_hydration_record(
            projection_adapter,
            proj,
            event,
            &hydration_hlc,
            "accepted-event-reducer",
        )?;
    }
    // Resolve the actual accepting Commit instead of assigning synthetic
    // coordinates to the Event snapshot's delivery order. Definitions and
    // response heads precede their dependents in this confirmed stream order.
    let mut ordered_polls = BTreeMap::new();
    for record in poll_events {
        let id = arkret_wire::EventId::new(record.event_id.clone())
            .map_err(coland_storage::PersistenceError::database)?;
        let accepted = persistence
            .authority_commits()
            .committed_event(&id)
            .await?
            .ok_or_else(|| {
                coland_storage::PersistenceError::Internal(
                    "poll hydration has no accepting Commit".to_owned(),
                )
            })?;
        if serde_json::to_value(&accepted.event)
            .map_err(coland_storage::PersistenceError::database)?
            != record.envelope
        {
            return Err(coland_storage::PersistenceError::Internal(
                "poll hydration canonical Event differs from its Commit binding".to_owned(),
            ));
        }
        let reference = arkret_wire::CommittedEventRef {
            event_id: id,
            commit_id: accepted.commit.commit_id,
            stream_ref: accepted.commit.stream_ref,
            stream_position: accepted.commit.stream_position,
        };
        let scope = arkret_canonical::canonical_json_bytes(&reference.stream_ref)
            .map_err(coland_storage::PersistenceError::database)?;
        ordered_polls.insert((scope, reference.stream_position), (record, reference));
    }
    for (record, reference) in ordered_polls.into_values() {
        replay_hydration_record_with_commit(
            projection_adapter,
            proj,
            record,
            &hydration_hlc,
            "accepted-poll",
            Some(reference),
        )?;
    }
    // Exact typed current remains the final object truth. Historical replay
    // contributes only the derived Calendar source that this cache needs.
    for (id, mut strand) in canonical_strands {
        strand.schedule_revision_source = proj
            .strands
            .get(&id)
            .and_then(|replayed| replayed.schedule_revision_source.clone());
        proj.strands.insert(id, strand);
    }
    // The default pointer is a singleton last-write-wins result. Replaying
    // reception order would let an older Event overwrite a later Commit, so
    // restore the exact typed current row after Strand projection hydration.
    for realm_id in default_strand_realms {
        let result = persistence
            .authority_commits()
            .realm_default_strand_current(&realm_id)
            .await?
            .ok_or_else(|| {
                coland_storage::PersistenceError::Internal(
                    "confirmed default Strand Event has no current state".to_owned(),
                )
            })?;
        let arkret_wire::CurrentState::Value { value, .. } = result;
        let object = value
            .as_object()
            .filter(|object| object.len() == 1)
            .ok_or_else(|| {
                coland_storage::PersistenceError::Internal(
                    "default Strand current value is malformed".to_owned(),
                )
            })?;
        let strand_id: arkret_wire::StrandId =
            serde_json::from_value(object.get("default_strand_id").cloned().ok_or_else(|| {
                coland_storage::PersistenceError::Internal(
                    "default Strand current value has no pointer".to_owned(),
                )
            })?)
            .map_err(|error| {
                coland_storage::PersistenceError::Internal(format!(
                    "default Strand current pointer is invalid: {error}"
                ))
            })?;
        let strand = proj.strands.get(strand_id.as_str()).ok_or_else(|| {
            coland_storage::PersistenceError::Internal(
                "default Strand current pointer is dangling".to_owned(),
            )
        })?;
        if strand.realm_id != realm_id.as_str()
            || strand.state == coland_domain::reducer::ObjectLifecycleState::Redacted
        {
            return Err(coland_storage::PersistenceError::Internal(
                "default Strand current pointer targets a redacted or foreign Strand".to_owned(),
            ));
        }
        if let Some(realm) = proj.realm_states.get_mut(realm_id.as_str()) {
            realm.default_strand_id = Some(strand_id.to_string());
        } else {
            // A since-join member replica need not retain Realm genesis. Its
            // proved pointer remains in typed current storage; do not invent
            // an owner/Realm cache merely to mirror that independent result.
            let anchored = persistence
                .authority_commits()
                .replica_stream_anchor(&realm_id)
                .await?
                .is_some_and(|anchor| {
                    anchor.realm_id == realm_id
                        && anchor.join_commit.stream_ref
                            == (CommitStreamRef::Realm {
                                realm_id: realm_id.clone(),
                            })
                        && anchor.anchored_head.is_some_and(|head| {
                            head.stream_ref == anchor.join_commit.stream_ref
                                && head.stream_position >= anchor.join_commit.stream_position
                        })
                });
            if !anchored {
                return Err(coland_storage::PersistenceError::Internal(format!(
                    "default Strand Realm projection is missing without an anchored replica: {realm_id}"
                )));
            }
        }
    }
    // Relation admission serializes one authoritative current row per typed
    // primary domain in the RealmCommit transaction. Hydrate that same row,
    // rather than trusting a process-local reducer cache or replaying Events
    // in receipt-time order, before Sidecar bindings resolve Relation refs.
    let relation_current = persistence.relation_current_states().snapshot_all().await?;
    install_relation_current_states(proj, relation_current)?;

    // Run after object mirrors because a native Sidecar attachment validates
    // that its referenced source Relation or Strand already exists.
    hydrate_sidecar_context_projections(persistence, proj, &hydration_hlc, projection_adapter)
        .await?;
    let mut lifecycle = BTreeMap::new();
    for record in hydration_replay_records(persistence).await? {
        if !matches!(
            arkret_wire::EventKind::from_wire(&record.kind),
            arkret_wire::EventKind::RealmArchive
                | arkret_wire::EventKind::RealmRestore
                | arkret_wire::EventKind::RealmFreeze
                | arkret_wire::EventKind::RealmUnfreeze
                | arkret_wire::EventKind::RealmTombstone
        ) {
            continue;
        }
        let id = arkret_wire::EventId::new(record.event_id.clone())
            .map_err(coland_storage::PersistenceError::database)?;
        let accepted = persistence
            .authority_commits()
            .committed_event(&id)
            .await?
            .ok_or_else(|| {
                coland_storage::PersistenceError::Internal(
                    "lifecycle hydration has no accepting Commit".to_owned(),
                )
            })?;
        if serde_json::to_value(&accepted.event)
            .map_err(coland_storage::PersistenceError::database)?
            != record.envelope
            || accepted.commit.event_ref != id
            || accepted.commit.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: accepted.event.realm_id.clone(),
                })
        {
            return Err(coland_storage::PersistenceError::Internal(
                "lifecycle hydration differs from its accepted Realm stream binding".to_owned(),
            ));
        }
        let reference = arkret_wire::CommittedEventRef {
            event_id: id,
            commit_id: accepted.commit.commit_id,
            stream_ref: accepted.commit.stream_ref,
            stream_position: accepted.commit.stream_position,
        };
        let stream = arkret_canonical::canonical_json_bytes(&reference.stream_ref)
            .map_err(coland_storage::PersistenceError::database)?;
        if lifecycle
            .insert((stream, reference.stream_position), (record, reference))
            .is_some()
        {
            return Err(coland_storage::PersistenceError::Internal(
                "lifecycle hydration has conflicting stream coordinates".to_owned(),
            ));
        }
    }
    for (record, reference) in lifecycle.into_values() {
        replay_hydration_record_with_commit(
            projection_adapter,
            proj,
            record,
            &hydration_hlc,
            "accepted-realm-lifecycle",
            Some(reference),
        )?;
    }
    Ok(())
}

pub async fn hydrate_realms_from_canonical_events(
    persistence: &dyn coland_storage::PersistenceStore,
    realms: &mut RealmDirectoryIndex,
) -> coland_storage::PersistenceResult<()> {
    let events = hydration_replay_records(persistence).await?;
    hydrate_realm_directory_records(persistence, realms, &events).await;
    Ok(())
}

/// Rebuild one Realm without replaying unrelated Station history.
pub async fn hydrate_realm_from_canonical_events(
    persistence: &dyn coland_storage::PersistenceStore,
    realms: &mut RealmDirectoryIndex,
    realm_id: &RealmId,
) -> coland_storage::PersistenceResult<()> {
    let records = persistence
        .events()
        .realm_events_newest_first(realm_id.as_str())
        .await?;
    if records.iter().any(|record| {
        record.realm_id.as_deref() != Some(realm_id.as_str())
            || serde_json::from_value::<Event>(record.envelope.clone())
                .ok()
                .is_none_or(|event| event.realm_id != *realm_id)
    }) {
        return Err(coland_storage::PersistenceError::Internal(
            "Realm-local hydration contains a foreign canonical Event".to_owned(),
        ));
    }
    let events = ordered_hydration_replay_records(persistence, records).await?;
    hydrate_realm_directory_records(persistence, realms, &events).await;
    Ok(())
}

async fn hydrate_realm_directory_records(
    persistence: &dyn coland_storage::PersistenceStore,
    realms: &mut RealmDirectoryIndex,
    events: &[CanonicalEventRecord],
) {
    // Directory entries are the replay roots for every subsequent Realm
    // facet. Hydrate all confirmed genesis Events first so bootstrap Events
    // that share one transaction timestamp never depend on storage iteration
    // order.
    for record in events
        .iter()
        .filter(|record| record.kind == arkret_wire::EventKind::RealmCreate.as_str())
    {
        hydrate_realm_create_event(persistence, realms, record).await;
    }

    for record in events {
        if record.kind == arkret_wire::EventKind::RealmProfile.as_str() {
            hydrate_realm_profile_event(realms, record);
        } else if matches!(
            arkret_wire::EventKind::from_wire(&record.kind),
            arkret_wire::EventKind::MemberState | arkret_wire::EventKind::InviteAccept
        ) {
            // Membership transitions MUST be replayed too, or joined members
            // vanish from `realm_entry.members` on restart. In an ordinary
            // Collaboration Realm the creator is established by the final
            // explicit bootstrap `ak.member.state`, not by `ak.realm.create`.
            // Losing that transition silently breaks admin-side MLS admission: the
            // admin's synced roster shows only itself, `other_joined` stays
            // false, and a newly-joined invitee_id is never claimed/Welcomed —
            // stuck "waiting for a Welcome" forever. Mirrors the live
            // projection in `routing/events/projection/realm.rs`.
            hydrate_realm_member_state_event(realms, record);
        } else if matches!(
            arkret_wire::EventKind::from_wire(&record.kind),
            arkret_wire::EventKind::RealmHistoryAccess
                | arkret_wire::EventKind::RealmPreviewPolicy
                | arkret_wire::EventKind::RealmAssetPrivacyPolicy
                | arkret_wire::EventKind::RealmPlaintextVisibleServices
        ) {
            hydrate_realm_policy_event(persistence, record).await;
        }
    }
}

pub fn reconcile_hydrated_agent_memberships(
    realms: &mut RealmDirectoryIndex,
    projection: &ProjectionState,
) {
    for ((realm_id, agent_id), binding) in &projection.agent_membership_bindings {
        let (Ok(realm_id), Ok(agent_id)) = (
            RealmId::new(realm_id.clone()),
            DidCoreId::new(agent_id.clone()),
        ) else {
            continue;
        };
        let Some(entry) = realms.get_mut(&realm_id) else {
            continue;
        };
        if !entry
            .members
            .contains(&binding.controller_account_id.principal_id)
        {
            entry.members.remove(&agent_id);
        }
    }
}

/// Replay the canonical Realm profile singleton into the restart directory.
///
/// The directory is an index, so its display fields must be reconstructed from
/// the accepted typed Event rather than from a weaker projection-event mirror.
pub fn hydrate_realm_profile_event(
    realms: &mut RealmDirectoryIndex,
    record: &CanonicalEventRecord,
) {
    let Ok(event) = serde_json::from_value::<Event>(record.envelope.clone()) else {
        return;
    };
    if event.kind != arkret_wire::EventKind::RealmProfile {
        return;
    }
    let Ok(profile) = event.typed_payload::<arkret_wire::event_spec::RealmProfile>() else {
        return;
    };
    let Some(entry) = realms.get_mut(&event.realm_id) else {
        return;
    };
    entry.title = profile.title;
    entry.description = profile.summary;
}

/// Replay one persisted `ak.member.state` or `ak.invite.accept` event into
/// the rebuilt Realm directory. Invite acceptance and `join` add the member;
/// `leave`/`ban` removes them. Other transitions (`invite`/`knock`) do not
/// affect the directory member set (they live in the structured membership
/// projection, consistent with the live `apply_membership` path). Events are
/// replayed in confirmed command order, so the `ak.realm.create` that
/// seeds the directory entry is always applied before any membership delta.
pub fn hydrate_realm_member_state_event(
    realms: &mut RealmDirectoryIndex,
    record: &CanonicalEventRecord,
) {
    if record.kind == arkret_wire::EventKind::InviteAccept.as_str() {
        let Ok(event) = serde_json::from_value::<Event>(record.envelope.clone()) else {
            return;
        };
        let Ok(accepted) = event.typed_payload::<arkret_wire::event_spec::InviteAccept>() else {
            return;
        };
        let Some(account) = event.actor_id.as_account_id() else {
            return;
        };
        if accepted
            .invitee_account_id
            .as_ref()
            .is_some_and(|invitee| invitee != account)
        {
            return;
        }
        if let Some(entry) = realms.get_mut(&event.realm_id) {
            entry.members.insert(account.principal_id.clone());
        }
        return;
    }
    let payload = record.envelope.get("payload");
    let membership = payload
        .and_then(|payload| payload.get("membership"))
        .and_then(Value::as_str);
    if !matches!(membership, Some("join" | "leave" | "ban")) {
        return;
    }
    let Some(member) = payload
        .and_then(|payload| payload.get("member_id"))
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok())
    else {
        return;
    };
    let Some(realm_id) = record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .or(record.realm_id.as_deref())
        .map(normalize_persisted_realm_id)
    else {
        return;
    };
    let Ok(realm_id) = RealmId::new(realm_id) else {
        return;
    };
    // Directory entries are a principal-only discovery index, never the
    // authority used for membership or delivery admission.
    let member = member.signing_principal_id().clone();
    let Some(entry) = realms.get_mut(&realm_id) else {
        // No directory entry yet (create event not seen / pruned) — nothing to
        // attach the membership to.
        return;
    };
    match membership {
        Some("join") => {
            entry.members.insert(member);
        }
        Some("leave" | "ban") => {
            entry.members.remove(&member);
        }
        _ => {}
    }
}

pub async fn hydrate_realm_create_event(
    persistence: &dyn coland_storage::PersistenceStore,
    realms: &mut RealmDirectoryIndex,
    record: &CanonicalEventRecord,
) {
    let payload_object = record
        .envelope
        .get("payload")
        .and_then(|payload| payload.get("object"));
    let Some(realm_id) = record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| {
            payload_object
                .and_then(|object| object.get("id"))
                .and_then(Value::as_str)
        })
        .or(record.realm_id.as_deref())
        .map(normalize_persisted_realm_id)
    else {
        return;
    };
    let Ok(realm_id) = RealmId::new(realm_id.clone()) else {
        tracing::warn!(realm_id = %realm_id, "skipping persisted realm.create with invalid realm_id");
        return;
    };
    let Ok(actor) = serde_json::from_str::<arkret_wire::ActorId>(&record.actor_id) else {
        tracing::warn!(actor = %record.actor_id, "skipping persisted realm.create with invalid actor");
        return;
    };
    let title = payload_object
        .and_then(|object| object.get("title"))
        .and_then(Value::as_str)
        .unwrap_or(realm_id.as_str());
    let summary = payload_object
        .and_then(|object| object.get("summary"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let discoverability = payload_object
        .and_then(|object| object.get("default_discoverability"))
        .and_then(Value::as_str)
        .unwrap_or("invite_only")
        .to_owned();
    let history_access = payload_object
        .and_then(|object| object.get("history_access"))
        .and_then(Value::as_str)
        .unwrap_or("since_join")
        .to_owned();
    let encryption_profile = payload_object
        .and_then(|object| object.get("encryption_profile"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let realm_class = payload_object
        .and_then(|object| object.get("realm_class"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let default_join_rule = payload_object
        .and_then(|object| object.get("default_join_rule"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let preview_policy = payload_object
        .and_then(|object| object.get("preview_policy"))
        .cloned();
    let preview_policy_digest = preview_policy.as_ref().and_then(canonical_value_digest);
    let asset_privacy_policy = payload_object
        .and_then(|object| object.get("asset_privacy_policy"))
        .cloned();
    let asset_privacy_policy_digest = asset_privacy_policy
        .as_ref()
        .and_then(canonical_value_digest);
    let plaintext_visible_services = record
        .envelope
        .get("payload")
        .and_then(|payload| payload.get("plaintext_visible_services"))
        .or_else(|| payload_object.and_then(|object| object.get("plaintext_visible_services")))
        .and_then(Value::as_array)
        .map(|services| {
            services
                .iter()
                .filter_map(|service| service.as_str().map(ToOwned::to_owned))
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut plaintext_visible_service_classes = record
        .envelope
        .get("payload")
        .map(plaintext_service_classes_from_value)
        .unwrap_or_default();
    if let Some(object) = payload_object {
        for (service, classes) in plaintext_service_classes_from_value(object) {
            plaintext_visible_service_classes
                .entry(service)
                .or_default()
                .extend(classes);
        }
    }
    let minimal_metadata_realm =
        payload_object.is_some_and(coland_domain::kinds::payload_declares_minimal_metadata_realm);

    let mut entry = RealmDirectoryEntry::new(
        realm_id.clone(),
        title,
        DirectoryProvenance::AcceptedEvent(record.event_id.clone()),
    );
    entry.description = summary.clone();
    entry.realm_class = realm_class;
    entry.default_join_rule = default_join_rule;
    entry.public = discoverability == "public";
    let create_seeds_membership = payload_object
        .and_then(|object| object.get("purpose"))
        .and_then(Value::as_str)
        == Some("direct_conversation");
    if create_seeds_membership {
        entry.members.insert(actor.signing_principal_id().clone());
    }
    entry.evaluated_at = record.received_at;
    entry.policy_revision = preview_policy_digest
        .clone()
        .unwrap_or_else(|| record.canonical_digest.clone());
    realms.upsert(entry);

    let meta = RealmMetaRecord {
        owner: record.actor_id.clone(),
        deleted: false,
        discoverability,
        history_access,
        preview_policy,
        preview_policy_digest,
        asset_privacy_policy,
        asset_privacy_policy_digest,
        encryption_profile,
        plaintext_visible_services,
        plaintext_visible_service_classes,
        minimal_metadata_realm,
        created_at: record.received_at,
        updated_at: record.received_at,
    };
    if let Err(error) = persistence.realm_meta().put(realm_id.as_str(), &meta).await {
        tracing::warn!(%error, realm_id = %realm_id, "failed to hydrate persisted realm meta");
    }
}

pub async fn hydrate_realm_policy_event(
    persistence: &dyn coland_storage::PersistenceStore,
    record: &CanonicalEventRecord,
) {
    let Some(realm_id) = event_record_realm_id(record) else {
        return;
    };
    let Ok(Some(mut meta)) = persistence.realm_meta().get(&realm_id).await else {
        return;
    };
    let Ok(event) = serde_json::from_value::<arkret_wire::Event>(record.envelope.clone()) else {
        return;
    };
    match &event.kind {
        arkret_wire::EventKind::RealmHistoryAccess => {
            let Some(value) = event.payload.get("to").and_then(Value::as_str) else {
                return;
            };
            meta.history_access = value.to_owned();
        }
        arkret_wire::EventKind::RealmPreviewPolicy => {
            let Ok(payload) = event.typed_payload::<arkret_wire::event_spec::RealmPreviewPolicy>()
            else {
                return;
            };
            let Ok(value) = serde_json::to_value(payload.value) else {
                return;
            };
            meta.preview_policy_digest = canonical_value_digest(&value);
            meta.preview_policy = Some(value);
        }
        arkret_wire::EventKind::RealmAssetPrivacyPolicy => {
            let Ok(payload) =
                event.typed_payload::<arkret_wire::event_spec::RealmAssetPrivacyPolicy>()
            else {
                return;
            };
            let Ok(value) = serde_json::to_value(payload.value) else {
                return;
            };
            meta.asset_privacy_policy = Some(value.clone());
            meta.asset_privacy_policy_digest = canonical_value_digest(&value);
        }
        arkret_wire::EventKind::RealmPlaintextVisibleServices => {
            let Ok(payload) =
                event.typed_payload::<arkret_wire::event_spec::RealmPlaintextVisibleServices>()
            else {
                return;
            };
            let Ok(payload) = serde_json::to_value(payload) else {
                return;
            };
            for (service, classes) in plaintext_service_classes_from_value(&payload) {
                meta.plaintext_visible_services.insert(service.clone());
                meta.plaintext_visible_service_classes
                    .entry(service)
                    .or_default()
                    .extend(classes);
            }
        }
        _ => {}
    }
    meta.updated_at = record.received_at;
    if let Err(error) = persistence.realm_meta().put(&realm_id, &meta).await {
        tracing::warn!(%error, realm_id = %realm_id, "failed to hydrate Realm policy event");
    }
}

pub fn event_record_realm_id(record: &CanonicalEventRecord) -> Option<String> {
    record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .or(record.realm_id.as_deref())
        .map(normalize_persisted_realm_id)
}

pub fn normalize_persisted_realm_id(id: &str) -> String {
    id.to_owned()
}

#[cfg(test)]
mod agent_membership_reconcile_tests {
    use arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding;
    use arkret_wire::AccountId;

    use super::*;
    use crate::events::DirectoryProvenance;

    #[test]
    fn removed_controller_cascades_to_bound_agent_during_hydration() {
        let realm_id =
            RealmId::new("ak:realm:AQXbKRls_Ty4E6MhnCM67pDwRngRQcn7i9AW0UjrkPMI").unwrap();
        let controller = DidCoreId::new("ak:did_core:web:controller.example").unwrap();
        let agent = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        let mut entry =
            RealmDirectoryEntry::new(realm_id.clone(), "realm", DirectoryProvenance::LocalOnly);
        entry.members.insert(agent.clone());
        let mut realms = RealmDirectoryIndex::new();
        realms.upsert(entry);

        let mut projection = ProjectionState::default();
        projection.agent_membership_bindings.insert(
            (realm_id.to_string(), agent.to_string()),
            AgentControllerMembershipBinding {
                controller_account_id: AccountId::new(
                    controller,
                    DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
                ),
                controller_membership_generation_ref: arkret_identifiers::EventId::new(
                    "ak:event:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim",
                )
                .unwrap(),
                controller_terminal_event_ref: None,
            },
        );

        reconcile_hydrated_agent_memberships(&mut realms, &projection);

        assert!(!realms.get(&realm_id).unwrap().members.contains(&agent));
    }
}

#[cfg(test)]
mod relation_current_state_hydration_tests {
    use arkret_models_collaboration::objects::relation::{Relation, RelationPrimaryConflictDomain};
    use coland_domain::reducer::ColandRelationState;
    use coland_storage::RelationCurrentStateRecord;

    use super::*;

    fn current_relation_record() -> RelationCurrentStateRecord {
        let realm_id =
            RealmId::new("ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru").unwrap();
        let primary_conflict_domain =
            serde_json::from_value::<RelationPrimaryConflictDomain>(serde_json::json!({
                "domain_kind":"tuple",
                "relation_kind":"references",
                "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
                "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-"
            }))
            .unwrap();
        let domain_key = arkret_canonical::canonical_json_string(&primary_conflict_domain).unwrap();
        let relation = serde_json::from_value::<Relation>(serde_json::json!({
            "schema":"ak.schema.relation.v1",
            "id":"ak:relation:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz",
            "realm_id":realm_id,
            "effective_scope":{"kind":"realm","realm_id":realm_id},
            "relation_kind":"references",
            "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
            "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-",
            "rank":"A1",
            "fields":{"note":"durable current"},
            "state":"active",
            "created_by":{
                "kind":"account",
                "account_id":{
                    "principal_id":"ak:did_core:web:relation-author.example",
                    "station_id":"ak:did_core:web:relation-station.example"
                }
            },
            "created_at":"2026-09-21T00:00:00.000Z",
            "updated_at":"2026-09-21T00:00:01.000Z"
        }))
        .unwrap();
        RelationCurrentStateRecord {
            realm_id,
            domain_key,
            primary_conflict_domain,
            relation,
            revision: arkret_wire::CurrentRevision {
                commit_id: arkret_wire::RealmCommitId::from_digest([0x44; 32]),
                stream_position: 7,
            },
        }
    }

    #[test]
    fn restart_installs_the_authoritative_relation_current_value() {
        let record = current_relation_record();
        let relation_id = record.relation.id.as_ref().unwrap().to_string();
        let current_key = (record.realm_id.to_string(), record.domain_key.clone());

        let mut first_boot = ProjectionState::default();
        install_relation_current_states(&mut first_boot, vec![record.clone()]).unwrap();

        let materialized = first_boot.relations.get(&relation_id).unwrap();
        assert_eq!(materialized.state, "active");
        assert_eq!(materialized.rank.as_deref(), Some("A1"));
        assert_eq!(
            materialized.fields.get("note").and_then(Value::as_str),
            Some("durable current")
        );
        assert_eq!(
            first_boot.relation_current.get(&current_key),
            Some(&relation_id)
        );
        let metadata = first_boot
            .relation_current_metadata
            .get(&current_key)
            .unwrap();
        assert_eq!(metadata.relation_id, relation_id);
        assert_eq!(metadata.revision.stream_position, 7);
        assert_eq!(
            metadata.revision.commit_id,
            arkret_wire::RealmCommitId::from_digest([0x44; 32])
        );

        // A process restart starts from an empty cache. Installing the same
        // authoritative storage snapshot reproduces the exact query/admission
        // identity without relying on the previous process state.
        let mut restarted = ProjectionState::default();
        install_relation_current_states(&mut restarted, vec![record]).unwrap();
        assert_eq!(restarted.relation_current, first_boot.relation_current);
        assert_eq!(
            restarted.relation_current_metadata,
            first_boot.relation_current_metadata
        );
        assert_eq!(
            restarted.relations.get(&relation_id).unwrap().fields,
            materialized.fields
        );
    }

    #[test]
    fn hydration_rejects_duplicate_authoritative_domains() {
        let record = current_relation_record();
        let mut projection = ProjectionState::default();
        let error = install_relation_current_states(&mut projection, vec![record.clone(), record])
            .unwrap_err();
        assert!(matches!(
            error,
            coland_storage::PersistenceError::Internal(_)
        ));
        assert!(projection.relations.is_empty());
        assert!(projection.relation_current.is_empty());
        assert!(projection.relation_current_metadata.is_empty());
    }

    #[test]
    fn hydration_preserves_derived_relation_edges() {
        let mut projection = ProjectionState::default();
        let derived_id = "ak:relation:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-".to_owned();
        projection.relations.insert(
            derived_id.clone(),
            ColandRelationState {
                relation_id: derived_id.clone(),
                realm_id: "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru".to_owned(),
                relation_kind: "contains".to_owned(),
                scope_circle_id: None,
                from_ref: Some("ak:space:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4".into()),
                to_ref: Some("ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4".into()),
                rank: None,
                fields: std::collections::BTreeMap::new(),
                state: "active".to_owned(),
                source_event_id: None,
                source_event_digest: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
        );

        install_relation_current_states(&mut projection, vec![current_relation_record()]).unwrap();

        assert!(projection.relations.contains_key(&derived_id));
        assert_eq!(projection.relation_current.len(), 1);
    }
}
