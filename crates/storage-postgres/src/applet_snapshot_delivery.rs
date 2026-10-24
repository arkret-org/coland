//! Exact-scope native snapshots retain the shared Account disclosure proof.

use arkret_wire::{
    CommitStreamRef, CurrentSelector, CurrentState, RealmCommit, RealmStateSnapshot,
};
use diesel::sql_types::Array;

use super::*;

#[derive(QueryableByName)]
struct SnapshotSourceRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    event_json: serde_json::Value,
}

fn stream(endpoint: &AppletManagedDeviceScopeGuard) -> PersistenceResult<CommitStreamRef> {
    if !matches!(
        endpoint.effective_scope,
        ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
    ) {
        return Err(refused("native snapshot has no supported business scope"));
    }
    CommitStreamRef::from_scope(&endpoint.effective_scope, None).map_err(PersistenceError::database)
}

pub(super) async fn restrict_material(
    conn: &mut diesel_async::AsyncPgConnection,
    station: &DidCoreId,
    endpoint: &AppletManagedDeviceScopeGuard,
    expiry: chrono::DateTime<chrono::Utc>,
    mut material: coland_storage::RealmStateSnapshotMaterial,
) -> PersistenceResult<(coland_storage::RealmStateSnapshotMaterial, Vec<ReadProof>)> {
    let expected = stream(endpoint)?;
    if &material.realm_id != expected.realm_id() {
        return Err(refused("native snapshot material belongs to another Realm"));
    }
    material
        .visible_stream_heads
        .retain(|head| head.stream_ref == expected);
    // Circle metadata is carried by a Realm authorization shell but belongs
    // to the Circle. It cannot ride a Realm Device cut; its Realm source is
    // also outside a Circle-only independent stream cut.
    material.current_state_entries.retain(|row| match row {
        CurrentState::Value {
            selector,
            source_stream_ref,
            ..
        } => source_stream_ref == &expected && !matches!(selector, CurrentSelector::Circle { .. }),
    });
    material
        .retention_and_history_floor
        .stream_floors
        .retain(|floor| floor.stream_ref == expected);
    let proofs = prepare_material(conn, station, endpoint, expiry, &material).await?;
    Ok((material, proofs))
}

pub(super) async fn prepare(
    conn: &mut diesel_async::AsyncPgConnection,
    station: &DidCoreId,
    endpoint: &AppletManagedDeviceScopeGuard,
    expiry: chrono::DateTime<chrono::Utc>,
    snapshot: &RealmStateSnapshot,
) -> PersistenceResult<Vec<ReadProof>> {
    // Recheck the archived original instead of rebuilding or resigning it.
    crate::issued_realm_snapshots::recheck_actor_disclosure_in_connection(
        conn,
        &endpoint.authority.actor_id,
        station,
        snapshot,
    )
    .await?;
    let material = coland_storage::RealmStateSnapshotMaterial {
        purpose: arkret_wire::RealmSnapshotPurpose::FullRecovery,
        history_basis: None,
        realm_id: snapshot.realm_id.clone(),
        governance_generation: snapshot.governance_generation,
        visible_stream_heads: snapshot.visible_stream_heads.clone(),
        current_state_entries: snapshot.current_state_entries.clone(),
        retention_and_history_floor: snapshot.retention_and_history_floor.clone(),
    };
    prepare_material(conn, station, endpoint, expiry, &material).await
}

// Only typed subject coordinates are resource identities. Free occurrence,
// action names and arbitrary current values must not influence Policy matches.
fn current_resources(
    realm: &arkret_wire::RealmId,
    selector: &CurrentSelector,
) -> Vec<PolicyResourceSelector> {
    use arkret_wire::{CurrentSelector as S, PinScope, PolicyActionSelector};
    let refs: Vec<String> = match selector {
        S::Strand { strand_id }
        | S::CalendarScheduleSource { strand_id }
        | S::StrandWatch { strand_id, .. }
        | S::Rsvp {
            event_ref: strand_id,
            ..
        } => vec![strand_id.to_string()],
        S::StrandPosition {
            board_space_id,
            strand_id,
        } => vec![board_space_id.to_string(), strand_id.to_string()],
        S::Space { space_id }
        | S::SpaceParent { space_id }
        | S::SpaceChildScopePolicy { space_id } => vec![space_id.to_string()],
        S::Circle { circle_id } | S::CircleMemberState { circle_id, .. } => {
            vec![circle_id.to_string()]
        }
        S::MessageRevision { message_id } => vec![message_id.to_string()],
        S::MessageReactions { target_ref }
        | S::ModerationState { target_ref }
        | S::ObjectRedaction { target_ref } => vec![target_ref.to_string()],
        S::ActorProfile { actor_profile_id } => vec![actor_profile_id.to_string()],
        S::CallState { call_id }
        | S::CallFocus { call_id }
        | S::CallRoster { call_id }
        | S::CallModeration { call_id } => vec![call_id.to_string()],
        S::CapabilityGrant { grant_id } => vec![grant_id.to_string()],
        S::InviteLifecycle { invite_id } | S::InviteDirectedInvitee { invite_id } => {
            vec![invite_id.to_string()]
        }
        S::ModerationReport { event_id } | S::ModerationFrankingProof { event_id } => {
            vec![event_id.to_string()]
        }
        S::Policy { policy_id }
        | S::PolicyAction {
            subject: PolicyActionSelector::PolicyRef { policy_id, .. },
        } => vec![policy_id.to_string()],
        S::Relation {
            primary_conflict_domain,
        } => std::iter::once(&primary_conflict_domain.from_ref)
            .chain(primary_conflict_domain.to_ref.iter())
            .filter_map(|endpoint| endpoint.as_object_ref().map(str::to_owned))
            .collect(),
        S::Pin { pin_scope } => vec![match pin_scope {
            PinScope::Realm { id } => id.to_string(),
            PinScope::Circle { id } => id.to_string(),
            PinScope::Strand { id } => id.to_string(),
            PinScope::Space { id } => id.to_string(),
        }],
        // These families have no additional canonical object subject. Their
        // actual accepted source and exact scope still supply read facts.
        _ => vec![],
    };
    let mut resources = Vec::new();
    for reference in refs.into_iter().collect::<std::collections::BTreeSet<_>>() {
        let kind = if reference.parse::<arkret_wire::StrandId>().is_ok() {
            Some(PolicyResourceKind::Strand)
        } else if reference.parse::<arkret_wire::SpaceId>().is_ok() {
            Some(PolicyResourceKind::Space)
        } else {
            None
        };
        if let Some(kind) = kind {
            resources.push(PolicyResourceSelector {
                kind,
                realm_id: Some(realm.clone()),
                resource_ref: Some(reference.clone()),
            });
        }
        resources.push(PolicyResourceSelector {
            kind: PolicyResourceKind::Object,
            realm_id: Some(realm.clone()),
            resource_ref: Some(reference),
        });
    }
    resources
}

async fn prepare_material(
    conn: &mut diesel_async::AsyncPgConnection,
    _station: &DidCoreId,
    endpoint: &AppletManagedDeviceScopeGuard,
    expiry: chrono::DateTime<chrono::Utc>,
    material: &coland_storage::RealmStateSnapshotMaterial,
) -> PersistenceResult<Vec<ReadProof>> {
    let expected = stream(endpoint)?;
    if &material.realm_id != expected.realm_id()
        || material.visible_stream_heads.len() != 1
        || material.visible_stream_heads[0].stream_ref != expected
        || material.retention_and_history_floor.stream_floors.len() != 1
        || material.retention_and_history_floor.stream_floors[0].stream_ref != expected
        || material.current_state_entries.iter().any(|row| match row {
            CurrentState::Value {
                source_stream_ref, ..
            } => source_stream_ref != &expected,
        })
    {
        return Err(refused(
            "native snapshot contains another or unproved stream",
        ));
    }
    let scope_proof =
        crate::boxed_future(|| mls_scope_read_proof(conn, endpoint, expiry, None)).await?;
    tracing::debug!(
        permitted = scope_proof.permits_at(chrono::Utc::now()),
        "native snapshot scope proof prepared"
    );
    let context = scope_proof.context.clone();
    let mut proofs = vec![scope_proof];
    // Covering originals supply internal resource facts, including for state
    // below the caller's history floor. They are never disclosed by this read.
    if !material.current_state_entries.is_empty() {
        let ids: Vec<_> = material
            .current_state_entries
            .iter()
            .map(|row| match row {
                CurrentState::Value { revision, .. } => revision.commit_id.to_string(),
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let rows = sql_query(
            "SELECT c.commit_json, e.envelope AS event_json FROM realm_commits c \
             JOIN canonical_events e ON e.pk=c.event_pk \
             WHERE c.realm_id=$1 AND c.commit_id=ANY($2) AND e.state='committed'",
        )
        .bind::<Text, _>(material.realm_id.as_str())
        .bind::<Array<Text>, _>(&ids)
        .get_results::<SnapshotSourceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut sources = BTreeMap::new();
        for row in rows {
            let commit: RealmCommit =
                serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
            let event: arkret_wire::Event =
                serde_json::from_value(row.event_json).map_err(PersistenceError::database)?;
            let full = arkret_wire::CommittedEventFullView { commit, event };
            full.validate_shape().map_err(PersistenceError::database)?;
            let source = arkret_wire::CommittedEventView::Full(full);
            if sources
                .insert(source.commit().commit_id.clone(), source)
                .is_some()
            {
                return Err(refused("native snapshot covering source is duplicated"));
            }
        }
        for row in &material.current_state_entries {
            let CurrentState::Value {
                revision,
                value,
                source_stream_ref,
                selector,
            } = row;
            let view = sources
                .get(&revision.commit_id)
                .ok_or_else(|| refused("native snapshot covering source is unavailable"))?;
            let scope = view
                .disclosure_scope()
                .map_err(PersistenceError::database)?;
            let arkret_wire::CommittedEventView::Full(source) = view else {
                return Err(refused(
                    "native snapshot covering source has no original Event",
                ));
            };
            if source.commit.stream_ref != *source_stream_ref
                || source.commit.stream_position != revision.stream_position
                || scope != endpoint.effective_scope
            {
                return Err(refused(
                    "native snapshot source differs from its exact accepted coordinates",
                ));
            }
            let content = matches!(selector, CurrentSelector::MessageRevision { .. });
            if content
                && (!matches!(
                    source.event.kind,
                    EventKind::MessageCreate | EventKind::MessageRevise
                ) || serde_json::to_value(&source.event.payload)
                    .map_err(PersistenceError::database)?
                    != *value)
            {
                return Err(refused(
                    "native snapshot content differs from its exact accepted source",
                ));
            }
            let actions = if content {
                &[
                    CapabilityActionId::EventRead,
                    CapabilityActionId::ObjectReadContent,
                ][..]
            } else {
                &[CapabilityActionId::EventRead][..]
            };
            let resources = current_resources(&material.realm_id, selector);
            let proof = source_read_proof(context.clone(), &source.event, actions, &resources)?;
            tracing::debug!(
                ?selector,
                permitted = proof.permits_at(chrono::Utc::now()),
                "native snapshot subject proof prepared"
            );
            proofs.push(proof);
        }
    }
    if proofs
        .iter()
        .any(|proof| !proof.permits_at(chrono::Utc::now()))
    {
        return Err(refused(
            "native snapshot current permission is unavailable or expired",
        ));
    }
    Ok(proofs)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(byte: u8) -> arkret_wire::EventId {
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
    }
    #[test]
    fn free_occurrence_metadata_never_becomes_a_resource_match() {
        let realm = arkret_wire::RealmId::from_event_id(&event(201));
        let strand = arkret_wire::StrandId::from_event_id(&event(202));
        let actor = ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:reader.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let mut selector = CurrentSelector::Rsvp {
            event_ref: strand,
            occurrence: None,
            responder_actor_id: actor,
        };
        let resources = current_resources(&realm, &selector);
        let CurrentSelector::Rsvp { occurrence, .. } = &mut selector else {
            unreachable!()
        };
        *occurrence = Some(arkret_wire::StrandId::from_event_id(&event(203)).to_string());
        assert_eq!(current_resources(&realm, &selector), resources);
    }
    #[test]
    fn updated_profile_and_call_rows_keep_their_object_subjects() {
        let realm = arkret_wire::RealmId::from_event_id(&event(204));
        let profile = arkret_wire::ActorProfileId::from_event_id(&event(205));
        let call = arkret_wire::CallId::from_event_id(&event(206));
        for (selector, reference) in [
            (
                CurrentSelector::ActorProfile {
                    actor_profile_id: profile.clone(),
                },
                profile.to_string(),
            ),
            (
                CurrentSelector::CallRoster {
                    call_id: call.clone(),
                },
                call.to_string(),
            ),
        ] {
            assert!(
                current_resources(&realm, &selector).contains(&PolicyResourceSelector {
                    kind: PolicyResourceKind::Object,
                    realm_id: Some(realm.clone()),
                    resource_ref: Some(reference),
                })
            );
        }
    }
}
