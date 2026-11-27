//! Home Station enrollment generations confirmed by one accepted Sidecar MLS state.
//!
//! These private originals do not reproduce H's native participant decision or
//! its digest preimage. Each real transition confirms only its resulting tree.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CommittedEventFullView, EventId, EventKind, ReadableFloor,
    ReadableFloorReason, RealmId, ScopeRef, SidecarId,
};
use coland_storage::{
    AuthorityCommitTransaction, ConflictCode, MlsGroupCurrentRecord, MlsStateInstallation,
    PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Jsonb, Nullable, Text};
use diesel_async::AsyncPgConnection;
use horme::RunQueryDsl;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{OptionalExtension, QueryableByName, sql_query};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MembershipBasis {
    controller_create_event_ref: EventId,
    agent_join_event_refs: Vec<EventId>,
}

impl MembershipBasis {
    fn validate_references(&self) -> PersistenceResult<()> {
        if self
            .agent_join_event_refs
            .iter()
            .any(|reference| reference == &self.controller_create_event_ref)
            || self
                .agent_join_event_refs
                .windows(2)
                .any(|pair| pair[0].as_str().as_bytes() >= pair[1].as_str().as_bytes())
        {
            return Err(invalid(
                "Agent join references are duplicated, not canonically ordered or name the controller create",
            ));
        }
        Ok(())
    }
}

#[derive(QueryableByName)]
struct OriginalRow {
    #[diesel(sql_type = Jsonb)]
    event: Value,
    #[diesel(sql_type = Jsonb)]
    commit: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    basis: Option<Value>,
}

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("Sidecar membership provenance: {detail}"))
}

fn unavailable(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "{}: {detail}",
        ConflictCode::TemporarilyUnavailable
    ))
}

fn full(realm: &RealmId, row: &OriginalRow) -> PersistenceResult<CommittedEventFullView> {
    let full = CommittedEventFullView {
        event: serde_json::from_value(row.event.clone()).map_err(invalid)?,
        commit: serde_json::from_value(row.commit.clone()).map_err(invalid)?,
    };
    full.validate_shape().map_err(invalid)?;
    full.event
        .verify_event_id_matches_content_with_digest_suite(realm.digest_suite_code().digest_suite())
        .map_err(invalid)?;
    full.commit
        .verify_commit_id_matches_content()
        .map_err(invalid)?;
    if &full.event.realm_id != realm || &full.commit.realm_id != realm {
        return Err(invalid("original belongs to another Realm"));
    }
    Ok(full)
}

async fn original(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    event: &EventId,
) -> PersistenceResult<OriginalRow> {
    sql_query("SELECT e.envelope AS event,c.commit_json AS commit,c.sidecar_membership_basis AS basis \
        FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
        WHERE e.realm_id=$1 AND c.realm_id=$1 AND e.envelope->>'event_id'=$2 AND e.state='committed'")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(event.as_str())
        .get_result(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| unavailable("required accepted Full membership original is absent"))
}

async fn require_governor(conn: &mut AsyncPgConnection, realm: &RealmId) -> PersistenceResult<()> {
    #[derive(QueryableByName)]
    struct Authority {
        #[diesel(sql_type = Text)]
        service_id: String,
        #[diesel(sql_type = Nullable<Text>)]
        local_service: Option<String>,
    }
    let authority = sql_query(
        "SELECT service_id,current_device_inventory_station() AS local_service \
        FROM realm_authorities WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<Authority>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if authority.is_none_or(|row| row.local_service.as_ref() != Some(&row.service_id)) {
        return Err(unavailable(
            "membership basis is available only at the actual governor",
        ));
    }
    Ok(())
}

/// Resolve ownership from the accepted Create, without any H-native PCR read.
pub(crate) async fn controller_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
) -> PersistenceResult<Option<AccountId>> {
    #[derive(QueryableByName)]
    struct Owner {
        #[diesel(sql_type = Jsonb)]
        controller: Value,
        #[diesel(sql_type = Text)]
        create_event_id: String,
    }
    let owner = sql_query("SELECT s.controller_account_id AS controller,s.create_event_id \
        FROM sidecar_current_states s JOIN realm_commits c ON c.realm_id=s.realm_id \
          AND c.commit_id=s.current_commit_id AND c.stream_position=s.current_stream_position \
          AND c.stream_ref=s.source_stream_ref \
        JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' AND e.kind='ak.sidecar.create' \
        WHERE s.realm_id=$1 AND s.sidecar_id=$2 AND s.value->>'state'='active'")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(sidecar.as_str())
        .get_result::<Owner>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(owner) = owner else { return Ok(None) };
    let controller: AccountId = serde_json::from_value(owner.controller).map_err(invalid)?;
    let create = EventId::new(owner.create_event_id).map_err(invalid)?;
    let source = full(realm, &original(conn, realm, &create).await?)?;
    if SidecarId::from_event_id(&create) != *sidecar
        || source.event.kind != EventKind::SidecarCreate
        || source.event.actor_id.as_account_id() != Some(&controller)
        || source.event.scope_ref
            != (ScopeRef::Realm {
                realm_id: realm.clone(),
            })
    {
        return Err(invalid("Create does not establish the stored controller"));
    }
    Ok(Some(controller))
}

fn agent_binding(
    source: &CommittedEventFullView,
    controller: &AccountId,
    sidecar: &SidecarId,
) -> PersistenceResult<ActorId> {
    use arkret_event_draft::EventPayloadExt as _;
    use arkret_models_collaboration::events_payloads::sidecar::SidecarMembership;
    let target = source.event.as_sidecar_member_state().map_err(invalid)?;
    let stream = CommitStreamRef::Sidecar {
        realm_id: source.event.realm_id.clone(),
        sidecar_id: sidecar.clone(),
    };
    if source.commit.stream_ref != stream
        || source.event.scope_ref != stream.scope_ref()
        || source.event.actor_id.as_account_id() != Some(controller)
        || target.agent_account_id == *controller
        || target.agent_account_id.station_id != controller.station_id
        || target.membership != SidecarMembership::Join
    {
        return Err(invalid("invalid original Sidecar enrollment"));
    }
    Ok(ActorId::account(target.agent_account_id))
}

async fn current_enrollment(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    actor: &ActorId,
    known: Option<&CommittedEventFullView>,
) -> PersistenceResult<Option<CommittedEventFullView>> {
    let Some(account) = actor.as_account_id() else {
        return Ok(None);
    };
    let Some(row) = crate::sidecar_authority_cut::enrollment(conn, realm, sidecar, account).await?
    else {
        return Ok(None);
    };
    if row.value["membership"] != "join" {
        return Ok(None);
    }
    let reference = EventId::new(row.event_id).map_err(invalid)?;
    let source = membership_original(conn, realm, &reference, known).await?;
    if source.commit.commit_id.as_str() != row.commit_id
        || source.commit.stream_position != u64::try_from(row.stream_position).map_err(invalid)?
    {
        return Err(invalid(
            "private enrollment differs from the retained original",
        ));
    }
    Ok(Some(source))
}

async fn membership_original(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    reference: &EventId,
    known: Option<&CommittedEventFullView>,
) -> PersistenceResult<CommittedEventFullView> {
    if let Some(source) = known.filter(|source| &source.event.event_id == reference) {
        return Ok(source.clone());
    }
    full(realm, &original(conn, realm, reference).await?)
}

async fn controller_creation(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    actor: &ActorId,
    known: Option<&CommittedEventFullView>,
) -> PersistenceResult<Option<CommittedEventFullView>> {
    let reference = EventId::from_token_bytes(sidecar.token_bytes()).map_err(invalid)?;
    let source = membership_original(conn, realm, &reference, known).await?;
    let Some(account) = actor.as_account_id() else {
        return Ok(None);
    };
    if source.event.kind != EventKind::SidecarCreate
        || source.event.actor_id != *actor
        || source.event.scope_ref
            != (ScopeRef::Realm {
                realm_id: realm.clone(),
            })
        || crate::morph_projection_reads::human_realm_in_connection(conn, account).await? != *realm
    {
        return Ok(None);
    }
    Ok(Some(source))
}

pub(crate) async fn actor_is_member_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    actor: &ActorId,
) -> PersistenceResult<bool> {
    require_governor(conn, realm).await?;
    let Some(controller) = controller_in_connection(conn, realm, sidecar).await? else {
        return Ok(false);
    };
    let Some(_) = controller_creation(
        conn,
        realm,
        sidecar,
        &ActorId::account(controller.clone()),
        None,
    )
    .await?
    else {
        return Ok(false);
    };
    if actor.as_account_id() == Some(&controller) {
        return Ok(true);
    }
    let Some(agent) = current_enrollment(conn, realm, sidecar, actor, None).await? else {
        return Ok(false);
    };
    Ok(agent_binding(&agent, &controller, sidecar).is_ok())
}

fn tree_actors(scope: &ScopeRef, epoch: u64, state: &[u8]) -> PersistenceResult<BTreeSet<ActorId>> {
    let group_id = scope.canonical_mls_group_id().map_err(invalid)?;
    arkret_mls::MlsPublicGroupTracker::restore(state, group_id.as_str(), epoch)
        .and_then(|tracker| tracker.leaves())
        .map_err(invalid)
        .map(|leaves| leaves.into_iter().map(|leaf| leaf.actor_id).collect())
}

async fn resolve_basis(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    controller: &AccountId,
    basis: &MembershipBasis,
    known: &[&CommittedEventFullView],
) -> PersistenceResult<(
    CommittedEventFullView,
    BTreeMap<ActorId, CommittedEventFullView>,
)> {
    basis.validate_references()?;
    let join = membership_original(
        conn,
        realm,
        &basis.controller_create_event_ref,
        known
            .iter()
            .copied()
            .find(|source| source.event.event_id == basis.controller_create_event_ref),
    )
    .await?;
    if join.event.kind != EventKind::SidecarCreate
        || SidecarId::from_event_id(&join.event.event_id) != *sidecar
        || join.event.actor_id.as_account_id() != Some(controller)
    {
        return Err(invalid("controller join belongs to another Actor"));
    }
    let mut agents = BTreeMap::new();
    for reference in &basis.agent_join_event_refs {
        let source = membership_original(
            conn,
            realm,
            reference,
            known
                .iter()
                .copied()
                .find(|source| &source.event.event_id == reference),
        )
        .await?;
        let actor = agent_binding(&source, controller, sidecar)?;
        if agents.insert(actor, source).is_some() {
            return Err(invalid("multiple generations of one Agent in a state"));
        }
    }
    Ok((join, agents))
}

fn state_basis(
    source: &CommittedEventFullView,
    basis: Option<&Value>,
    scope: &ScopeRef,
) -> PersistenceResult<MembershipBasis> {
    if source.event.scope_ref != *scope
        || !matches!(
            source.event.kind,
            EventKind::MlsGenesis | EventKind::MlsCommit
        )
    {
        return Err(invalid("basis does not cover this Sidecar MLS original"));
    }
    serde_json::from_value(
        basis
            .cloned()
            .ok_or_else(|| unavailable("accepted MLS state lacks its original membership basis"))?,
    )
    .map_err(invalid)
}

/// Freeze the actual resulting membership, never H's full desired/native set.
pub(crate) async fn freeze_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    installation: &MlsStateInstallation,
) -> PersistenceResult<()> {
    let ScopeRef::Sidecar {
        realm_id,
        sidecar_id,
    } = &transaction.event.scope_ref
    else {
        return Ok(());
    };
    require_governor(conn, realm_id).await?;
    let controller = controller_in_connection(conn, realm_id, sidecar_id)
        .await?
        .ok_or_else(|| invalid("Sidecar controller is unavailable"))?;
    let join = controller_creation(
        conn,
        realm_id,
        sidecar_id,
        &ActorId::account(controller.clone()),
        None,
    )
    .await?
    .ok_or_else(|| invalid("personal Sidecar creation proof is unavailable"))?;
    // The serving owner derives this set from the verified RFC tracker once.
    let actors = &installation.member_principals;
    if installation.effective_scope != transaction.event.scope_ref
        || actors.is_empty()
        || (transaction.event.kind == EventKind::MlsGenesis
            && actors != &BTreeSet::from([ActorId::account(controller.clone())]))
    {
        return Err(invalid(
            "verified resulting tree differs from the Sidecar membership installation",
        ));
    }
    let mut refs = Vec::new();
    for actor in actors {
        if actor.as_account_id() == Some(&controller) {
            continue;
        }
        let agent = current_enrollment(conn, realm_id, sidecar_id, actor, None)
            .await?
            .ok_or_else(|| invalid("resulting Agent leaf is not currently joined"))?;
        agent_binding(&agent, &controller, sidecar_id)?;
        refs.push(agent.event.event_id);
    }
    refs.sort_by(|a, b| a.as_str().as_bytes().cmp(b.as_str().as_bytes()));
    let basis = MembershipBasis {
        controller_create_event_ref: join.event.event_id,
        agent_join_event_refs: refs,
    };
    let row = original(conn, realm_id, &transaction.event.event_id).await?;
    let accepted = full(realm_id, &row)?;
    if serde_json::to_value(&accepted.event).map_err(invalid)?
        != serde_json::to_value(&transaction.event).map_err(invalid)?
        || serde_json::to_value(&accepted.commit).map_err(invalid)?
            != serde_json::to_value(&transaction.commit).map_err(invalid)?
    {
        return Err(invalid(
            "fresh transition cannot rebind an accepted original membership basis",
        ));
    }
    let supplied = serde_json::to_value(basis).map_err(invalid)?;
    match row.basis {
        None => attach(conn, &accepted.commit.commit_id, &supplied).await,
        Some(existing) if existing == supplied => Ok(()),
        Some(_) => Err(invalid(
            "accepted original already has a different membership basis",
        )),
    }
}

async fn attach(
    conn: &mut AsyncPgConnection,
    commit: &arkret_wire::RealmCommitId,
    basis: &Value,
) -> PersistenceResult<()> {
    let updated = sql_query(
        "UPDATE realm_commits SET sidecar_membership_basis=$1 \
        WHERE commit_id=$2 AND sidecar_membership_basis IS NULL",
    )
    .bind::<Jsonb, _>(basis)
    .bind::<Text, _>(commit.as_str())
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if updated != 1 {
        return Err(invalid(
            "membership basis attachment lost its exact original",
        ));
    }
    Ok(())
}

/// A stale incarnation requires a real new transition; old leaf provenance stays intact.
pub(crate) async fn current_state_is_confirmed(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    current: &MlsGroupCurrentRecord,
) -> PersistenceResult<bool> {
    require_governor(conn, realm).await?;
    if &current.realm_id != realm
        || current.value.effective_scope
            != (ScopeRef::Sidecar {
                realm_id: realm.clone(),
                sidecar_id: sidecar.clone(),
            })
    {
        return Err(invalid("group current belongs to another effective scope"));
    }
    let Some(controller) = controller_in_connection(conn, realm, sidecar).await? else {
        return Ok(false);
    };
    let row = original(conn, realm, &current.value.current_mls_commit_event_ref).await?;
    let source = full(realm, &row)?;
    let basis = state_basis(&source, row.basis.as_ref(), &current.value.effective_scope)?;
    if source.commit.commit_id != current.current_commit_id {
        return Err(invalid("current state has a different covering Commit"));
    }
    if basis.agent_join_event_refs.is_empty() {
        basis.validate_references()?;
        let actors = tree_actors(
            &current.value.effective_scope,
            current.value.epoch,
            &current.public_state,
        )?;
        if actors != BTreeSet::from([ActorId::account(controller.clone())]) {
            return Err(invalid(
                "controller-only basis differs from the actual tree",
            ));
        }
        // A recorded old controller cut is not an extra current send gate.
        return Ok(
            controller_creation(conn, realm, sidecar, &ActorId::account(controller), None)
                .await?
                .is_some(),
        );
    }
    let (controller_source, agents) =
        resolve_basis(conn, realm, sidecar, &controller, &basis, &[]).await?;
    let actors = tree_actors(
        &current.value.effective_scope,
        current.value.epoch,
        &current.public_state,
    )?;
    if actors.is_empty()
        || actors
            .iter()
            .filter(|actor| actor.as_account_id() != Some(&controller))
            .cloned()
            .collect::<BTreeSet<_>>()
            != agents.keys().cloned().collect()
    {
        return Err(invalid(
            "current tree differs from its confirmed membership basis",
        ));
    }
    let Some(join) = controller_creation(
        conn,
        realm,
        sidecar,
        &ActorId::account(controller.clone()),
        Some(&controller_source),
    )
    .await?
    else {
        return Ok(false);
    };
    if join.event.event_id != basis.controller_create_event_ref {
        return Ok(false);
    }
    for (actor, original) in agents {
        let Some(agent) = current_enrollment(conn, realm, sidecar, &actor, Some(&original)).await?
        else {
            return Ok(false);
        };
        if agent.event.event_id != original.event.event_id
            || agent_binding(&agent, &controller, sidecar).is_err()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// G's private source is not copied to ordinary replicas or inferred from D.
pub(crate) async fn agent_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    sidecar: &SidecarId,
    actor: &ActorId,
) -> PersistenceResult<Option<ReadableFloor>> {
    require_governor(conn, realm).await?;
    let Some(controller) = controller_in_connection(conn, realm, sidecar).await? else {
        return Ok(None);
    };
    if actor.as_account_id() == Some(&controller) {
        return Ok(None);
    }
    let Some(controller_create) = controller_creation(
        conn,
        realm,
        sidecar,
        &ActorId::account(controller.clone()),
        None,
    )
    .await?
    else {
        return Ok(None);
    };
    let Some(agent) = current_enrollment(conn, realm, sidecar, actor, None).await? else {
        return Ok(None);
    };
    if agent_binding(&agent, &controller, sidecar).is_err() {
        return Ok(None);
    }
    let scope = ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let row = sql_query(
        "SELECT e.envelope AS event,c.commit_json AS commit,c.sidecar_membership_basis AS basis \
        FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
        WHERE c.realm_id=$1 AND c.stream_ref=$2 AND e.state='committed' \
          AND e.kind IN ('ak.mls.genesis','ak.mls.commit') \
          AND c.sidecar_membership_basis->>'controller_create_event_ref'=$3 \
          AND c.sidecar_membership_basis->'agent_join_event_refs' @> $4 \
        ORDER BY c.stream_position LIMIT 1",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Jsonb, _>(
        serde_json::to_value(CommitStreamRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: sidecar.clone(),
        })
        .map_err(invalid)?,
    )
    .bind::<Text, _>(controller_create.event.event_id.as_str())
    .bind::<Jsonb, _>(serde_json::json!([agent.event.event_id]))
    .get_result::<OriginalRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if let Some(row) = row {
        let source = full(realm, &row)?;
        let basis = state_basis(&source, row.basis.as_ref(), &scope)?;
        let (_, agents) = resolve_basis(
            conn,
            realm,
            sidecar,
            &controller,
            &basis,
            &[&controller_create, &agent],
        )
        .await?;
        if basis.controller_create_event_ref == controller_create.event.event_id
            && agents.get(actor).map(|source| &source.event.event_id) == Some(&agent.event.event_id)
        {
            return Ok(Some(ReadableFloor {
                oldest_position: source.commit.stream_position,
                floor_commit_id: source.commit.commit_id,
                floor_reason: if source.commit.stream_position == 0 {
                    ReadableFloorReason::StreamStart
                } else {
                    ReadableFloorReason::HistoryAccessPolicy
                },
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(byte: u8) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
    }

    #[test]
    fn membership_basis_has_no_agent_count_veto_and_rejects_ambiguous_references() {
        let mut basis = MembershipBasis {
            controller_create_event_ref: event(0),
            agent_join_event_refs: (1..=65).map(event).collect(),
        };
        basis
            .agent_join_event_refs
            .sort_by(|a, b| a.as_str().as_bytes().cmp(b.as_str().as_bytes()));
        assert!(basis.validate_references().is_ok());
        basis
            .agent_join_event_refs
            .push(basis.agent_join_event_refs[0].clone());
        assert!(basis.validate_references().is_err());
        basis.agent_join_event_refs = vec![event(0)];
        assert!(basis.validate_references().is_err());
    }

    #[test]
    fn membership_basis_is_closed_and_does_not_admit_an_old_head() {
        let basis = MembershipBasis {
            controller_create_event_ref: event(0),
            agent_join_event_refs: vec![],
        };
        let mut value = serde_json::to_value(&basis).unwrap();
        value["authority_stream_head"] = serde_json::json!([]);
        assert!(serde_json::from_value::<MembershipBasis>(value).is_err());
        let value = serde_json::json!({"controller_create_event_ref": event(0), "agent_join_event_refs": null});
        assert!(serde_json::from_value::<MembershipBasis>(value).is_err());
    }
}
