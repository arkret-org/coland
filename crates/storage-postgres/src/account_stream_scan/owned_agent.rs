//! Governance-side account disclosure on a live request from the owning Station.
use arkret_models_collaboration::authority_commit::OwnedAgentStreamScanRequestBody;
use arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef;
use arkret_models_collaboration::governance::operation_wire::{
    AgentPolicyOperation, Policy, PolicyResourceKind, PolicyResourceSelector,
};
use arkret_models_collaboration::governance::realm_join_intake::OwnedAgentContentAction;
use arkret_wire::{
    ActorId, CapabilityActionId, CommitStreamRef, DidCoreId, StreamScanResponseBody,
};
use coland_storage::{AccountContentDeliveryGuard, PersistenceError, PersistenceResult};
use diesel::sql_types::Text;
use horme::RunQueryDsl;

use crate::account_content_delivery::DeliveryGuard;
use crate::realm_authorization_cut::RealmAuthorizationCut;

fn denied() -> PersistenceError {
    PersistenceError::Conflict("capability_denied: Agent history is unavailable".into())
}

struct GoverningDelivery {
    held: Box<DeliveryGuard>,
    authority: ProjectReadAuthority,
}

pub(crate) struct ProjectReadAuthority {
    request: OwnedAgentStreamScanRequestBody,
    agent: RealmAuthorizationCut,
    controller: RealmAuthorizationCut,
    source: IssuerAuthorityRef,
    policies: Vec<Policy>,
    events: Vec<arkret_wire::Event>,
    resources: Vec<Vec<PolicyResourceSelector>>,
}

impl ProjectReadAuthority {
    pub(crate) async fn load(
        conn: &mut crate::AsyncPgConnection,
        request: &OwnedAgentStreamScanRequestBody,
        pair: &crate::agent_interaction_current_states::GovernedJoinPair,
        local_station: &DidCoreId,
    ) -> PersistenceResult<Self> {
        let realm = &request.scan.realm_id;
        if !matches!(
            request.scan.stream_ref,
            CommitStreamRef::Realm { .. } | CommitStreamRef::Circle { .. }
        ) {
            return Err(denied());
        }
        let agent_actor = ActorId::account(request.member_account_id.clone());
        let controller_actor = ActorId::account(pair.controller.clone());
        let (agent, controller) = if local_station == &request.member_account_id.station_id {
            // H has the verified replica of G's grant/policy cut.
            (
                RealmAuthorizationCut::read_accepted(conn, realm, &agent_actor).await?,
                RealmAuthorizationCut::read_accepted(conn, realm, &controller_actor).await?,
            )
        } else {
            (
                RealmAuthorizationCut::read(conn, realm, &agent_actor).await?,
                RealmAuthorizationCut::read(conn, realm, &controller_actor).await?,
            )
        };
        let source = IssuerAuthorityRef::OwnedAgent {
            realm_id: realm.clone(),
            controller_account_id: pair.controller.clone(),
            controller_join_event_id: pair.controller_commit.event_ref.clone(),
            agent_join_event_id: pair.agent_commit.event_ref.clone(),
        };
        let policies = crate::policy_current_states::read_scoped_agent_management_policy_snapshot_in_connection(conn, realm, None).await?;
        let resources = vec![vec![PolicyResourceSelector {
            kind: PolicyResourceKind::Realm,
            realm_id: Some(realm.clone()),
            resource_ref: Some(realm.to_string()),
        }]];
        Ok(Self {
            request: request.clone(),
            agent,
            controller,
            source,
            policies,
            events: Vec::new(),
            resources,
        })
    }

    pub(crate) fn add_page(&mut self, page: &StreamScanResponseBody) -> PersistenceResult<()> {
        for event in page
            .committed_events
            .iter()
            .filter_map(|item| item.reducer_input())
        {
            self.add_event(event)?;
        }
        self.check()
    }

    fn add_event(&mut self, event: &arkret_wire::Event) -> PersistenceResult<()> {
        if event.scope_ref != self.request.content_intent.effective_scope {
            return Err(denied());
        }
        let mut targets = crate::agent_management_admission::event_content_resources(event)?;
        for target in &self.resources[0] {
            if !targets.contains(target) {
                targets.push(target.clone());
            }
        }
        self.resources.push(targets);
        self.events.push(event.clone());
        Ok(())
    }

    pub(crate) fn check(&self) -> PersistenceResult<()> {
        let now = chrono::Utc::now();
        let intent = &self.request.content_intent;
        let action = CapabilityActionId::EventRead;
        self.agent.require_open_content_read()?;
        self.controller.require_open_content_read()?;
        self.agent
            .require_projection_read_for_source(now, Some(self.source.clone()))?;
        self.controller.require_realm_projection_read(now)?;
        for targets in &self.resources {
            for operation in [AgentPolicyOperation::Read, AgentPolicyOperation::Deliver] {
                crate::agent_management_admission::require_content_policy(
                    &self.policies,
                    &self.request.scan.realm_id,
                    &intent.controller_account_id,
                    &self.request.member_account_id,
                    operation,
                    action,
                    targets,
                    now,
                )?;
            }
        }
        for event in &self.events {
            self.agent.require_content_read_constraints(
                event,
                now,
                Some(self.source.clone()),
                action,
            )?;
            self.controller
                .require_content_read_constraints(event, now, None, action)?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl AccountContentDeliveryGuard for GoverningDelivery {
    async fn prepare_handoff(&mut self) -> bool {
        self.held.probe().await.is_ok() && self.authority.check().is_ok()
    }
    async fn finish(self: Box<Self>) -> PersistenceResult<()> {
        self.held.finish().await
    }
}

pub(crate) async fn acquire(
    pool: &crate::PgPool,
    request: &OwnedAgentStreamScanRequestBody,
    home: &DidCoreId,
    governor: &DidCoreId,
) -> PersistenceResult<(StreamScanResponseBody, Box<dyn AccountContentDeliveryGuard>)> {
    request
        .validate_binding()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let realm = &request.scan.realm_id;
    if !matches!(
        request.scan.stream_ref,
        CommitStreamRef::Realm { .. } | CommitStreamRef::Circle { .. }
    ) {
        return Err(denied());
    }
    let intent = &request.content_intent;
    if home != &request.member_account_id.station_id
        || home == governor
        || intent.action != OwnedAgentContentAction::EventRead
        || intent.strand_id.is_some()
    {
        return Err(denied());
    }
    let mut held = DeliveryGuard::begin(pool).await?;
    let conn = held.connection();
    crate::sync_cursor::retention::lock(conn, false)
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
    let active = diesel::sql_query(
        "SELECT EXISTS(SELECT 1 FROM realm_authorities a
        WHERE a.realm_id=$1 AND a.service_id=$2 AND a.service_id=current_device_inventory_station()
        AND NOT EXISTS(SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk
          WHERE c.realm_id=a.realm_id AND c.governance_generation=a.generation
          AND e.kind='ak.realm.governance_station.change')) AS present",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(governor.as_str())
    .get_result::<crate::query_rows::ExistsRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !active.present {
        return Err(denied());
    }
    let pair = crate::agent_interaction_current_states::governed_join_pair(
        conn,
        realm,
        &request.member_account_id,
        chrono::Utc::now(),
        true,
        None,
    )
    .await?
    .ok_or_else(denied)?;
    if pair.controller != intent.controller_account_id
        || pair.controller_commit.commit_id != intent.controller_membership_commit_id
        || pair.agent_commit.commit_id != request.membership_commit_id
    {
        return Err(denied());
    }
    let agent_actor = ActorId::account(request.member_account_id.clone());
    let controller_actor = ActorId::account(pair.controller.clone());
    let floor = match &request.scan.stream_ref {
        CommitStreamRef::Realm { .. } => {
            crate::account_stream_scan::caller_realm_floor_in_connection(conn, realm, &agent_actor)
                .await?
        }
        CommitStreamRef::Circle { circle_id, .. } => {
            crate::account_stream_scan::caller_circle_floor_in_connection(
                conn,
                realm,
                circle_id,
                &agent_actor,
            )
            .await?
        }
        _ => return Err(denied()),
    }
    .ok_or_else(denied)?;
    let mut page = crate::authority_commit::stream_page_above_floor_in_connection(
        conn,
        &request.scan,
        Some(floor),
    )
    .await?;
    let ids = page
        .committed_events
        .iter()
        .map(|row| row.commit().commit_id.to_string())
        .collect::<Vec<_>>();
    let withheld =
        crate::committed_disclosure::withheld_commit_ids_in_connection(conn, &ids).await?;
    let now = chrono::Utc::now();
    for item in &mut page.committed_events {
        let arkret_wire::CommittedEventView::Full(row) = item else {
            continue;
        };
        if withheld.contains(row.commit.commit_id.as_str())
            || !crate::committed_disclosure::member_event_visible_in_connection(
                conn,
                row,
                &agent_actor,
                now,
            )
            .await?
            || !crate::committed_disclosure::member_event_visible_in_connection(
                conn,
                row,
                &controller_actor,
                now,
            )
            .await?
        {
            *item = arkret_wire::CommittedEventView::Withheld(
                arkret_wire::CommittedEventWithheldView {
                    commit: row.commit.clone(),
                    event_disclosure: arkret_wire::EventDisclosure {
                        status: arkret_wire::EventDisclosureStatus::Withheld,
                    },
                },
            );
        }
    }
    page.validate_for_request(&request.scan)
        .map_err(PersistenceError::database)?;
    let mut authority = ProjectReadAuthority::load(conn, request, &pair, governor).await?;
    authority.add_page(&page)?;
    let guard = GoverningDelivery { held, authority };
    Ok((page, Box::new(guard)))
}
