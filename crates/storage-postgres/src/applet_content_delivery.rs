//! Session-free delivery at the real managed Account, PCR and resource cut.
use std::collections::BTreeMap;

use arkret_models_collaboration::governance::accountability::AccountabilityProjection;
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilitySubject, IssuerAuthorityRef, ManagedActorRole,
};
use arkret_models_collaboration::governance::operation_wire::{
    AppletPolicyOperation, Policy, PolicyResourceKind, PolicyResourceSelector,
};
use arkret_wire::{
    AccountId, ActorId, CapabilityActionId, CommittedEventView, DidCoreId, EventKind, GrantId,
    ScopeRef, WireResourceSelector,
};
use coland_storage::{
    AccountContentDeliveryGuard, AccountContentDeliveryInput, AppletManagedDeviceScopeGuard,
    AuthorizationOperation, OperationFacts, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::RunQueryDsl;

use crate::capability_grant_current_results::{
    CapabilityGrantCurrentResultReadRow, RealmAuthorityRootCurrent, RealmAuthorityRootReadRow,
    decode_authority_root, decode_row,
};

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
}
fn refused(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}
struct ReadOperation {
    action: CapabilityActionId,
    targets: Vec<WireResourceSelector>,
    facts: OperationFacts,
}
struct ReadProof {
    checked_at: chrono::DateTime<chrono::Utc>,
    credential_expiry: chrono::DateTime<chrono::Utc>,
    endpoint: AppletManagedDeviceScopeGuard,
    registration: arkret_models_integration::AppletRegistrationPayload,
    role: ManagedActorRole,
    root: RealmAuthorityRootCurrent,
    grants: BTreeMap<GrantId, CapabilityGrant>,
    policies: Vec<Policy>,
    accountability: Vec<AccountabilityProjection>,
    resources: Vec<PolicyResourceSelector>,
    operations: Vec<ReadOperation>,
}
impl ReadProof {
    fn root_current(&self, source: &IssuerAuthorityRef) -> bool {
        matches!(source,IssuerAuthorityRef::RealmRoot{realm_id,authority_event_ref,authority_generation}
            if realm_id==self.endpoint.effective_scope.realm_id() && authority_event_ref==&self.root.authority_event_ref
                && authority_generation==&self.root.authority_generation)
    }
    fn permits_at(&self, at: chrono::DateTime<chrono::Utc>) -> bool {
        at >= self.checked_at
            && at >= self.endpoint.authority.not_before
            && at < self.endpoint.authority.expires_at
            && at < self.credential_expiry
            && self.accountability.iter().any(|a| a.verifies_at(at))
            && self
                .operations
                .iter()
                .all(|operation| self.operation_permitted(operation, at).unwrap_or(false))
    }
    fn operation_permitted(
        &self,
        operation: &ReadOperation,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let service = ActorId::service(self.registration.service_id.clone());
        let account = ActorId::account(self.endpoint.authority.account_id.clone());
        let action = operation.action.as_str();
        let actions = [action];
        for mode in [AppletPolicyOperation::Read, AppletPolicyOperation::Deliver] {
            let decision = arkret_policy::applet_management::select_applet_management(
                Some(&self.policies),
                &arkret_policy::applet_management::AppletManagementContext {
                    realm_id: self.endpoint.effective_scope.realm_id(),
                    requester_actor_id: &service,
                    applet_id: &self.registration.applet_id,
                    effective_scope: &self.endpoint.effective_scope,
                    managed_actor_id: Some(&account),
                    operation: mode,
                    content_action: Some(operation.action),
                    resources: Some(&self.resources),
                    at,
                },
            )
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
            if decision.effect != arkret_wire::PolicyEffect::Allow {
                return Ok(false);
            }
        }
        let mut candidates = BTreeMap::new();
        for target in &operation.targets {
            for actor in [&account, &service] {
                let grants = arkret_policy::grant_authority::current_subject_grants(
                    actor,
                    action,
                    target,
                    &self.grants,
                    at,
                    |source| self.root_current(source),
                )
                .map_err(|e| PersistenceError::Conflict(e.to_string()))?;
                let mut facts = operation.facts.clone();
                facts.executed_by = Some(actor.clone());
                if coland_storage::evaluate_authority_sources_with_verified_approvals(
                    &AuthorizationOperation {
                        actor,
                        actions: &actions,
                        target,
                        at,
                        facts: &facts,
                    },
                    grants.iter().copied(),
                    &[],
                )
                .is_refusal()
                {
                    return Ok(false);
                }
                if actor == &service {
                    for grant in grants {
                        if arkret_policy::grant_authority::managed_service_source(
                            grant,
                            &service,
                            &self.registration.applet_id,
                            &self.registration.registration_epoch,
                            self.role,
                            action,
                        ) {
                            candidates
                                .entry(grant.id.clone())
                                .or_insert((grant, target));
                        }
                    }
                }
            }
        }
        // This consumer counts only complete unreserved paths. External quota
        // and review paths remain closed until their accepting operation is
        // wired; another explicit unreserved source is a normal alternative.
        for (grant, target) in candidates.into_values() {
            let mut sources = arkret_policy::grant_authority::current_sources(
                grant,
                action,
                target,
                &self.grants,
                at,
                |source| self.root_current(source),
            )
            .map_err(|e| PersistenceError::Conflict(e.to_string()))?;
            sources.push(grant);
            let mut allowed = true;
            for source in sources {
                let CapabilitySubject::Actor(actor) = &source.subject else {
                    allowed = false;
                    break;
                };
                let mut facts = operation.facts.clone();
                facts.executed_by = Some(actor.clone());
                let current = arkret_policy::grant_authority::current_subject_grants(
                    actor,
                    action,
                    target,
                    &self.grants,
                    at,
                    |source| self.root_current(source),
                )
                .map_err(|e| PersistenceError::Conflict(e.to_string()))?;
                let op = AuthorizationOperation {
                    actor,
                    actions: &actions,
                    target,
                    at,
                    facts: &facts,
                };
                if coland_storage::evaluate_authority_sources_with_verified_approvals(
                    &op,
                    current,
                    &[],
                )
                .is_refusal()
                    || coland_storage::evaluate_authority_sources_with_verified_approvals(
                        &op,
                        [source],
                        &[],
                    )
                    .unreserved()
                    .is_empty()
                {
                    allowed = false;
                    break;
                }
            }
            if allowed {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
struct NativeDeliveryGuard {
    held: Box<crate::account_content_delivery::DeliveryGuard>,
    proofs: Vec<ReadProof>,
}
#[async_trait::async_trait]
impl AccountContentDeliveryGuard for NativeDeliveryGuard {
    fn permits_handoff(&self) -> bool {
        let at = chrono::Utc::now();
        self.proofs.iter().all(|proof| proof.permits_at(at))
    }
    async fn finish(self: Box<Self>) -> PersistenceResult<()> {
        self.held.finish().await
    }
}

pub(crate) async fn acquire(
    pool: &crate::PgPool,
    account: &AccountId,
    station: &DidCoreId,
    endpoint: &AppletManagedDeviceScopeGuard,
    input: &AccountContentDeliveryInput,
) -> PersistenceResult<Option<Box<dyn AccountContentDeliveryGuard>>> {
    if &endpoint.authority.account_id != account
        || &account.station_id != station
        || !matches!(
            endpoint.effective_scope,
            ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
        )
        || input.committed_events.is_empty()
        || input.committed_events.len() > 64
        || !input.current_views.is_empty()
        || !input.projection_lists.is_empty()
        || !input.morph_lists.is_empty()
        || !input.morph_documents.is_empty()
        || !input.morph_absences.is_empty()
        || !input.account_status_observations.is_empty()
        || !input.realm_exports.is_empty()
        || !input.snapshots.is_empty()
        || !input.future_materials.is_empty()
        || !input.notifications.is_empty()
        || !input.exact_reads.is_empty()
        || !input.watch_reads.is_empty()
        || input.remote_watch_read.is_some()
        || input.audited_watch_read.is_some()
        || input.watch_delivery_device.is_some()
        || input.watch_local_session.is_some()
        || !input.blobs.is_empty()
        || input.agent_session_scope.is_some()
        || input.agent_endpoint.is_some()
        || input.qualified_agent_scope_evidence.is_some()
        || !input.unresolved_content_realms.is_empty()
        || input
            .realms
            .iter()
            .any(|r| r != endpoint.effective_scope.realm_id())
    {
        return Err(refused(
            "native delivery has no consumer for these exact inputs",
        ));
    }
    let credential_expiry = input
        .credential_expires_at
        .ok_or_else(|| refused("native read transport expiry is unavailable"))?;
    let mut held = crate::account_content_delivery::DeliveryGuard::begin(pool).await?;
    let mut realms = vec![
        endpoint.authority.pcr_realm_id.clone(),
        endpoint.effective_scope.realm_id().clone(),
    ];
    realms.sort();
    realms.dedup();
    for realm in realms {
        let locked=sql_query("SELECT to_jsonb(a) AS value FROM realm_authorities a WHERE realm_id=$1 FOR SHARE NOWAIT")
            .bind::<Text,_>(realm.as_str()).get_result::<JsonRow>(held.connection()).await.map_err(PersistenceError::database)?;
        if locked.value["service_id"].as_str() != Some(station.as_str()) {
            return Err(refused(
                "native read has no current local governing barrier",
            ));
        }
    }
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let current = crate::pcr_applet_device_authority::current_in_connection(
        held.connection(),
        account,
        &endpoint.authority.device_id,
        at,
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?
    .ok_or_else(|| refused("native read Device is unavailable"))?;
    if current != endpoint.authority {
        return Err(refused("native read Device instance changed"));
    }
    let mut proofs = Vec::with_capacity(input.committed_events.len());
    for original in &input.committed_events {
        proofs.push(
            crate::boxed_future(|| {
                event_proof(
                    held.connection(),
                    station,
                    endpoint,
                    &current,
                    original,
                    at,
                    credential_expiry,
                )
            })
            .await?,
        );
    }
    Ok(Some(Box::new(NativeDeliveryGuard { held, proofs })))
}

async fn event_proof(
    conn: &mut diesel_async::AsyncPgConnection,
    station: &DidCoreId,
    endpoint: &AppletManagedDeviceScopeGuard,
    current: &coland_storage::AppletManagedDeviceAuthority,
    original: &CommittedEventView,
    at: chrono::DateTime<chrono::Utc>,
    credential_expiry: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<ReadProof> {
    let account = &endpoint.authority.account_id;
    let full = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &original.commit().event_ref,
    )
    .await?
    .ok_or_else(|| refused("native read target scope is unproved"))?;
    if full.event.scope_ref != endpoint.effective_scope
        || full.event.realm_id != *endpoint.effective_scope.realm_id()
    {
        return Err(refused(
            "native read target differs from its authenticated scope",
        ));
    }
    let encrypted=sql_query("SELECT to_jsonb(EXISTS(SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.state='committed' AND e.kind='ak.mls.genesis' AND c.realm_id=$1 AND e.envelope->'scope_ref'=$2)) AS value")
        .bind::<Text,_>(full.event.realm_id.as_str()).bind::<Jsonb,_>(serde_json::json!(full.event.scope_ref)).get_result::<JsonRow>(conn).await.map_err(PersistenceError::database)?;
    if encrypted.value.as_bool() != Some(false) {
        return Err(PersistenceError::Conflict(
            "applet_e2ee_join_unauthorized: native MLS read consent is not established".into(),
        ));
    }
    let actor = ActorId::account(account.clone());
    let reread = crate::boxed_future(|| {
        crate::account_stream_scan::committed_event_for_member_in_connection(
            conn,
            &full.event.event_id,
            &actor,
            station,
        )
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)?;
    let coland_storage::MemberCommittedEventRead::Read(reread) = reread else {
        return Err(refused("native Event history is not currently visible"));
    };
    if reread.as_ref() != original {
        return Err(refused("native Event disclosure changed before handoff"));
    }
    let mut actions = vec![CapabilityActionId::EventRead];
    if matches!(original, CommittedEventView::Full(_))
        && matches!(
            full.event.kind,
            EventKind::MessageCreate
                | EventKind::MessageRevise
                | EventKind::MorphCreate
                | EventKind::MorphUpdate
        )
    {
        actions.push(CapabilityActionId::ObjectReadContent);
    }
    let (registration, _) = crate::boxed_future(|| {
        crate::applet_device_admission::installation_for_device(
            conn,
            current,
            &full.event.scope_ref,
            &endpoint.service_did_document,
            &actions,
            at,
            false,
        )
    })
    .await?;
    let sources=sql_query("SELECT e.envelope->'payload' AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.state='committed' AND e.kind='ak.applet.managed_actor.provision' AND e.envelope#>'{payload,actor_id}'=$1")
        .bind::<Jsonb,_>(serde_json::json!(actor)).get_results::<JsonRow>(conn).await.map_err(PersistenceError::database)?;
    let [source] = sources.as_slice() else {
        return Err(refused("native read provision is not unique"));
    };
    let provision: arkret_models_integration::AppletManagedActorProvisionPayload =
        serde_json::from_value(source.value.clone()).map_err(PersistenceError::database)?;
    if provision.actor_id != actor
        || provision.service_id != registration.service_id
        || provision.applet_id != registration.applet_id
    {
        return Err(refused("native read provision differs"));
    }
    let role = match provision.actor_role {
        arkret_models_integration::AppletManagedActorRole::Bot => ManagedActorRole::Bot,
        arkret_models_integration::AppletManagedActorRole::Ghost => ManagedActorRole::Ghost,
    };
    let root=sql_query("SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1 FOR SHARE")
        .bind::<Text,_>(full.event.realm_id.as_str()).get_result::<RealmAuthorityRootReadRow>(conn).await.map_err(PersistenceError::database)?;
    let rows=sql_query("SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value FROM capability_grant_current_results WHERE realm_id=$1 ORDER BY grant_id FOR SHARE")
        .bind::<Text,_>(full.event.realm_id.as_str()).get_results::<CapabilityGrantCurrentResultReadRow>(conn).await.map_err(PersistenceError::database)?;
    let mut grants = BTreeMap::new();
    for row in rows {
        let row = decode_row(row)?;
        grants.insert(row.grant_id, row.value);
    }
    let cut = crate::boxed_future(|| {
        crate::realm_authorization_cut::RealmAuthorizationCut::read(
            conn,
            &full.event.realm_id,
            &actor,
        )
    })
    .await?;
    cut.require_governed_member(&full.event.kind)?;
    cut.require_open_content_read()?;
    let mut resources = crate::agent_management_admission::event_content_resources(&full.event)?;
    if let ScopeRef::Circle { circle_id, .. } = &full.event.scope_ref {
        resources.push(PolicyResourceSelector {
            kind: PolicyResourceKind::Object,
            realm_id: Some(full.event.realm_id.clone()),
            resource_ref: Some(circle_id.to_string()),
        });
    }
    let mut operations = Vec::new();
    for action in actions {
        let (target, mut facts) = cut.content_scope_facts(&full.event, action)?;
        facts.applet_id = Some(registration.applet_id.to_string());
        facts.registration_epoch = Some(registration.registration_epoch.to_string());
        let mut targets = crate::agent_management_admission::content_capability_targets(
            &full.event.realm_id,
            &resources,
        );
        if !targets.contains(&target) {
            targets.push(target);
        }
        if let ScopeRef::Circle {
            realm_id,
            circle_id,
        } = &full.event.scope_ref
        {
            let circle = WireResourceSelector::circle(realm_id.clone(), circle_id.clone());
            if !targets.contains(&circle) {
                targets.push(circle);
            }
        }
        operations.push(ReadOperation {
            action,
            targets,
            facts,
        });
    }
    let policies =
        crate::policy_current_results::read_scoped_applet_management_policies_in_connection(
            conn,
            &full.event.realm_id,
            full.event.scope_ref.circle_id(),
        )
        .await?;
    let accountability=sql_query("SELECT value FROM identity_accountability_current_results WHERE subject_id=$1 AND issuer_id=$2 ORDER BY realm_id,scope_set_digest FOR SHARE")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(registration.service_id.as_str()).get_results::<JsonRow>(conn).await.map_err(PersistenceError::database)?
        .into_iter().map(|row|serde_json::from_value(row.value).map_err(PersistenceError::database)).collect::<PersistenceResult<Vec<AccountabilityProjection>>>()?;
    let proof = ReadProof {
        checked_at: at,
        credential_expiry,
        endpoint: endpoint.clone(),
        registration,
        role,
        root: decode_authority_root(root)?,
        grants,
        policies,
        accountability,
        resources,
        operations,
    };
    if !proof.permits_at(at) {
        return Err(refused(
            "native read has no current unreserved Applet content source",
        ));
    }
    Ok(proof)
}
