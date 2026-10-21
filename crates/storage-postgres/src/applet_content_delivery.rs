//! Session-free delivery at the Realm actor, Device and resource cut.
use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilitySubject, IssuerAuthorityRef, ManagedActorRole,
};
use arkret_models_collaboration::governance::operation_wire::{
    AppletPolicyOperation, Policy, PolicyResourceKind, PolicyResourceSelector,
};
use arkret_wire::{
    ActorId, CapabilityActionId, CommittedEventView, DidCoreId, EventKind, GrantId, ScopeRef,
    WireResourceSelector,
};
use coland_storage::{
    AccountContentDeliveryGuard, AccountContentDeliveryInput, AppletManagedDeviceScopeGuard,
    AuthorizationOperation, OperationFacts, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Jsonb, Text};
use diesel::{OptionalExtension as _, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;

use crate::capability_grant_current_results::{
    CapabilityGrantCurrentResultReadRow, RealmAuthorityRootCurrent, RealmAuthorityRootReadRow,
    decode_authority_root, decode_row,
};

#[path = "applet_blob_delivery.rs"]
mod blobs;
#[path = "applet_exact_current_delivery.rs"]
mod exact_current;
#[path = "applet_mls_material_delivery.rs"]
mod mls_material;
#[path = "applet_snapshot_delivery.rs"]
mod snapshots;

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
struct ReadContext {
    checked_at: chrono::DateTime<chrono::Utc>,
    credential_expiry: chrono::DateTime<chrono::Utc>,
    endpoint: AppletManagedDeviceScopeGuard,
    registration: arkret_models_integration::AppletRegistrationPayload,
    role: ManagedActorRole,
    root: RealmAuthorityRootCurrent,
    grants: BTreeMap<GrantId, CapabilityGrant>,
    policies: Vec<Policy>,
    e2ee_consent: Option<crate::applet_e2ee::CurrentConsent>,
    cut: crate::realm_authorization_cut::RealmAuthorizationCut,
}
pub(crate) struct ReadProof {
    context: Arc<ReadContext>,
    resources: Vec<PolicyResourceSelector>,
    complete_resources: bool,
    operations: Vec<ReadOperation>,
}
impl ReadContext {
    fn root_current(&self, source: &IssuerAuthorityRef) -> bool {
        matches!(source,IssuerAuthorityRef::RealmRoot{realm_id,authority_event_ref,authority_generation}
            if realm_id==self.endpoint.effective_scope.realm_id() && authority_event_ref==&self.root.authority_event_ref
                && authority_generation==&self.root.authority_generation)
    }
}
impl ReadProof {
    pub(crate) fn permits_at(&self, at: chrono::DateTime<chrono::Utc>) -> bool {
        at >= self.context.checked_at
            && at >= self.context.endpoint.authority.not_before
            && at < self.context.endpoint.authority.expires_at
            && at < self.context.credential_expiry
            && self.context.e2ee_consent.as_ref().is_none_or(|consent| {
                consent
                    .permits_at(&self.context.grants, &self.context.root, at)
                    .unwrap_or(false)
            })
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
        if !self
            .context
            .endpoint
            .authority
            .scopes
            .permits(&self.context.endpoint.effective_scope, &[operation.action])
            || (!self.complete_resources
                && self
                    .context
                    .policies
                    .iter()
                    .flat_map(|p| &p.rules)
                    .any(|rule| {
                        rule.resources.as_ref().is_some_and(|resources| {
                            resources
                                .iter()
                                .any(|r| r.kind != PolicyResourceKind::Realm)
                        })
                    }))
        {
            return Ok(false);
        }
        let service = ActorId::service(self.context.registration.service_id.clone());
        let account = self.context.endpoint.authority.actor_id.clone();
        let action = operation.action.as_str();
        let actions = [action];
        let modes = if operation.action == CapabilityActionId::SelfBlobUploadCreateV1 {
            [
                AppletPolicyOperation::Authorize,
                AppletPolicyOperation::Execute,
            ]
        } else {
            [AppletPolicyOperation::Read, AppletPolicyOperation::Deliver]
        };
        for mode in modes {
            let decision = arkret_policy::applet_management::select_applet_management(
                Some(&self.context.policies),
                &arkret_policy::applet_management::AppletManagementContext {
                    device_control: None,
                    realm_id: self.context.endpoint.effective_scope.realm_id(),
                    requester_actor_id: &service,
                    applet_id: &self.context.registration.applet_id,
                    effective_scope: &self.context.endpoint.effective_scope,
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
        if let Some(surface) = arkret_wire::ServiceOperationId::from_wire(action) {
            // The original native Device scope authorizes the transport
            // surface. Realm content sources are independent operations in
            // the same proof, not invented grants for Station service scopes.
            return Ok(matches!(
                arkret_wire::applet_managed_device_scope_rule(surface),
                Some(arkret_wire::ManagedDeviceScopeRule::AllActions(required))
                    if required.contains(&operation.action)
            ));
        }
        let mut candidates = BTreeMap::new();
        for target in &operation.targets {
            for actor in [&account, &service] {
                let grants = arkret_policy::grant_authority::current_subject_grants(
                    actor,
                    action,
                    target,
                    &self.context.grants,
                    at,
                    |source| self.context.root_current(source),
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
                            &self.context.registration.applet_id,
                            &self.context.registration.registration_epoch,
                            self.context.role,
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
                &self.context.grants,
                at,
                |source| self.context.root_current(source),
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
                    &self.context.grants,
                    at,
                    |source| self.context.root_current(source),
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
    endpoint_windows: Vec<crate::mls_keypackage_claim_endpoints::EndpointWindow>,
}
#[async_trait::async_trait]
impl AccountContentDeliveryGuard for NativeDeliveryGuard {
    async fn commit_native_blob_upload(
        self: Box<Self>,
        reference: &arkret_wire::BlobRef,
        record: &coland_storage::BlobRecord,
        max_actor_bytes: u64,
        max_realm_bytes: u64,
    ) -> PersistenceResult<coland_storage::BlobRecord> {
        blobs::commit_upload(self, reference, record, max_actor_bytes, max_realm_bytes).await
    }
    fn permits_handoff(&self) -> bool {
        let at = chrono::Utc::now();
        self.proofs.iter().all(|proof| proof.permits_at(at))
            && self
                .endpoint_windows
                .iter()
                .all(|window| window.permits_at(at))
    }
    async fn prepare_handoff(&mut self) -> bool {
        if !self.permits_handoff() {
            return false;
        }
        matches!(
            tokio::time::timeout(std::time::Duration::from_secs(5), self.held.probe()).await,
            Ok(Ok(()))
        ) && self.permits_handoff()
    }
    async fn finish(self: Box<Self>) -> PersistenceResult<()> {
        self.held.finish().await
    }
}

pub(crate) async fn acquire(
    pool: &crate::PgPool,
    actor: &ActorId,
    station: &DidCoreId,
    endpoint: &AppletManagedDeviceScopeGuard,
    input: &AccountContentDeliveryInput,
) -> PersistenceResult<Option<Box<dyn AccountContentDeliveryGuard>>> {
    let lanes = [
        input.native_blob_upload.is_some(),
        !input.blobs.is_empty(),
        !input.committed_events.is_empty(),
        !input.stream_scans.is_empty(),
        !input.keypackage_claims.is_empty(),
        !input.mls_group_material_reads.is_empty(),
        !input.mls_roster_reads.is_empty(),
        !input.exact_reads.is_empty(),
        !input.snapshots.is_empty(),
    ]
    .into_iter()
    .filter(|active| *active)
    .count();
    if &endpoint.authority.actor_id != actor
        || actor
            .as_realm_actor_id()
            .is_none_or(|subject| subject.realm_id != endpoint.authority.realm_id)
        || &endpoint.authority.governance_service_id != station
        || !matches!(
            endpoint.effective_scope,
            ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
        )
        || input.stream_scans.len() > 1
        || input.keypackage_claims.len() > 1
        || input.mls_group_material_reads.len() > 1
        || input.mls_roster_reads.len() > 1
        || input.exact_reads.len() > 1
        || input.snapshots.len() > 1
        || input.committed_events.len() > 64
        || lanes != 1
        || !input.current_views.is_empty()
        || !input.projection_lists.is_empty()
        || !input.morph_lists.is_empty()
        || !input.morph_documents.is_empty()
        || !input.morph_absences.is_empty()
        || !input.account_status_observations.is_empty()
        || !input.realm_lifecycle_reads.is_empty()
        || !input.realm_link_reads.is_empty()
        || !input.realm_exports.is_empty()
        || !input.future_materials.is_empty()
        || !input.notifications.is_empty()
        || !input.watch_reads.is_empty()
        || input.remote_watch_read.is_some()
        || input.realm_actor_material.is_some()
        || input.audited_watch_read.is_some()
        || input.watch_delivery_device.is_some()
        || input.watch_local_session.is_some()
        || input.blobs.len() > 1
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
        endpoint.authority.realm_id.clone(),
        endpoint.effective_scope.realm_id().clone(),
    ];
    let counterparts = if let Some(claim) = input.keypackage_claims.as_slice().first() {
        crate::boxed_future(|| {
            crate::mls_keypackage_claim_endpoints::prepare(
                held.connection(),
                &claim.outcome,
                claim.command.as_ref(),
                station,
                &claim.remote_devices,
            )
        })
        .await?
    } else {
        Vec::new()
    };
    realms.extend(counterparts.iter().map(|endpoint| endpoint.realm().clone()));
    if let Some(claim) = input.keypackage_claims.as_slice().first() {
        let endpoints = &claim.endpoints;
        if !endpoints.contains(endpoint) {
            return Err(refused("claim delivery omits its actual endpoint"));
        }
        for endpoint in endpoints {
            if endpoint.authority.governance_service_id != *station {
                return Err(refused("native claim lacks local current authority"));
            }
            realms.push(endpoint.authority.realm_id.clone());
            realms.push(endpoint.effective_scope.realm_id().clone());
        }
    }
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
    let current = crate::realm_actor_device_authority::current_in_connection(
        held.connection(),
        actor,
        &endpoint.authority.device_id,
        at,
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?
    .ok_or_else(|| refused("native read Device is unavailable"))?;
    if current != endpoint.authority {
        return Err(refused("native read Device instance changed"));
    }
    if input.native_blob_upload.is_some() || !input.blobs.is_empty() {
        let proof = blobs::prepare(
            held.connection(),
            station,
            endpoint,
            &current,
            at,
            credential_expiry,
            input,
        )
        .await?;
        if !proof.permits_at(chrono::Utc::now()) {
            return Err(refused("native Blob current permission expired"));
        }
        return Ok(Some(Box::new(NativeDeliveryGuard {
            held,
            proofs: vec![proof],
            endpoint_windows: Vec::new(),
        })));
    }
    if let Some(snapshot) = input.snapshots.as_slice().first() {
        let proofs = crate::boxed_future(|| {
            snapshots::prepare(
                held.connection(),
                station,
                endpoint,
                credential_expiry,
                snapshot,
            )
        })
        .await?;
        return Ok(Some(Box::new(NativeDeliveryGuard {
            held,
            proofs,
            endpoint_windows: Vec::new(),
        })));
    }
    let material_proof = if let Some(request) = input.mls_group_material_reads.as_slice().first() {
        Some(
            crate::boxed_future(|| {
                mls_material::group_state(
                    held.connection(),
                    station,
                    endpoint,
                    credential_expiry,
                    request,
                )
            })
            .await?,
        )
    } else if let Some(request) = input.mls_roster_reads.as_slice().first() {
        Some(
            crate::boxed_future(|| {
                mls_material::roster(
                    held.connection(),
                    station,
                    endpoint,
                    credential_expiry,
                    request,
                )
            })
            .await?,
        )
    } else if let Some((request, outcome)) = input.exact_reads.as_slice().first() {
        Some(
            crate::boxed_future(|| {
                exact_current::prepare(
                    held.connection(),
                    station,
                    endpoint,
                    credential_expiry,
                    request,
                    outcome,
                )
            })
            .await?,
        )
    } else {
        None
    };
    if let Some(proof) = material_proof {
        if !proof.permits_at(chrono::Utc::now()) {
            return Err(refused("native MLS material permission expired"));
        }
        return Ok(Some(Box::new(NativeDeliveryGuard {
            held,
            proofs: vec![proof],
            endpoint_windows: Vec::new(),
        })));
    }
    if let Some(claim) = input.keypackage_claims.as_slice().first() {
        let outcome = &claim.outcome;
        let endpoints = &claim.endpoints;
        for endpoint in &counterparts {
            crate::boxed_future(|| endpoint.require_current(held.connection())).await?;
        }

        let material_deadline = crate::mls_keypackage_claim_admission::require_stored_outcome(
            held.connection(),
            claim.operation,
            outcome,
            endpoints,
            &claim.remote_devices,
        )
        .await?;
        let mut proofs = Vec::new();
        for endpoint in endpoints {
            if endpoint.effective_scope.realm_id()
                != &outcome.claim_receipt.request.intended_realm_id
                || endpoint
                    .effective_scope
                    .canonical_mls_group_id()
                    .map_err(PersistenceError::database)?
                    != outcome.claim_receipt.request.mls_group_id
            {
                return Err(refused(
                    "claim delivery differs from its exact signed scope",
                ));
            }
            proofs.push(
                crate::boxed_future(|| {
                    mls_scope_read_proof(
                        held.connection(),
                        endpoint,
                        credential_expiry.min(material_deadline),
                        outcome.claim_receipt.request.strand_id.as_ref(),
                    )
                })
                .await?,
            );
        }
        if proofs.is_empty() || !proofs.iter().all(|p| p.permits_at(chrono::Utc::now())) {
            return Err(refused("claim delivery expired"));
        }
        return Ok(Some(Box::new(NativeDeliveryGuard {
            held,
            proofs,
            endpoint_windows: counterparts
                .iter()
                .map(|endpoint| endpoint.window())
                .collect(),
        })));
    }
    let mut events = input.committed_events.as_slice();
    if let Some((request, page)) = input.stream_scans.as_slice().first() {
        page.validate_for_request(request)
            .map_err(PersistenceError::database)?;
        if request.stream_ref.scope_ref() != endpoint.effective_scope {
            return Err(refused("native scan differs from its authenticated scope"));
        }
        let fresh = crate::boxed_future(|| {
            crate::account_stream_scan::scan_stream_for_actor_in_connection(
                held.connection(),
                request,
                actor,
                station,
            )
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
        let coland_storage::AccountStreamScan::Page(fresh) = fresh else {
            return Err(refused("native stream history is not currently proved"));
        };
        let fresh = fresh
            .into_effective_scope(&endpoint.effective_scope)
            .map_err(PersistenceError::database)?
            .ok_or_else(|| refused("native page contains another data scope"))?;
        if &fresh != page {
            return Err(refused(
                "native stream page or floor changed before handoff",
            ));
        }
        events = &page.committed_events;
    }
    let context = Arc::new(
        crate::boxed_future(|| {
            read_context(held.connection(), endpoint, &current, at, credential_expiry)
        })
        .await?,
    );
    let mut proofs = Vec::with_capacity(events.len() + 1);
    if !input.stream_scans.is_empty() {
        let proof = stream_proof(Arc::clone(&context));
        if tracing::enabled!(tracing::Level::DEBUG) && !proof.permits_at(at) {
            tracing::debug!(
                stage = "stream_permission",
                "native content preparation refused"
            );
        }
        proofs.push(proof);
    }
    for original in events {
        let kind = original
            .reducer_input()
            .map(|event| event.kind.as_str())
            .unwrap_or("withheld");
        let proof=crate::boxed_future(|| event_proof(
            held.connection(), station, Arc::clone(&context), original,
        )).await.map_err(|error| {
            tracing::debug!(stage="event_material",event_kind=kind,error=%error,"native content preparation refused");
            error
        })?;
        if tracing::enabled!(tracing::Level::DEBUG) && !proof.permits_at(at) {
            tracing::debug!(
                stage = "event_permission",
                event_kind = kind,
                "native content preparation refused"
            );
        }
        proofs.push(proof);
    }
    if proofs.is_empty() || !proofs.iter().all(|p| p.permits_at(at)) {
        return Err(refused(
            "native read has no current unreserved Applet content source",
        ));
    }
    Ok(Some(Box::new(NativeDeliveryGuard {
        held,
        proofs,
        endpoint_windows: counterparts
            .iter()
            .map(|endpoint| endpoint.window())
            .collect(),
    })))
}

async fn read_context(
    conn: &mut diesel_async::AsyncPgConnection,
    endpoint: &AppletManagedDeviceScopeGuard,
    current: &coland_storage::AppletManagedDeviceAuthority,
    at: chrono::DateTime<chrono::Utc>,
    credential_expiry: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<ReadContext> {
    operation_context(
        conn,
        endpoint,
        current,
        at,
        credential_expiry,
        &[CapabilityActionId::EventRead],
    )
    .await
}

async fn operation_context(
    conn: &mut diesel_async::AsyncPgConnection,
    endpoint: &AppletManagedDeviceScopeGuard,
    current: &coland_storage::AppletManagedDeviceAuthority,
    at: chrono::DateTime<chrono::Utc>,
    credential_expiry: chrono::DateTime<chrono::Utc>,
    actions: &[CapabilityActionId],
) -> PersistenceResult<ReadContext> {
    let actor = endpoint.authority.actor_id.clone();
    let scope = &endpoint.effective_scope;
    let encrypted=sql_query("SELECT to_jsonb(EXISTS(SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.state='committed' AND e.kind='ak.mls.genesis' AND c.realm_id=$1 AND e.envelope->'scope_ref'=$2)) AS value")
        .bind::<Text,_>(scope.realm_id().as_str()).bind::<Jsonb,_>(serde_json::json!(scope)).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let encrypted = encrypted.value.as_bool().ok_or_else(|| {
        PersistenceError::SchemaViolation("native encryption source is not a boolean".into())
    })?;
    let (registration, installation) = crate::boxed_future(|| {
        crate::applet_device_admission::installation_for_device(
            conn,
            current,
            scope,
            &endpoint.service_did_document,
            actions,
            at,
            false,
        )
    })
    .await?;
    let e2ee_consent = if encrypted {
        Some(
            crate::boxed_future(|| {
                crate::applet_e2ee::current_consent(conn, &registration, &installation, scope, at)
            })
            .await?,
        )
    } else {
        None
    };
    let creation = crate::realm_actor_control::creation_source(conn, &actor).await?;
    if creation.applet_id != registration.applet_id {
        return Err(refused("native read creation belongs to another Applet"));
    }
    let role = match creation.actor_role {
        arkret_models_integration::RealmActorCreatePayloadActorRole::Bot => ManagedActorRole::Bot,
        arkret_models_integration::RealmActorCreatePayloadActorRole::Ghost => {
            ManagedActorRole::Ghost
        }
    };
    let root=sql_query("SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1 FOR SHARE")
        .bind::<Text,_>(scope.realm_id().as_str()).get_result::<RealmAuthorityRootReadRow>(conn).await.map_err(PersistenceError::database)?;
    let rows=sql_query("SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value FROM capability_grant_current_results WHERE realm_id=$1 ORDER BY grant_id FOR SHARE")
        .bind::<Text,_>(scope.realm_id().as_str()).get_results::<CapabilityGrantCurrentResultReadRow>(conn).await.map_err(PersistenceError::database)?;
    let mut grants = BTreeMap::new();
    for row in rows {
        let row = decode_row(row)?;
        grants.insert(row.grant_id, row.value);
    }
    let cut = crate::boxed_future(|| {
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, scope.realm_id(), &actor)
    })
    .await?;
    cut.require_open_content_read()?;
    let policies =
        crate::policy_current_results::read_scoped_applet_management_policies_for_delivery(
            conn,
            scope.realm_id(),
            scope.circle_id(),
        )
        .await?;
    Ok(ReadContext {
        checked_at: at,
        credential_expiry,
        endpoint: endpoint.clone(),
        registration,
        role,
        root: decode_authority_root(root)?,
        grants,
        policies,
        e2ee_consent,
        cut,
    })
}

fn scope_resources(scope: &ScopeRef) -> Vec<PolicyResourceSelector> {
    let mut resources = vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(scope.realm_id().clone()),
        resource_ref: Some(scope.realm_id().to_string()),
    }];
    if let ScopeRef::Circle {
        realm_id,
        circle_id,
    } = scope
    {
        resources.push(PolicyResourceSelector {
            kind: PolicyResourceKind::Object,
            realm_id: Some(realm_id.clone()),
            resource_ref: Some(circle_id.to_string()),
        });
    }
    resources
}
fn scope_operation(context: &ReadContext) -> ReadOperation {
    let scope = &context.endpoint.effective_scope;
    let target = match scope {
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => WireResourceSelector::circle(realm_id.clone(), circle_id.clone()),
        _ => WireResourceSelector::realm(scope.realm_id().clone()),
    };
    ReadOperation {
        action: CapabilityActionId::EventRead,
        targets: vec![target],
        facts: OperationFacts {
            circle_id: scope.circle_id().map(ToString::to_string),
            applet_id: Some(context.registration.applet_id.to_string()),
            registration_epoch: Some(context.registration.registration_epoch.to_string()),
            ..OperationFacts::default()
        },
    }
}
fn stream_proof(context: Arc<ReadContext>) -> ReadProof {
    ReadProof {
        resources: scope_resources(&context.endpoint.effective_scope),
        operations: vec![scope_operation(&context)],
        complete_resources: true,
        context,
    }
}

async fn event_proof(
    conn: &mut diesel_async::AsyncPgConnection,
    station: &DidCoreId,
    context: Arc<ReadContext>,
    original: &CommittedEventView,
) -> PersistenceResult<ReadProof> {
    original
        .validate_shape()
        .map_err(PersistenceError::database)?;
    let scope = &context.endpoint.effective_scope;
    if original
        .disclosure_scope()
        .map_err(PersistenceError::database)?
        != *scope
    {
        return Err(refused("native Event differs from its authenticated scope"));
    }
    let actor = context.endpoint.authority.actor_id.clone();
    let reread = crate::boxed_future(|| {
        crate::account_stream_scan::committed_event_for_member_in_connection(
            conn,
            &original.commit().event_ref,
            &actor,
            station,
        )
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)?;
    let coland_storage::MemberCommittedEventRead::Read(reread) = reread else {
        return Err(refused("native Event history is not currently visible"));
    };
    let reread = (*reread)
        .into_effective_scope(scope)
        .map_err(PersistenceError::database)?
        .ok_or_else(|| refused("native Event has another data scope"))?;
    if &reread != original {
        return Err(refused("native Event disclosure changed before handoff"));
    }
    let full = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &original.commit().event_ref,
    )
    .await?;
    let Some(full) = full else {
        if matches!(original, CommittedEventView::Full(_)) {
            return Err(refused("native Full Event source is unavailable"));
        }
        // The held member reader proves this opaque chain node, not any
        // missing payload or narrower resource facts.
        let mut operation = scope_operation(&context);
        let mut target = WireResourceSelector::realm(scope.realm_id().clone());
        target.kind = arkret_wire::ResourceSelectorKind::Event;
        target.event_id = Some(original.commit().event_ref.clone());
        operation.targets.push(target);
        return Ok(ReadProof {
            resources: scope_resources(scope),
            operations: vec![operation],
            complete_resources: false,
            context,
        });
    };
    full.validate_shape().map_err(PersistenceError::database)?;
    if &full.commit != original.commit() {
        return Err(refused("native full source differs from its exact Commit"));
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
    source_read_proof(context, &full.event, &actions, &[])
}

fn source_read_proof(
    context: Arc<ReadContext>,
    source: &arkret_wire::Event,
    actions: &[CapabilityActionId],
    extra_resources: &[PolicyResourceSelector],
) -> PersistenceResult<ReadProof> {
    let scope = &context.endpoint.effective_scope;
    let mut resources = crate::agent_management_admission::event_content_resources(source)?;
    for resource in scope_resources(scope).iter().chain(extra_resources) {
        if !resources.contains(resource) {
            resources.push(resource.clone());
        }
    }
    let mut operations = Vec::new();
    for &action in actions {
        let (target, mut facts) = context.cut.content_scope_facts(source, action)?;
        facts.circle_id = scope.circle_id().map(ToString::to_string);
        facts.applet_id = Some(context.registration.applet_id.to_string());
        facts.registration_epoch = Some(context.registration.registration_epoch.to_string());
        let mut targets = crate::agent_management_admission::content_capability_targets(
            scope.realm_id(),
            &resources,
        );
        if !targets.contains(&target) {
            targets.push(target);
        }
        if let ScopeRef::Circle {
            realm_id,
            circle_id,
        } = scope
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
    Ok(ReadProof {
        context,
        resources,
        operations,
        complete_resources: true,
    })
}

/// Admission-time scope reading for existing MLS material. The caller holds
/// the real PCR/business cuts in its own transaction, not a parallel lease.
pub(crate) async fn mls_scope_read_proof(
    conn: &mut diesel_async::AsyncPgConnection,
    endpoint: &AppletManagedDeviceScopeGuard,
    expires_at: chrono::DateTime<chrono::Utc>,
    strand: Option<&arkret_wire::StrandId>,
) -> PersistenceResult<ReadProof> {
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    if at >= expires_at {
        return Err(refused("native MLS read request expired"));
    }
    let current = crate::realm_actor_device_authority::current_in_connection(
        conn,
        &endpoint.authority.actor_id,
        &endpoint.authority.device_id,
        at,
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?
    .ok_or_else(|| refused("native MLS reader is unavailable"))?;
    if current != endpoint.authority {
        return Err(refused("native MLS reader authorization changed"));
    }
    let context = Arc::new(
        crate::boxed_future(|| read_context(conn, endpoint, &current, at, expires_at)).await?,
    );
    if !context.cut.actor_is_joined() {
        return Err(refused("native MLS reader is not a Realm member"));
    }
    if let ScopeRef::Circle {
        realm_id,
        circle_id,
    } = &endpoint.effective_scope
    {
        let basis =
            crate::circle_current_results::locked_circle_basis(conn, realm_id, circle_id).await?;
        if basis["value"]["state"] != "active"
            || !crate::circle_current_results::effective_member_in_connection(
                conn,
                realm_id,
                circle_id,
                &endpoint.authority.actor_id.clone(),
            )
            .await?
        {
            return Err(refused("native MLS reader has no active Circle membership"));
        }
    }
    let mut proof = stream_proof(context);
    if let Some(strand) = strand {
        let actual = crate::strand_current_results::locked_active_strand_scope(
            conn,
            endpoint.effective_scope.realm_id(),
            strand,
        )
        .await?;
        if actual != endpoint.effective_scope {
            return Err(refused("native MLS Strand has another actual scope"));
        }
        proof.resources.push(PolicyResourceSelector {
            kind: PolicyResourceKind::Strand,
            realm_id: Some(actual.realm_id().clone()),
            resource_ref: Some(strand.to_string()),
        });
        let mut target = WireResourceSelector::realm(actual.realm_id().clone());
        target.kind = arkret_wire::ResourceSelectorKind::Strand;
        target.strand_id = Some(strand.clone());
        proof.operations[0].targets.push(target);
    }
    if !proof.permits_at(chrono::Utc::now()) {
        return Err(refused("native MLS read has no current complete source"));
    }
    Ok(proof)
}

pub(crate) async fn require_mls_scope_read(
    conn: &mut diesel_async::AsyncPgConnection,
    endpoint: &AppletManagedDeviceScopeGuard,
    expires_at: chrono::DateTime<chrono::Utc>,
    strand: Option<&arkret_wire::StrandId>,
) -> PersistenceResult<()> {
    crate::boxed_future(|| mls_scope_read_proof(conn, endpoint, expires_at, strand))
        .await
        .map(|_| ())
}

/// Prove one native scope before snapshot signing in the caller's transaction.
pub(crate) async fn snapshot_material_for_device(
    conn: &mut diesel_async::AsyncPgConnection,
    station: &DidCoreId,
    endpoint: &AppletManagedDeviceScopeGuard,
    expiry: chrono::DateTime<chrono::Utc>,
    material: coland_storage::RealmStateSnapshotMaterial,
) -> PersistenceResult<(coland_storage::RealmStateSnapshotMaterial, Vec<ReadProof>)> {
    snapshots::restrict_material(conn, station, endpoint, expiry, material).await
}

/// Preserve the native reader's PCR/business authority barriers before the
/// snapshot issuer establishes and signs its local governing cut.
pub(crate) async fn lock_snapshot_device_authorities(
    conn: &mut diesel_async::AsyncPgConnection,
    station: &DidCoreId,
    endpoint: &AppletManagedDeviceScopeGuard,
) -> PersistenceResult<()> {
    if &endpoint.authority.governance_service_id != station {
        return Err(refused("native snapshot is not at its Account Station"));
    }
    let mut realms = vec![
        endpoint.authority.realm_id.clone(),
        endpoint.effective_scope.realm_id().clone(),
    ];
    realms.sort();
    realms.dedup();
    for realm in realms {
        let locked = sql_query(
            "SELECT to_jsonb(a) AS value FROM realm_authorities a \
             WHERE realm_id=$1 FOR SHARE NOWAIT",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result::<JsonRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if locked.value["service_id"].as_str() != Some(station.as_str()) {
            return Err(refused(
                "native snapshot has no current local governing barrier",
            ));
        }
    }
    Ok(())
}
