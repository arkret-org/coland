//! Creation-specific facts consumed by the shared private management ledger.
use arkret_models_integration::{
    AppletManagedActorCommittedRequest, AppletManagedActorProvisionPayload,
};
use coland_storage::{AppletAdmissionRequest, AppletAuthoringCandidate, ManagementReviewCurrent};

use super::*;

pub(super) fn native_event(request: &ManagementReviewRequestBody) -> bool {
    matches!(&request.target, ManagementReviewTarget::Event {event} if event.applet_id.is_some())
}

pub(super) fn event_target(request: &ManagementReviewRequestBody) -> PersistenceResult<&Event> {
    request.validate().map_err(invalid)?;
    let ManagementReviewTarget::Event { event } = &request.target else {
        return Err(hidden());
    };
    if !native_event(request)
        || request.management_operation != ManagementOperation::Join
        || event.scope_ref != request.effective_scope
        || !matches!(request.requester_actor_id, ActorId::Service { .. })
    {
        return Err(hidden());
    }
    crate::applet_device_admission::action(event)?;
    Ok(event)
}

pub(super) async fn event_pins(
    conn: &mut AsyncPgConnection,
    request: &ManagementReviewRequestBody,
    at: DateTime<Utc>,
    current: &ManagementReviewCurrent,
) -> PersistenceResult<(Value, Vec<ManagementReviewRequirement>)> {
    let event = event_target(request)?;
    let material = current.applet_event.as_ref().ok_or_else(|| {
        refused(
            "revision_unavailable",
            "native management resolver material is unavailable",
        )
    })?;
    let authority = crate::pcr_applet_device_authority::for_event_in_connection(conn, event, at)
        .await
        .map_err(crate::PgTransactionError::into_persistence)?
        .ok_or_else(hidden)?;
    if material.pcr_realm_id != authority.pcr_realm_id
        || current.station_id != authority.account_id.station_id
        || request.requester_actor_id != ActorId::service(authority.source_service_id.clone())
    {
        return Err(refused(
            "capability_denied",
            "native management source or Service requester differs",
        ));
    }
    let guard = coland_storage::AppletManagedDeviceEventGuard {
        authority: authority.clone(),
        effective_scope: event.scope_ref.clone(),
        service_did_document: material.service_did_document.clone(),
    };
    crate::applet_device_admission::require_installation_binding(conn, event, &guard, at).await?;
    let (registration, installation) =
        crate::applet_device_admission::installation(conn, event, &guard, at).await?;
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &event.realm_id,
        &event.actor_id,
    )
    .await?;
    cut.require_open_lifecycle(event)?;
    let source =
        crate::agent_producer_signer_keys::prepare_local_account_device_source_in_connection(
            conn, event, at,
        )
        .await?
        .ok_or_else(hidden)?;
    let (policies, decision) =
        crate::applet_device_admission::select_management(conn, event, &registration, at).await?;
    let ids = policies
        .iter()
        .map(|p| p.id.to_string())
        .collect::<Vec<_>>();
    let revisions=sql_query("SELECT to_jsonb(p) AS value FROM policy_current_results p WHERE policy_id=ANY($1) ORDER BY policy_id FOR SHARE")
        .bind::<diesel::sql_types::Array<Text>,_>(ids).load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let membership=sql_query("SELECT to_jsonb(m) AS value FROM member_state_current_results m WHERE realm_id=$1 AND member_id=$2 FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.actor_id.to_string()).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let mut pending = std::collections::BTreeSet::from([event
        .authorization_ref
        .as_ref()
        .ok_or_else(hidden)?
        .to_string()]);
    let mut grants = std::collections::BTreeMap::new();
    while let Some(id) = pending.pop_first() {
        if grants.contains_key(&id) {
            continue;
        }
        let row=sql_query("SELECT to_jsonb(g) AS value FROM capability_grant_current_results g WHERE realm_id=$1 AND grant_id=$2 FOR SHARE")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&id).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(hidden)?;
        let value: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant =
            serde_json::from_value(row.value["value"].clone()).map_err(invalid)?;
        for source in value.issuer_authority_refs {
            if let arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant {grant_id}=source {pending.insert(grant_id.to_string());}
        }
        grants.insert(id, row.value);
    }
    let root=sql_query("SELECT to_jsonb(r) AS value FROM realm_authority_root_current_results r WHERE realm_id=$1 FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let identity =
        crate::pcr_applet_device::current_resolution_in_connection(conn, &authority.account_id)
            .await
            .map_err(crate::PgTransactionError::into_persistence)?;
    let profile=sql_query("SELECT to_jsonb(p) AS value FROM actor_profile_current_results p WHERE realm_id=$1 FOR SHARE")
        .bind::<Text,_>(authority.pcr_realm_id.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok((
        json!({"producer":source,"original_proof":event.producer_proof,"scope":event.scope_ref,
        "device_scopes":authority.scopes,"device_expires_at":authority.expires_at,"device_generation":authority.current_device_generation_ref,
        "registration":registration,"installation_status":installation["status"],"package":installation["package"],"registration_event":installation["registration_event"],
        "resolution":identity.projection,"resolution_source":identity.current_event,"profile":profile.value,"membership":membership.map(|r|r.value),
        "grant_revisions":grants,"authority_root":root.value,"policies":policies,"policy_revisions":revisions.into_iter().map(|r|r.value).collect::<Vec<_>>() }),
        decision.review_requirements,
    ))
}

pub(super) fn creation(request: &ManagementReviewRequestBody) -> bool {
    !matches!(request.target, ManagementReviewTarget::Event { .. })
}

pub(super) fn beneficiary(request: &ManagementReviewRequestBody) -> PersistenceResult<ActorId> {
    let event = match &request.target {
        ManagementReviewTarget::BotCreation { request_body, .. } => {
            &request_body
                .managed_actor_bundle
                .managed_actor_provision_event
        }
        ManagementReviewTarget::GhostCreation { request_body, .. } => {
            if let Some(existing) = &request_body.existing_managed_actor {
                return Ok(existing.ghost_actor_id.clone());
            }
            &request_body
                .managed_actor_bundle
                .as_ref()
                .ok_or_else(hidden)?
                .managed_actor_provision_event
        }
        _ => return Err(hidden()),
    };
    let provision: AppletManagedActorProvisionPayload =
        serde_json::from_value(json!(&event.payload)).map_err(invalid)?;
    provision.validate().map_err(invalid)?;
    Ok(provision.actor_id)
}

pub(crate) fn target(
    input: &AppletAuthoringCandidate,
) -> PersistenceResult<ManagementReviewTarget> {
    match &input.request {
        AppletAdmissionRequest::Managed(AppletManagedActorCommittedRequest::Bot(body)) => {
            Ok(ManagementReviewTarget::BotCreation {
                applet_id: input.package.applet_id.clone(),
                request_body: body.clone(),
            })
        }
        AppletAdmissionRequest::Managed(AppletManagedActorCommittedRequest::Ghost(body)) => {
            Ok(ManagementReviewTarget::GhostCreation {
                applet_id: input.package.applet_id.clone(),
                request_body: body.clone(),
            })
        }
        _ => Err(hidden()),
    }
}

pub(super) fn deadline(request: &ManagementReviewRequestBody) -> Option<DateTime<Utc>> {
    match &request.target {
        ManagementReviewTarget::BotCreation { request_body, .. } => {
            Some(request_body.authoring_request.expires_at)
        }
        ManagementReviewTarget::GhostCreation { request_body, .. } => {
            Some(request_body.authoring_request.expires_at)
        }
        _ => None,
    }
}

pub(super) async fn lock(
    conn: &mut AsyncPgConnection,
    request: &ManagementReviewRequestBody,
    station: &arkret_wire::DidCoreId,
) -> PersistenceResult<()> {
    let applet = match &request.target {
        ManagementReviewTarget::BotCreation { applet_id, .. }
        | ManagementReviewTarget::GhostCreation { applet_id, .. } => applet_id,
        _ => return Ok(()),
    };
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!("applet:{applet}:{station}"))
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

pub(super) async fn pins(
    conn: &mut AsyncPgConnection,
    request: &ManagementReviewRequestBody,
    at: DateTime<Utc>,
    current: &ManagementReviewCurrent,
) -> PersistenceResult<(Value, Vec<ManagementReviewRequirement>)> {
    request.validate().map_err(invalid)?;
    let mut input = Box::new(
        current
            .applet_candidate
            .as_deref()
            .ok_or_else(|| {
                refused(
                    "revision_unavailable",
                    "creation candidate verification material is unavailable",
                )
            })?
            .clone(),
    );
    if target(&input)?.canonical_target_digest().map_err(invalid)?
        != request.target.canonical_target_digest().map_err(invalid)?
        || input.admin_actor_id != request.requester_actor_id
        || input.admin_actor_id != ActorId::service(input.package.service_id.clone())
        || !input.admin_producer_guards.is_empty()
        || input.recomputed_install_plan.is_some()
    {
        return Err(refused(
            "signature_invalid",
            "creation preparation differs from original intent",
        ));
    }
    input.accepted_at = arkret_canonical::normalize_timestamp_canonical(at);
    let mut validated = crate::applet_admission::validate_candidate(&input).await?;
    if validated.portal_realm != *request.effective_scope.realm_id() {
        return Err(refused("capability_denied", "creation Realm differs"));
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &validated.portal_realm)
        .await?;
    crate::applet_admission::validate_managed_current(conn, &input, &mut validated).await?;
    let grant = crate::applet_action_approval::CreationAuthority::read(conn, &input, &validated)
        .await?
        .pin_grant()?;
    let provision = validated.provision.as_ref().ok_or_else(hidden)?;
    if provision.actor_id != beneficiary(request)? {
        return Err(hidden());
    }
    let installation =
        current_installation(conn, &input, &request.effective_scope, &current.station_id).await?;
    let (policies, decision) = select_current_creation(
        conn,
        &input,
        &request.effective_scope,
        request.management_operation,
        if input.prior_managed_refs.is_empty() {
            None
        } else {
            Some(&provision.actor_id)
        },
        at,
    )
    .await?;
    let ids = policies
        .iter()
        .map(|p| p.id.to_string())
        .collect::<Vec<_>>();
    let revisions=sql_query("SELECT to_jsonb(p) AS value FROM policy_current_results p WHERE policy_id=ANY($1) ORDER BY policy_id FOR SHARE")
        .bind::<diesel::sql_types::Array<Text>,_>(&ids).load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut pending =
        std::collections::BTreeSet::from([grant["id"].as_str().ok_or_else(hidden)?.to_owned()]);
    let mut grant_revisions = std::collections::BTreeMap::new();
    while let Some(id) = pending.pop_first() {
        if grant_revisions.contains_key(&id) {
            continue;
        }
        let row=sql_query("SELECT to_jsonb(g) AS value FROM capability_grant_current_results g WHERE realm_id=$1 AND grant_id=$2 FOR SHARE")
            .bind::<Text,_>(validated.portal_realm.as_str()).bind::<Text,_>(&id).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let value: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant =
            serde_json::from_value(row.value["value"].clone()).map_err(invalid)?;
        for source in value.issuer_authority_refs {
            if let arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant {grant_id}=source {pending.insert(grant_id.to_string());}
        }
        grant_revisions.insert(id, row.value);
    }
    let authority_root=sql_query("SELECT to_jsonb(r) AS value FROM realm_authority_root_current_results r WHERE realm_id=$1 FOR SHARE")
        .bind::<Text,_>(validated.portal_realm.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let native_identity = if !input.prior_managed_refs.is_empty() {
        let account = provision.actor_id.as_account_id().ok_or_else(hidden)?;
        let resolution = crate::pcr_applet_device::current_resolution_in_connection(conn, account)
            .await
            .map_err(crate::PgTransactionError::into_persistence)?;
        let profile=sql_query("SELECT to_jsonb(p) AS value FROM actor_profile_current_results p WHERE realm_id=$1 AND value->>'principal_id'=$2 FOR SHARE")
            .bind::<Text,_>(resolution.pcr_realm_id.as_str()).bind::<Text,_>(account.principal_id.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        json!({"resolution":resolution.projection,"current_event":resolution.current_event,"profile":profile.value})
    } else {
        Value::Null
    };
    // Bind only security facts, not unrelated bots, mappings or quota usage.
    Ok((
        json!({"provision":provision,"original_target_digest":request.target.canonical_target_digest().map_err(invalid)?,
        "package":input.package,"registration":installation.value["registration_event"],"status":installation.value["status"],
        "grant_revisions":grant_revisions,"authority_root":authority_root.value,"policies":policies,"policy_revisions":revisions.into_iter().map(|r|r.value).collect::<Vec<_>>(),
        "prior_managed_refs":input.prior_managed_refs,"native_identity":native_identity}),
        decision.review_requirements,
    ))
}

pub(super) fn operation(request: &ManagementReviewRequestBody) -> arkret_wire::ServiceOperationId {
    if request.management_operation == ManagementOperation::CreateBot {
        arkret_wire::ServiceOperationId::SelfAppletBotCommandProvisionV1
    } else {
        arkret_wire::ServiceOperationId::SelfAppletGhostCommandProvisionV1
    }
}

pub(crate) async fn lock_approval_accounts(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringCandidate,
    prepared: Option<&coland_storage::OperationApprovalCommit>,
) -> PersistenceResult<()> {
    let (scope, station, _) = creation_binding(input)?;
    let mut current = prepared
        .map(|prepared| prepared.current.clone())
        .unwrap_or_else(|| ManagementReviewCurrent {
            station_id: station.clone(),
            observations: Vec::new(),
            applet_candidate: None,
            applet_event: None,
        });
    if current.station_id != *station {
        return Err(refused(
            "revision_unavailable",
            "creation observations name another receiving Station",
        ));
    }
    current.applet_candidate = Some(Box::new(input.clone()));
    let mut accounts = current
        .observations
        .iter()
        .map(|observation| observation.record().account_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(prepared) = prepared {
        let (expected_operation, digest) = crate::applet_action_approval::operation_binding(input)?;
        if prepared.operation != expected_operation || prepared.target_digest != digest {
            return Err(refused(
                "signature_invalid",
                "operation approval preparation differs from the actual target",
            ));
        }
        if let Some(id) = approval_request_id(&prepared.methods)? {
            let row = read(conn, &id, false).await?.ok_or_else(hidden)?;
            let request = row.request();
            if request.target.canonical_target_digest().map_err(invalid)? != digest
                || operation(&request) != expected_operation
                || request.requester_actor_id != input.admin_actor_id
                || request.effective_scope != *scope
            {
                return Err(refused(
                    "signature_invalid",
                    "creation management intent differs from actual target",
                ));
            }
            accounts.extend(material_accounts(&row, &request.requester_actor_id, &[])?);
        }
    }
    lock_current_account_realms(
        conn,
        scope.realm_id(),
        &accounts.into_iter().collect::<Vec<_>>(),
        Some(&current),
        &[],
    )
    .await?;
    Ok(())
}

fn approval_request_id(methods: &[ApprovalHistoricalMethod]) -> PersistenceResult<Option<String>> {
    let mut ids = std::collections::BTreeSet::new();
    for method in methods {
        if let arkret_wire::ApprovalContext::Management { request_id, .. } =
            &method.signature.input.approval_context
        {
            ids.insert(request_id.clone());
        }
    }
    if ids.len() > 1 {
        return Err(refused(
            "signature_invalid",
            "creation combines different management requests",
        ));
    }
    Ok(ids.pop_first())
}

/// Management admission is independent of grant and Realm-governance approval.
/// All supplied outer evidence must still match the receiver's preparation.
pub(crate) async fn prepare_admission(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringCandidate,
    validated: &crate::applet_admission::ValidatedAppletUnit,
    prepared: Option<&coland_storage::OperationApprovalCommit>,
    at: DateTime<Utc>,
) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
    let supplied = match &input.request {
        AppletAdmissionRequest::Managed(AppletManagedActorCommittedRequest::Bot(body)) => {
            &body.approval_signatures
        }
        AppletAdmissionRequest::Managed(AppletManagedActorCommittedRequest::Ghost(body)) => {
            &body.approval_signatures
        }
        _ => return Err(hidden()),
    };
    if !match prepared {
        Some(prepared) => prepared
            .methods
            .iter()
            .map(|method| &method.signature)
            .eq(supplied.iter()),
        None => supplied.is_empty(),
    } {
        return Err(refused(
            "signature_invalid",
            "prepared creation votes differ from actual outer evidence",
        ));
    }
    let (scope, station, management_operation) = creation_binding(input)?;
    let mut current = prepared
        .map(|prepared| prepared.current.clone())
        .unwrap_or_else(|| ManagementReviewCurrent {
            station_id: station.clone(),
            observations: Vec::new(),
            applet_candidate: None,
            applet_event: None,
        });
    if current.station_id != *station {
        return Err(refused(
            "revision_unavailable",
            "creation observations name another receiving Station",
        ));
    }
    current.applet_candidate = Some(Box::new(input.clone()));
    let accounts = current
        .observations
        .iter()
        .map(|observation| observation.record().account_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    require_current_accounts(conn, scope.realm_id(), &accounts, &current).await?;
    let (expected_operation, digest) = crate::applet_action_approval::operation_binding(input)?;
    if prepared.is_some_and(|prepared| {
        prepared.operation != expected_operation || prepared.target_digest != digest
    }) {
        return Err(refused(
            "signature_invalid",
            "operation preparation differs from actual target",
        ));
    }
    let methods = prepared
        .map(|prepared| {
            prepared
                .methods
                .iter()
                .filter(|method| {
                    matches!(
                        method.signature.input.approval_context,
                        arkret_wire::ApprovalContext::Management { .. }
                    )
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let Some(id) = approval_request_id(&methods)? else {
        current_installation(conn, input, scope, station).await?;
        let provision = validated.provision.as_ref().ok_or_else(hidden)?;
        let (_, decision) = select_current_creation(
            conn,
            input,
            scope,
            management_operation,
            if input.prior_managed_refs.is_empty() {
                None
            } else {
                Some(&provision.actor_id)
            },
            at,
        )
        .await?;
        if !decision.review_requirements.is_empty() {
            return Err(refused(
                "approval_required",
                "current Applet Policy requires management review",
            ));
        }
        return Ok(Vec::new());
    };
    let mut row = read(conn, &id, true).await?.ok_or_else(hidden)?;
    let request = row.request();
    if !creation(&request)
        || request.target.canonical_target_digest().map_err(invalid)? != digest
        || request.requester_actor_id != input.admin_actor_id
        || request.effective_scope != *scope
        || operation(&request) != expected_operation
    {
        return Err(refused(
            "signature_invalid",
            "approved creation target changed",
        ));
    }
    Box::pin(refresh(conn, &mut row, at, &current)).await?;
    if row.status != "approved" {
        return Err(refused(
            "approval_required",
            "creation has no current unconsumed management approval",
        ));
    }
    if json!(
        methods
            .iter()
            .map(|method| &method.signature)
            .collect::<Vec<_>>()
    ) != row.approval_signatures
    {
        return Err(refused(
            "signature_invalid",
            "creation management votes differ from durable decision",
        ));
    }
    let bases = row.approval_basis.as_array().ok_or_else(hidden)?;
    if bases.len() != methods.len() {
        return Err(refused(
            "signature_invalid",
            "creation management basis count differs",
        ));
    }
    for (method, basis) in methods.iter().zip(bases) {
        if basis["public_key"] != json!(arkret_canonical::base64url_encode(method.public_key))
            || basis["control_history"] != json!(method.control_history)
        {
            return Err(refused(
                "signature_invalid",
                "creation management vote history changed",
            ));
        }
    }
    let qualified = qualify(conn, &row, &methods, at, &current).await?;
    if !threshold_met(&row, &qualified)? {
        return Err(refused(
            "approval_required",
            "creation management threshold is not currently met",
        ));
    }
    Ok(qualified)
}

pub(crate) async fn consume(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringCandidate,
    qualified: &[crate::approval_admission::QualifiedApproval],
    refs: &[arkret_wire::CommittedEventRef],
    response: &Value,
) -> PersistenceResult<()> {
    if qualified.is_empty() {
        return Ok(());
    }
    let id = qualified[0].qualification_basis["management_request_id"]
        .as_str()
        .ok_or_else(hidden)?;
    crate::applet_action_approval::consume(conn, input, qualified, refs, response).await?;
    let outcome = crate::applet_action_approval::accepted_outcome(input, refs, response)?;
    let updated=sql_query("UPDATE management_review_requests SET status='consumed',accepted_operation_outcome=$2 WHERE request_id=$1 AND status='approved'")
        .bind::<Text,_>(id).bind::<Jsonb,_>(outcome).execute(conn).await.map_err(PersistenceError::database)?;
    if updated != 1 {
        return Err(refused(
            "approval_required",
            "creation review consumption lost its cut",
        ));
    }
    Ok(())
}

async fn current_installation(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringCandidate,
    scope: &ScopeRef,
    station: &arkret_wire::DidCoreId,
) -> PersistenceResult<JsonRow> {
    let scope_key = coland_storage::applet_effective_scope_key(scope)?;
    let installation = sql_query("SELECT i.record AS value FROM applet_installations i WHERE applet_id=$1 AND effective_scope_key=$2 FOR UPDATE")
        .bind::<Text,_>(input.package.applet_id.as_str()).bind::<Text,_>(scope_key).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(hidden)?;
    let identity = sql_query("SELECT record AS value FROM applet_managed_identities WHERE applet_id=$1 AND target_station_id=$2 FOR UPDATE")
        .bind::<Text,_>(input.package.applet_id.as_str()).bind::<Text,_>(station.as_str()).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(hidden)?;
    if installation.value["effective_scope"] != json!(scope)
        || installation.value["package"] != json!(input.package)
        || installation.value["target_station_id"] != json!(station)
        || installation
            .value
            .get("revoked_at")
            .is_some_and(|v| !v.is_null())
        || identity
            .value
            .get("globally_fenced_at")
            .is_some_and(|v| !v.is_null())
        || !matches!(
            installation.value["status"].as_str(),
            Some("installed" | "partially_installed")
        )
    {
        return Err(refused(
            "capability_denied",
            "creation installation is not current active",
        ));
    }
    Ok(installation)
}

pub(crate) async fn require_current_installation(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringCandidate,
) -> PersistenceResult<()> {
    current_installation(
        conn,
        input,
        crate::applet_admission::effective_scope(input)?,
        crate::applet_admission::target_station(input)?,
    )
    .await
    .map(|_| ())
}

async fn select_current_creation(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringCandidate,
    scope: &ScopeRef,
    operation: ManagementOperation,
    managed_actor: Option<&ActorId>,
    at: DateTime<Utc>,
) -> PersistenceResult<(
    Vec<Policy>,
    arkret_policy::applet_management::AppletManagementDecision,
)> {
    let circle = match scope {
        ScopeRef::Circle { circle_id, .. } => Some(circle_id),
        _ => None,
    };
    let policies =
        crate::policy_current_results::read_scoped_applet_management_policies_in_connection(
            conn,
            scope.realm_id(),
            circle,
        )
        .await?;
    use arkret_models_collaboration::governance::operation_wire::{
        AppletPolicyOperation, PolicyResourceKind, PolicyResourceSelector,
    };
    let resources = vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(scope.realm_id().clone()),
        resource_ref: Some(scope.realm_id().to_string()),
    }];
    let decision = arkret_policy::applet_management::select_applet_management(
        Some(&policies),
        &arkret_policy::applet_management::AppletManagementContext {
            realm_id: scope.realm_id(),
            requester_actor_id: &input.admin_actor_id,
            applet_id: &input.package.applet_id,
            effective_scope: scope,
            managed_actor_id: managed_actor,
            operation: match operation {
                ManagementOperation::CreateBot => AppletPolicyOperation::CreateBot,
                ManagementOperation::MapGhost => AppletPolicyOperation::MapGhost,
                _ => return Err(hidden()),
            },
            content_action: None,
            resources: Some(&resources),
            at,
        },
    )
    .map_err(invalid)?;
    if matches!(
        decision.effect,
        PolicyEffect::Deny | PolicyEffect::Quarantine
    ) {
        return Err(refused(
            "capability_denied",
            "Applet management Policy rejects creation",
        ));
    }
    Ok((policies, decision))
}

fn creation_binding(
    input: &AppletAuthoringCandidate,
) -> PersistenceResult<(&ScopeRef, &arkret_wire::DidCoreId, ManagementOperation)> {
    match &input.request {
        AppletAdmissionRequest::Managed(AppletManagedActorCommittedRequest::Bot(body)) => {
            let basis = body.authoring_request.basis.bot().ok_or_else(hidden)?;
            Ok((
                &basis.effective_scope,
                &basis.target_station_id,
                ManagementOperation::CreateBot,
            ))
        }
        AppletAdmissionRequest::Managed(AppletManagedActorCommittedRequest::Ghost(body)) => {
            let basis = body.authoring_request.basis.ghost().ok_or_else(hidden)?;
            Ok((
                &basis.effective_scope,
                &basis.target_station_id,
                ManagementOperation::MapGhost,
            ))
        }
        _ => Err(hidden()),
    }
}
