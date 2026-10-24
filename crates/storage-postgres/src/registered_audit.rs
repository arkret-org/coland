//! Registered audit units: exact fences, accepting-cut rights and frozen reads.

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, AuditPairedEventAcceptanceOutcome, AuditPairedEventUnitKind,
};
use arkret_models_collaboration::events_payloads::audit::AuditAccessedKind;
use arkret_models_collaboration::strand_watch_operations::{
    WatchAuditReadRequestBody, WatchAuditReadResponseBody,
};
use arkret_wire::{
    CapabilityActionId, EventId, ResourceSelectorKind, ScopeRef, WireResourceSelector,
};
use coland_storage::{
    AuthorityCommitTransaction, EventBatchCommitRequest, PersistenceError, PersistenceResult,
    RegisteredAuditCommit, RegisteredAuditOutcome, RegisteredAuditResult, SelfExactCurrentRead,
};
use diesel::sql_query;
use diesel::sql_types::{Binary, Jsonb, Text};
use diesel_async::{AsyncConnection, AsyncPgConnection};
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::Value;

use crate::PgTransactionError;

#[derive(diesel::QueryableByName)]
struct ArchiveRow {
    #[diesel(sql_type = Text)]
    private_audit_digest: String,
    #[diesel(sql_type = Binary)]
    canonical_request: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    outcome: Value,
}

fn conflict(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(detail.to_owned())
}
fn unavailable(detail: &str) -> PersistenceError {
    conflict(&format!("revision_unavailable: {detail}"))
}

pub(crate) async fn original_in_connection(
    conn: &mut AsyncPgConnection,
    event: &EventId,
) -> PersistenceResult<Option<RegisteredAuditResult>> {
    let pair = sql_query("SELECT canonical_request,outcome,private_audit_digest FROM registered_audit_units WHERE business_event_id=$1 OR audit_event_id=$1")
        .bind::<Text,_>(event.as_str()).get_result::<ArchiveRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(row) = pair {
        let request: arkret_models_collaboration::authority_commit::AuditPairedEventUnitSubmission =
            serde_json::from_slice(&row.canonical_request).map_err(PersistenceError::database)?;
        let outcome: AuditPairedEventAcceptanceOutcome =
            serde_json::from_value(row.outcome).map_err(PersistenceError::database)?;
        outcome
            .validate_for_request(&request)
            .map_err(PersistenceError::database)?;
        require_archived_slots(
            conn,
            &request.events,
            &outcome.commits,
            &row.private_audit_digest,
        )
        .await?;
        return Ok(Some(RegisteredAuditResult {
            canonical_request: row.canonical_request,
            outcome: RegisteredAuditOutcome::Pair(outcome),
        }));
    }
    let read = sql_query("SELECT canonical_request,outcome,private_audit_digest FROM watch_audit_read_results WHERE audit_event_id=$1")
        .bind::<Text,_>(event.as_str()).get_result::<ArchiveRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(row) = read {
        let request: WatchAuditReadRequestBody =
            serde_json::from_slice(&row.canonical_request).map_err(PersistenceError::database)?;
        let outcome: WatchAuditReadResponseBody =
            serde_json::from_value(row.outcome).map_err(PersistenceError::database)?;
        outcome
            .validate_for_request(&request, outcome.audit_commit.governance_generation)
            .map_err(PersistenceError::database)?;
        require_archived_slots(
            conn,
            std::slice::from_ref(&request.audit_submission),
            std::slice::from_ref(&outcome.audit_commit),
            &row.private_audit_digest,
        )
        .await?;
        return Ok(Some(RegisteredAuditResult {
            canonical_request: row.canonical_request,
            outcome: RegisteredAuditOutcome::WatchRead(outcome),
        }));
    }
    Ok(None)
}

async fn require_archived_slots(
    conn: &mut AsyncPgConnection,
    slots: &[arkret_wire::EventAdmissionSubmission],
    commits: &[arkret_wire::RealmCommit],
    expected_private_digest: &str,
) -> PersistenceResult<()> {
    #[derive(diesel::QueryableByName)]
    struct Full {
        #[diesel(sql_type=Jsonb)]
        envelope: Value,
        #[diesel(sql_type=Jsonb)]
        commit_json: Value,
    }
    for (slot, commit) in slots.iter().zip(commits) {
        let held = sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1 AND e.state='committed'")
            .bind::<Text,_>(slot.event.event_id.as_str()).get_result::<Full>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let envelope = serde_json::to_value(&slot.event).map_err(PersistenceError::database)?;
        let commit_json = serde_json::to_value(commit).map_err(PersistenceError::database)?;
        if held.is_none_or(|held| held.envelope != envelope || held.commit_json != commit_json) {
            return Err(unavailable(
                "registered acceptance lacks its exact complete Event/Commit originals",
            ));
        }
    }
    let ids = slots
        .iter()
        .map(|slot| slot.event.event_id.clone())
        .collect::<Vec<_>>();
    if private_audit_digest(conn, &ids).await? != expected_private_digest {
        return Err(unavailable(
            "registered acceptance lacks its complete private approval audit",
        ));
    }
    Ok(())
}

fn target(event: &arkret_wire::Event) -> PersistenceResult<WireResourceSelector> {
    let mut target = WireResourceSelector::realm(event.realm_id.clone());
    match &event.scope_ref {
        ScopeRef::Circle { circle_id, .. } => {
            target.kind = ResourceSelectorKind::Circle;
            target.circle_id = Some(circle_id.clone());
        }
        ScopeRef::Realm { .. } => {}
        _ => {
            return Err(conflict(
                "failed_precondition: audit requires a Realm or Circle stream",
            ));
        }
    }
    if let Some(strand) = event
        .payload
        .get("strand_id")
        .and_then(Value::as_str)
        .or_else(|| {
            event
                .payload
                .get("target_ref")
                .and_then(Value::as_str)
                .filter(|id| id.starts_with("ak:strand:"))
        })
    {
        target.kind = ResourceSelectorKind::Strand;
        target.strand_id = Some(strand.parse().map_err(PersistenceError::database)?);
    }
    Ok(target)
}

pub(crate) async fn read_approval_markers_in_connection(
    conn: &mut AsyncPgConnection,
    request: &WatchAuditReadRequestBody,
) -> PersistenceResult<Vec<coland_storage::VerifiedGrantApproval>> {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=Jsonb)]
        accepted_basis: Value,
        #[diesel(sql_type=Jsonb)]
        evidence: Value,
    }
    let rows = sql_query(
        "SELECT accepted_basis,evidence FROM event_approval_private_audit WHERE event_id=$1",
    )
    .bind::<Text, _>(request.audit_submission.event.event_id.as_str())
    .load::<Row>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut markers: Vec<coland_storage::VerifiedGrantApproval> = Vec::new();
    for row in rows {
        let signature: arkret_wire::ApprovalSignature =
            serde_json::from_value(row.evidence).map_err(PersistenceError::database)?;
        let arkret_wire::ApprovalContext::Grant {
            grant_id: evidence_grant,
        } = &signature.input.approval_context
        else {
            continue;
        };
        let qualifications = row
            .accepted_basis
            .get("qualifications")
            .and_then(Value::as_array)
            .ok_or_else(|| unavailable("accepted approval qualifications are missing"))?;
        for grouped in qualifications {
            let qualified = grouped
                .get("registered_unit_qualifications")
                .and_then(Value::as_array)
                .ok_or_else(|| unavailable("registered approval qualifications are missing"))?;
            for qualification in qualified {
                let Some(requirement) = qualification.get("grant_requirement") else {
                    continue;
                };
                let grant_id = serde_json::from_value(requirement["grant_id"].clone())
                    .map_err(PersistenceError::database)?;
                if &grant_id != evidence_grant {
                    return Err(unavailable("accepted approval names another grant"));
                }
                let constraint_digest = requirement["constraint_digest"]
                    .as_str()
                    .ok_or_else(|| unavailable("accepted approval constraint is missing"))?
                    .to_owned();
                let marker = coland_storage::VerifiedGrantApproval {
                    grant_id,
                    constraint_digest,
                    action: signature.input.action,
                };
                if !markers.iter().any(|item| {
                    item.grant_id == marker.grant_id
                        && item.constraint_digest == marker.constraint_digest
                        && item.action == marker.action
                }) {
                    markers.push(marker);
                }
            }
        }
    }
    Ok(markers)
}

pub(crate) fn bind_approvals(batch: &mut EventBatchCommitRequest) -> PersistenceResult<()> {
    let Some(unit) = &mut batch.audit_unit else {
        return Ok(());
    };
    let binding = match unit {
        RegisteredAuditCommit::Pair { request, .. } => {
            request.validate().map_err(PersistenceError::database)?;
            let mut original = request.as_ref().clone();
            for slot in &mut original.events {
                slot.approval_signatures = None;
            }
            coland_storage::ApprovalCarrierBinding::AuditPair {
                request_digest: arkret_canonical::canonical_sha256(&original)
                    .map_err(PersistenceError::database)?,
            }
        }
        RegisteredAuditCommit::WatchRead { request } => {
            request.validate().map_err(PersistenceError::database)?;
            let mut original = request.as_ref().clone();
            original.audit_submission.approval_signatures = None;
            coland_storage::ApprovalCarrierBinding::WatchAuditRead {
                request_digest: arkret_canonical::canonical_sha256(&original)
                    .map_err(PersistenceError::database)?,
            }
        }
    };
    match unit {
        RegisteredAuditCommit::Pair { approvals, .. } => {
            for approval in approvals.iter_mut().flatten() {
                approval.carrier_binding = Some(binding.clone());
            }
        }
        RegisteredAuditCommit::WatchRead { .. } => {
            if let Some(approval) = &mut batch.event_approvals {
                approval.carrier_binding = Some(binding);
            }
        }
    }
    Ok(())
}

async fn action_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    approvals: Option<&coland_storage::EventApprovalCommit>,
    action: CapabilityActionId,
) -> Result<Vec<crate::approval_admission::QualifiedApproval>, PgTransactionError> {
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event).await?;
    let accepted = cut
        .require_registered_audit_action(conn, event, commit, approvals, action, &target(event)?)
        .await?;
    Ok(accepted)
}

/// Read-only current rights. Replay does not reserve another quota or approval nonce.
pub(crate) async fn read_visibility_in_connection(
    conn: &mut AsyncPgConnection,
    request: &WatchAuditReadRequestBody,
    issuer: &arkret_wire::DidCoreId,
    expected_generation: Option<u64>,
) -> PersistenceResult<()> {
    request.validate().map_err(PersistenceError::database)?;
    let event = &request.audit_submission.event;
    let authority = crate::authority_commit::locked_authority(conn, &event.realm_id)
        .await
        .map_err(PgTransactionError::into_persistence)?;
    if authority.as_ref().is_none_or(|authority| {
        &authority.service_id != issuer
            || expected_generation.is_some_and(|generation| generation != authority.generation)
    }) {
        return Err(unavailable(
            "audit observation governing tenure is no longer current",
        ));
    }
    #[derive(diesel::QueryableByName)]
    struct Strand {
        #[diesel(sql_type=Jsonb)]
        value: Value,
        #[diesel(sql_type=Text)]
        current_commit_id: String,
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        current_stream_position: i64,
        #[diesel(sql_type=Jsonb)]
        source_stream_ref: Value,
    }
    let strand = sql_query("SELECT value,current_commit_id,current_stream_position,c.stream_ref AS source_stream_ref FROM strand_current_states s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.realm_id=$1 AND s.strand_id=$2 FOR SHARE OF s")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(request.selector().map_err(PersistenceError::database)?.strand_id.as_str()).get_result::<Strand>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let strand = match strand {
        Some(strand) => strand,
        None => {
            #[derive(diesel::QueryableByName)]
            struct Exists {
                #[diesel(sql_type=diesel::sql_types::Bool)]
                present: bool,
            }
            let orphan = sql_query("SELECT EXISTS(SELECT 1 FROM strand_current_states WHERE realm_id=$1 AND strand_id=$2) AS present")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(request.selector().map_err(PersistenceError::database)?.strand_id.as_str())
                .get_result::<Exists>(&mut *conn).await.map_err(PersistenceError::database)?.present;
            return Err(if orphan {
                unavailable("audited Strand covering Commit is missing")
            } else {
                PersistenceError::NotFound("audited Strand unavailable".to_owned())
            });
        }
    };
    let scope = match strand.value.get("scope_circle_id").and_then(Value::as_str) {
        Some(circle) => ScopeRef::Circle {
            realm_id: event.realm_id.clone(),
            circle_id: circle.parse().map_err(PersistenceError::database)?,
        },
        None => ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        },
    };
    if strand.value.get("state").and_then(Value::as_str) != Some("active")
        || event.scope_ref != scope
    {
        return Err(PersistenceError::NotFound(
            "audited Strand scope is no longer visible".to_owned(),
        ));
    }
    let stream = arkret_wire::CommitStreamRef::from_scope(&scope, None)
        .map_err(PersistenceError::database)?;
    if serde_json::to_value(&stream).map_err(PersistenceError::database)?
        != strand.source_stream_ref
    {
        return Err(unavailable(
            "audited Strand source differs from its effective stream",
        ));
    }
    let source = crate::account_content_delivery::current_source_in_connection(
        conn,
        &event.realm_id,
        &stream,
        &arkret_wire::CurrentRevision {
            commit_id: strand
                .current_commit_id
                .parse()
                .map_err(PersistenceError::database)?,
            stream_position: u64::try_from(strand.current_stream_position)
                .map_err(PersistenceError::database)?,
        },
    )
    .await?;
    if let ScopeRef::Circle { circle_id, .. } = &scope {
        let circle = sql_query("SELECT value,current_commit_id,current_stream_position,source_stream_ref FROM circle_current_states WHERE realm_id=$1 AND circle_id=$2 FOR SHARE")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(circle_id.as_str()).get_result::<Strand>(&mut *conn).await.optional().map_err(PersistenceError::database)?
            .ok_or_else(|| unavailable("audited Circle current is missing"))?;
        if circle.value.get("state").and_then(Value::as_str) != Some("active") {
            return Err(PersistenceError::NotFound(
                "audited Circle is not active".to_owned(),
            ));
        }
        let stream =
            serde_json::from_value(circle.source_stream_ref).map_err(PersistenceError::database)?;
        crate::account_content_delivery::current_source_in_connection(
            conn,
            &event.realm_id,
            &stream,
            &arkret_wire::CurrentRevision {
                commit_id: circle
                    .current_commit_id
                    .parse()
                    .map_err(PersistenceError::database)?,
                stream_position: u64::try_from(circle.current_stream_position)
                    .map_err(PersistenceError::database)?,
            },
        )
        .await?;
    }
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event).await?;
    cut.require_open_lifecycle(event)
        .map_err(|_| PersistenceError::NotFound("audited Realm is not visible".to_owned()))?;
    cut.require_governed_member(&event.kind)
        .map_err(|error| match error {
            PersistenceError::Conflict(detail)
                if detail.contains("revision_unavailable")
                    || detail.contains("no authority root") =>
            {
                PersistenceError::Conflict(detail)
            }
            _ => PersistenceError::NotFound("auditor is not a current Realm member".to_owned()),
        })?;
    let bounded = cut
        .bounded_actor_authorization_in_connection(conn, chrono::Utc::now())
        .await?;
    let (resource, facts) = cut.event_operation(event);
    let resource = target(event).unwrap_or(resource);
    let owned = crate::realm_authorization_cut::owned_source_in_connection(
        conn,
        &event.realm_id,
        &event.actor_id,
        chrono::Utc::now(),
        false,
    )
    .await?;
    let markers = read_approval_markers_in_connection(conn, request).await?;
    if expected_generation.is_some() {
        cut.require_content_read_constraints_with_approvals(
            &source,
            chrono::Utc::now(),
            owned,
            CapabilityActionId::RealmNotificationAudit,
            &markers,
        )
        .map_err(|_| {
            PersistenceError::NotFound(
                "audited Strand disclosure is no longer permitted".to_owned(),
            )
        })?;
    }
    if expected_generation.is_some() {
        let markers = read_approval_markers_in_connection(conn, request).await?;
        for action in [
            CapabilityActionId::RealmNotificationAudit,
            CapabilityActionId::AuditAccessed,
        ] {
            let actions = [action.as_str()];
            let evaluation = bounded.evaluate_with_approvals(&actions, &resource, &facts, &markers);
            let owner = matches!(evaluation, coland_storage::GrantEvaluation::Unsatisfied)
                && bounded.root_controller
                && bounded.agent_ceiling.is_none()
                && arkret_policy::owner_may_author_action(action.as_str()).unwrap_or(false);
            if !matches!(evaluation, coland_storage::GrantEvaluation::Allowed(_)) && !owner {
                return Err(PersistenceError::NotFound(
                    "Watch audit is not currently visible".to_owned(),
                ));
            }
        }
    }
    if let ScopeRef::Circle { circle_id, .. } = &event.scope_ref
        && !crate::circle_current_states::effective_member_in_connection(
            conn,
            &event.realm_id,
            circle_id,
            &event.actor_id,
        )
        .await?
    {
        let explicit = cut.effective_grants(chrono::Utc::now()).any(|(_, grant)| {
            grant
                .resources
                .iter()
                .any(|selector| selector.circle_id.as_ref() == Some(circle_id))
                && coland_storage::grant_names_target(
                    grant,
                    &[CapabilityActionId::CircleAudit.as_str()],
                    &resource,
                )
        });
        let actions = [CapabilityActionId::CircleAudit.as_str()];
        let markers = read_approval_markers_in_connection(conn, request).await?;
        if !explicit
            || (expected_generation.is_some()
                && !matches!(
                    bounded.evaluate_with_approvals(&actions, &resource, &facts, &markers),
                    coland_storage::GrantEvaluation::Allowed(_)
                ))
        {
            return Err(PersistenceError::NotFound(
                "Circle audit is not visible".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn begin_in_connection(
    conn: &mut AsyncPgConnection,
    batch: &EventBatchCommitRequest,
) -> Result<Option<RegisteredAuditOutcome>, PgTransactionError> {
    let Some(unit) = &batch.audit_unit else {
        for slot in &batch.events {
            let event = &slot.authority_commit.event;
            if event.kind == arkret_wire::EventKind::AuditAccessed {
                let kind = event
                    .as_audit_accessed()
                    .map_err(PersistenceError::database)?
                    .access_kind;
                if matches!(
                    kind,
                    AuditAccessedKind::WatchAuditRead
                        | AuditAccessedKind::WatchSetOthers
                        | AuditAccessedKind::CircleMemberSetOthers
                ) {
                    return Err(conflict(
                        "failed_precondition: audit requires its registered unit or read command",
                    )
                    .into());
                }
            }
        }
        return Ok(None);
    };
    let first = &batch
        .events
        .as_slice()
        .first()
        .ok_or_else(|| conflict("failed_precondition: empty audit unit"))?
        .authority_commit;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &first.event.realm_id)
        .await?;
    let original_bytes = unit.canonical_request()?;
    let audit_id = match unit {
        RegisteredAuditCommit::Pair { request, .. } => {
            request.validate().map_err(PersistenceError::database)?;
            if batch.events.len() != 2
                || batch
                    .events
                    .iter()
                    .zip(&request.events)
                    .any(|(event, slot)| event.authority_commit.event != slot.event)
            {
                return Err(conflict("failed_precondition: accepting audit pair differs from its complete signed unit").into());
            }
            AuditPairedEventAcceptanceOutcome {
                unit_kind: request.unit_kind,
                status: AggregateAcceptanceStatus::Committed,
                commits: [
                    batch.events[0].authority_commit.commit.clone(),
                    batch.events[1].authority_commit.commit.clone(),
                ],
            }
            .validate()
            .map_err(PersistenceError::database)?;
            &request.events[1].event.event_id
        }
        RegisteredAuditCommit::WatchRead { request } => {
            request.validate().map_err(PersistenceError::database)?;
            if batch.events.len() != 1 || first.event != request.audit_submission.event {
                return Err(conflict(
                    "failed_precondition: audit read differs from its signed intent",
                )
                .into());
            }
            &first.event.event_id
        }
    };
    crate::unit_of_work::advisory_lock(conn, format!("registered-audit:{audit_id}")).await?;
    for slot in &batch.events {
        if let Some(original) =
            original_in_connection(conn, &slot.authority_commit.event.event_id).await?
        {
            if original.canonical_request != original_bytes {
                return Err(conflict(
                    "duplicate_conflict: audit Event is already bound to another complete request",
                )
                .into());
            }
            match (unit, &original.outcome) {
                (
                    RegisteredAuditCommit::Pair { request, .. },
                    RegisteredAuditOutcome::Pair(outcome),
                ) => outcome.validate_for_request(request).map_err(|_| {
                    unavailable("stored pair outcome does not bind its original request")
                })?,
                (
                    RegisteredAuditCommit::WatchRead { request },
                    RegisteredAuditOutcome::WatchRead(outcome),
                ) => outcome
                    .validate_for_request(request, first.expected_authority.generation)
                    .map_err(|_| {
                        unavailable("stored audit observation does not bind its original request")
                    })?,
                _ => {
                    return Err(
                        unavailable("stored audit outcome has another registered kind").into(),
                    );
                }
            }
            if let (
                RegisteredAuditCommit::WatchRead { request },
                RegisteredAuditOutcome::WatchRead(outcome),
            ) = (unit, &original.outcome)
            {
                read_visibility_in_connection(
                    conn,
                    request,
                    &first.expected_authority.service_id,
                    Some(outcome.audit_commit.governance_generation),
                )
                .await?;
            }
            return Ok(Some(original.outcome));
        }
        #[derive(diesel::QueryableByName)]
        struct Present {
            #[diesel(sql_type=diesel::sql_types::Bool)]
            present: bool,
        }
        let present = sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events WHERE envelope->>'event_id'=$1) AS present")
            .bind::<Text,_>(slot.authority_commit.event.event_id.as_str()).get_result::<Present>(&mut *conn).await?;
        if present.present {
            return Err(unavailable(
                "preaccepted or partial audit material has no exact result fence",
            )
            .into());
        }
    }
    for (index, slot) in batch.events.iter().enumerate() {
        let prepared = match unit {
            RegisteredAuditCommit::Pair { approvals, .. } => {
                approvals.get(index).and_then(Option::as_ref)
            }
            RegisteredAuditCommit::WatchRead { .. } => batch.event_approvals.as_ref(),
        };
        let submitted = match unit {
            RegisteredAuditCommit::Pair { request, .. } => request
                .events
                .get(index)
                .and_then(|slot| slot.approval_signatures.as_deref()),
            RegisteredAuditCommit::WatchRead { request } => {
                request.audit_submission.approval_signatures.as_deref()
            }
        }
        .unwrap_or_default();
        let resolved = prepared
            .map(|prepared| prepared.methods.as_slice())
            .unwrap_or_default();
        if submitted.len() != resolved.len()
            || submitted
                .iter()
                .zip(resolved)
                .any(|(submitted, resolved)| submitted != &resolved.signature)
        {
            return Err(conflict("signature_invalid: prepared approval history differs from the full registered submission").into());
        }
        crate::approval_admission::validate_candidate(
            &slot.authority_commit.event,
            &slot.authority_commit.commit,
            prepared,
        )?;
    }
    let mut accepted_actions = Vec::new();
    match unit {
        RegisteredAuditCommit::Pair { request, approvals } => {
            let business = &first.event;
            if business.kind == arkret_wire::EventKind::StrandWatchSet {
                accepted_actions.push((
                    0,
                    CapabilityActionId::StrandWatchSetOthers,
                    action_in_connection(
                        conn,
                        business,
                        &first.commit,
                        approvals[0].as_ref(),
                        CapabilityActionId::StrandWatchSetOthers,
                    )
                    .await?,
                ));
            } else {
                let primary = conn
                    .transaction::<_, PgTransactionError, _>(async |conn| {
                        action_in_connection(
                            conn,
                            business,
                            &first.commit,
                            approvals[0].as_ref(),
                            CapabilityActionId::CircleMemberManage,
                        )
                        .await
                    })
                    .await;
                let (action, approved) = if let Ok(approved) = primary {
                    (CapabilityActionId::CircleMemberManage, approved)
                } else {
                    (
                        CapabilityActionId::CircleMemberAddOthers,
                        action_in_connection(
                            conn,
                            business,
                            &first.commit,
                            approvals[0].as_ref(),
                            CapabilityActionId::CircleMemberAddOthers,
                        )
                        .await?,
                    )
                };
                accepted_actions.push((0, action, approved));
            }
            let audit = &batch.events[1].authority_commit;
            accepted_actions.push((
                1,
                CapabilityActionId::AuditAccessed,
                action_in_connection(
                    conn,
                    &audit.event,
                    &audit.commit,
                    approvals[1].as_ref(),
                    CapabilityActionId::AuditAccessed,
                )
                .await?,
            ));
            debug_assert_eq!(request.events[1].event.event_id, audit.event.event_id);
        }
        RegisteredAuditCommit::WatchRead { request } => {
            read_visibility_in_connection(
                conn,
                request,
                &first.expected_authority.service_id,
                None,
            )
            .await?;
            if let ScopeRef::Circle { circle_id, .. } = &first.event.scope_ref
                && !crate::circle_current_states::effective_member_in_connection(
                    conn,
                    &first.event.realm_id,
                    circle_id,
                    &first.event.actor_id,
                )
                .await?
            {
                accepted_actions.push((
                    0,
                    CapabilityActionId::CircleAudit,
                    action_in_connection(
                        conn,
                        &first.event,
                        &first.commit,
                        batch.event_approvals.as_ref(),
                        CapabilityActionId::CircleAudit,
                    )
                    .await?,
                ));
            }
            accepted_actions.push((
                0,
                CapabilityActionId::RealmNotificationAudit,
                action_in_connection(
                    conn,
                    &first.event,
                    &first.commit,
                    batch.event_approvals.as_ref(),
                    CapabilityActionId::RealmNotificationAudit,
                )
                .await?,
            ));
            accepted_actions.push((
                0,
                CapabilityActionId::AuditAccessed,
                action_in_connection(
                    conn,
                    &first.event,
                    &first.commit,
                    batch.event_approvals.as_ref(),
                    CapabilityActionId::AuditAccessed,
                )
                .await?,
            ));
        }
    }
    consume_registered_actions(conn, batch, accepted_actions).await?;
    Ok(None)
}

async fn consume_registered_actions(
    conn: &mut AsyncPgConnection,
    batch: &EventBatchCommitRequest,
    actions: Vec<(
        usize,
        CapabilityActionId,
        Vec<crate::approval_admission::QualifiedApproval>,
    )>,
) -> PersistenceResult<()> {
    let mut groups = std::collections::BTreeMap::new();
    for (index, action, qualified) in actions {
        for vote in qualified {
            let signature = &vote.method.signature;
            let key = (
                arkret_canonical::canonical_json_string(&signature.input.approval_context)
                    .map_err(PersistenceError::database)?,
                signature.input.approver_did.to_string(),
                signature.input.nonce.clone(),
            );
            let entry = groups
                .entry(key)
                .or_insert_with(|| (index, vote.clone(), Vec::new(), Vec::new()));
            if entry.1.method.signature != vote.method.signature
                || entry.1.method.public_key != vote.method.public_key
                || entry.1.method.control_history != vote.method.control_history
                || (entry.0 != index
                    && !matches!(
                        signature.input.approval_target,
                        arkret_wire::ApprovalTarget::Operation
                    ))
            {
                return Err(conflict(
                    "approval_nonce_reused: distinct registered evidence shares one nonce",
                ));
            }
            if !entry.2.contains(&vote.qualification_basis) {
                entry.2.push(vote.qualification_basis);
            }
            let basis = serde_json::json!({"event_id": batch.events[index].authority_commit.event.event_id, "action":action});
            if !entry.3.contains(&basis) {
                entry.3.push(basis);
            }
        }
    }
    for (_, (index, mut vote, qualifications, actions)) in groups {
        vote.qualification_basis =
            serde_json::json!({"registered_unit_qualifications":qualifications});
        let tx = &batch.events[index].authority_commit;
        crate::approval_admission::consume_and_audit(
            conn,
            &tx.event,
            &tx.commit,
            &[vote],
            &serde_json::json!({"registered_audit_actions":actions}),
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn finish_in_connection(
    conn: &mut AsyncPgConnection,
    unit: &RegisteredAuditCommit,
    transactions: &[AuthorityCommitTransaction],
) -> Result<RegisteredAuditOutcome, PgTransactionError> {
    let canonical = unit.canonical_request()?;
    match unit {
        RegisteredAuditCommit::Pair { request, .. } => {
            let commits = [
                transactions[0].commit.clone(),
                transactions[1].commit.clone(),
            ];
            let outcome = AuditPairedEventAcceptanceOutcome {
                unit_kind: AuditPairedEventUnitKind::AuditPairedEvent,
                status: AggregateAcceptanceStatus::Committed,
                commits,
            };
            outcome
                .validate_for_request(request)
                .map_err(PersistenceError::database)?;
            sql_query("INSERT INTO registered_audit_units(business_event_id,audit_event_id,realm_id,canonical_request,outcome,private_audit_digest) VALUES($1,$2,$3,$4,$5,$6)")
                .bind::<Text,_>(request.events[0].event.event_id.as_str()).bind::<Text,_>(request.events[1].event.event_id.as_str()).bind::<Text,_>(request.events[0].event.realm_id.as_str()).bind::<Binary,_>(canonical).bind::<Jsonb,_>(serde_json::to_value(&outcome).map_err(PersistenceError::database)?).bind::<Text,_>(private_audit_digest(conn, &request.events.each_ref().map(|slot| slot.event.event_id.clone())).await?).execute(&mut *conn).await?;
            crate::realm_fanout::plan_audit_pair_in_connection(
                conn,
                request,
                &outcome.commits,
                &transactions[0].expected_authority.service_id,
            )
            .await?;
            Ok(RegisteredAuditOutcome::Pair(outcome))
        }
        RegisteredAuditCommit::WatchRead { request } => {
            let transaction = &transactions[0];
            let current = crate::self_current_reads::strand_watch_observation_in_connection(
                conn,
                &request.selector().map_err(PersistenceError::database)?,
                request
                    .audit_submission
                    .event
                    .actor_id
                    .as_account_id()
                    .ok_or_else(|| conflict("failed_precondition: audit requires an Account"))?,
                &transaction.expected_authority.service_id,
                Some(request),
            )
            .await?;
            let current = match current {
                SelfExactCurrentRead::Answer(value) => value,
                SelfExactCurrentRead::NotFound => {
                    return Err(
                        PersistenceError::NotFound("Watch audit not found".to_owned()).into(),
                    );
                }
                _ => {
                    return Err(
                        unavailable("Watch observation has no complete current basis").into(),
                    );
                }
            };
            let outcome = WatchAuditReadResponseBody {
                audit_commit: transaction.commit.clone(),
                current,
            };
            outcome
                .validate_for_request(request, transaction.expected_authority.generation)
                .map_err(PersistenceError::database)?;
            sql_query("INSERT INTO watch_audit_read_results(audit_event_id,realm_id,auditor_actor_id,canonical_request,outcome,private_audit_digest) VALUES($1,$2,$3,$4,$5,$6)")
                .bind::<Text,_>(request.audit_submission.event.event_id.as_str()).bind::<Text,_>(request.audit_submission.event.realm_id.as_str()).bind::<Text,_>(request.audit_submission.event.actor_id.to_string()).bind::<Binary,_>(canonical).bind::<Jsonb,_>(serde_json::to_value(&outcome).map_err(PersistenceError::database)?).bind::<Text,_>(private_audit_digest(conn, std::slice::from_ref(&request.audit_submission.event.event_id)).await?).execute(&mut *conn).await?;
            Ok(RegisteredAuditOutcome::WatchRead(outcome))
        }
    }
}

#[derive(diesel::QueryableByName)]
struct ForwardRow {
    #[diesel(sql_type=Binary)]
    canonical_request: Vec<u8>,
    #[diesel(sql_type=diesel::sql_types::Nullable<Jsonb>)]
    outcome: Option<Value>,
}

pub(crate) async fn forward_original_in_connection(
    conn: &mut AsyncPgConnection,
    event_id: &arkret_wire::EventId,
) -> PersistenceResult<Option<RegisteredAuditResult>> {
    let row = sql_query("SELECT canonical_request,outcome FROM registered_audit_forward_units WHERE business_event_id=$1 OR audit_event_id=$1")
        .bind::<Text,_>(event_id.as_str()).get_result::<ForwardRow>(conn).await.optional().map_err(PersistenceError::database)?;
    row.and_then(|row| row.outcome.map(|value| (row.canonical_request, value))).map(|(canonical_request, value)| {
        let request: arkret_models_collaboration::authority_commit::AuditPairedEventUnitSubmission = serde_json::from_slice(&canonical_request).map_err(PersistenceError::database)?;
        let outcome: AuditPairedEventAcceptanceOutcome = serde_json::from_value(value).map_err(PersistenceError::database)?;
        outcome.validate_for_request(&request).map_err(PersistenceError::database)?;
        Ok(RegisteredAuditResult { canonical_request, outcome: RegisteredAuditOutcome::Pair(outcome) })
    }).transpose()
}

pub(crate) async fn retain_forward_in_connection(
    conn: &mut AsyncPgConnection,
    request: &arkret_models_collaboration::authority_commit::AuditPairedEventUnitSubmission,
    outcome: Option<&AuditPairedEventAcceptanceOutcome>,
) -> Result<(), PgTransactionError> {
    request.validate().map_err(PersistenceError::database)?;
    if let Some(outcome) = outcome {
        outcome
            .validate_for_request(request)
            .map_err(PersistenceError::database)?;
    }
    let canonical =
        arkret_canonical::canonical_json_bytes(request).map_err(PersistenceError::database)?;
    // Use the same complete Realm cut as local acceptance and handoff.
    crate::realm_authorization_cut::lock_realm_authorization_cut(
        conn,
        &request.events[0].event.realm_id,
    )
    .await?;
    let first = &request.events[0].event.event_id;
    let second = &request.events[1].event.event_id;
    for id in [first, second] {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind::<Text, _>(id.as_str())
            .execute(&mut *conn)
            .await?;
    }
    let row = sql_query("SELECT canonical_request,outcome FROM registered_audit_forward_units WHERE business_event_id IN ($1,$2) OR audit_event_id IN ($1,$2) FOR UPDATE")
        .bind::<Text,_>(first.as_str()).bind::<Text,_>(second.as_str()).get_result::<ForwardRow>(&mut *conn).await.optional()?;
    let value = outcome
        .map(serde_json::to_value)
        .transpose()
        .map_err(PersistenceError::database)?;
    if let Some(row) = row {
        if row.canonical_request != canonical {
            return Err(conflict(
                "duplicate_conflict: origin Event belongs to another complete unit",
            )
            .into());
        }
        if let (Some(original), Some(next)) = (&row.outcome, &value) {
            let original: AuditPairedEventAcceptanceOutcome =
                serde_json::from_value(original.clone()).map_err(PersistenceError::database)?;
            let next: AuditPairedEventAcceptanceOutcome =
                serde_json::from_value(next.clone()).map_err(PersistenceError::database)?;
            if original.commits != next.commits {
                return Err(conflict(
                    "duplicate_conflict: governing acknowledgement changed original Commits",
                )
                .into());
            }
        }
        if row.outcome.is_none()
            && let Some(value) = value
        {
            sql_query(
                "UPDATE registered_audit_forward_units SET outcome=$2 WHERE business_event_id=$1",
            )
            .bind::<Text, _>(first.as_str())
            .bind::<Jsonb, _>(value)
            .execute(&mut *conn)
            .await?;
        }
    } else {
        sql_query("INSERT INTO registered_audit_forward_units(business_event_id,audit_event_id,realm_id,canonical_request,outcome) VALUES($1,$2,$3,$4,$5)")
            .bind::<Text,_>(first.as_str()).bind::<Text,_>(second.as_str()).bind::<Text,_>(request.events[0].event.realm_id.as_str())
            .bind::<Binary,_>(canonical).bind::<diesel::sql_types::Nullable<Jsonb>,_>(value).execute(&mut *conn).await?;
    }
    Ok(())
}

async fn private_audit_digest(
    conn: &mut AsyncPgConnection,
    ids: &[EventId],
) -> PersistenceResult<String> {
    #[derive(diesel::QueryableByName)]
    struct Audit {
        #[diesel(sql_type=Jsonb)]
        value: Value,
    }
    let rows = sql_query("SELECT jsonb_set(to_jsonb(a),'{accepted_at}',to_jsonb(to_char(a.accepted_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'))) AS value FROM event_approval_private_audit a WHERE event_id=ANY($1) ORDER BY approval_context,approver_did,nonce")
        .bind::<diesel::sql_types::Array<Text>,_>(ids.iter().map(|id| id.as_str()).collect::<Vec<_>>())
        .load::<Audit>(conn).await.map_err(PersistenceError::database)?;
    arkret_canonical::canonical_sha256(&rows.into_iter().map(|row| row.value).collect::<Vec<_>>())
        .map_err(PersistenceError::database)
}

/// Handoff activates pre-imported private state. A member replica or a
/// current-only snapshot cannot replace the complete acceptance archive.
pub(crate) async fn verify_handoff_archive(
    conn: &mut AsyncPgConnection,
    originals: &[arkret_wire::CommittedEventFullView],
) -> PersistenceResult<()> {
    #[derive(diesel::QueryableByName)]
    struct Digest {
        #[diesel(sql_type=Text)]
        private_audit_digest: String,
    }
    let full_by_id = originals
        .iter()
        .map(|full| (&full.event.event_id, full))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut checked = std::collections::BTreeSet::new();
    for full in originals {
        if checked.contains(&full.event.event_id) {
            continue;
        }
        let paired =
            arkret_models_collaboration::authority_commit::is_audit_paired_event_slot(&full.event)
                .map_err(PersistenceError::database)?;
        let read = full.event.kind == arkret_wire::EventKind::AuditAccessed
            && full
                .event
                .payload
                .get("access_kind")
                .and_then(Value::as_str)
                == Some("watch_audit_read");
        if !paired && !read {
            continue;
        }
        let original = original_in_connection(conn, &full.event.event_id)
            .await?
            .ok_or_else(|| {
                unavailable("handoff lacks the complete private audit acceptance fence")
            })?;
        let (ids, expected_commits, table) = match &original.outcome {
            RegisteredAuditOutcome::Pair(outcome) if paired => {
                let request: arkret_models_collaboration::authority_commit::AuditPairedEventUnitSubmission = serde_json::from_slice(&original.canonical_request).map_err(PersistenceError::database)?;
                outcome
                    .validate_for_request(&request)
                    .map_err(PersistenceError::database)?;
                for slot in &request.events {
                    if full_by_id.get(&slot.event.event_id).map(|item| &item.event)
                        != Some(&slot.event)
                    {
                        return Err(unavailable(
                            "handoff audit unit request differs from its complete originals",
                        ));
                    }
                }
                (
                    request
                        .events
                        .each_ref()
                        .map(|slot| slot.event.event_id.clone())
                        .to_vec(),
                    outcome.commits.to_vec(),
                    "registered_audit_units",
                )
            }
            RegisteredAuditOutcome::WatchRead(outcome) if read => {
                let request: WatchAuditReadRequestBody =
                    serde_json::from_slice(&original.canonical_request)
                        .map_err(PersistenceError::database)?;
                outcome
                    .validate_for_request(&request, outcome.audit_commit.governance_generation)
                    .map_err(PersistenceError::database)?;
                if request.audit_submission.event != full.event {
                    return Err(unavailable(
                        "handoff frozen audit request differs from original",
                    ));
                }
                (
                    vec![full.event.event_id.clone()],
                    vec![outcome.audit_commit.clone()],
                    "watch_audit_read_results",
                )
            }
            _ => {
                return Err(unavailable(
                    "handoff audit acceptance kind conflicts with its original",
                ));
            }
        };
        for commit in expected_commits {
            if full_by_id.get(&commit.event_ref).map(|item| &item.commit) != Some(&commit) {
                return Err(unavailable(
                    "handoff audit outcome does not bind exact source Commits",
                ));
            }
        }
        checked.extend(ids.iter().cloned());
        let query = match table {
            "registered_audit_units" => {
                "SELECT private_audit_digest FROM registered_audit_units WHERE business_event_id=$1"
            }
            _ => {
                "SELECT private_audit_digest FROM watch_audit_read_results WHERE audit_event_id=$1"
            }
        };
        let digest = sql_query(query)
            .bind::<Text, _>(ids[0].as_str())
            .get_result::<Digest>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        if digest.private_audit_digest != private_audit_digest(conn, &ids).await? {
            return Err(unavailable(
                "handoff private approval audit is incomplete or changed",
            ));
        }
    }
    Ok(())
}
