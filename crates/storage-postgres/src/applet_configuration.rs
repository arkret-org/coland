//! The governing Realm's private administrator intent and exact Applet result.
//! All writers share the Realm authority lock with candidate admission.
use arkret_models_integration::{
    AppletConfigurationAdmissionStatus as Admission, AppletConfigurationCommand as Command,
    AppletConfigurationExecutionIntent as Intent, AppletConfigurationExecutionOutcome as Source,
    AppletConfigurationExecutionStatus as SourceStatus, AppletConfigurationOutcome as Outcome,
};
use arkret_wire::{CapabilityActionId, DidCoreId, Event, EventId, WireResourceSelector};
use coland_storage::{AppletEventProducerGuard, PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::Value;

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type = Jsonb)]
    intent: Value,
    #[diesel(sql_type = Jsonb)]
    outcome: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    candidate: Option<Value>,
}

/// Acquire all Account PCR and governance locks in the existing global order.
/// A validated peer signature proves provenance, not current Account status.
async fn require_account(
    conn: &mut AsyncPgConnection,
    governor: &DidCoreId,
    realm: &arkret_wire::RealmId,
    actor: &arkret_wire::ActorId,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<()> {
    let account = actor
        .as_account_id()
        .ok_or_else(|| invalid("configuration requires a complete Account identity"))?;
    if current.station_id != *governor {
        return Err(invalid(
            "configuration Account observation targets another governor",
        ));
    }
    crate::agent_management_review::require_current_accounts(
        conn,
        realm,
        std::slice::from_ref(account),
        current,
    )
    .await?;
    crate::agent_management_review::require_active_caller(actor, current)
}

async fn gate(
    conn: &mut AsyncPgConnection,
    governor: &DidCoreId,
    intent: &Intent,
    mutation: bool,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<()> {
    intent.validate().map_err(invalid)?;
    let realm = intent.effective_scope.realm_id();
    require_account(conn, governor, realm, &intent.originating_actor_id, current).await?;
    crate::realm_actor_control::require_current_governor(conn, realm, governor).await?;
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        realm,
        &intent.originating_actor_id,
    )
    .await?;
    if !cut.permits_unreserved_current_actions(
        &[CapabilityActionId::REALM_ADMIN],
        &WireResourceSelector::realm(realm.clone()),
        chrono::Utc::now(),
    ) {
        return Err(PersistenceError::Conflict(
            "capability_denied: configuration requires the original Account's current Realm administration".into(),
        ));
    }
    if mutation {
        cut.require_open_business_mutation()?;
        let install = crate::applet_widget_tokens::lock_install(
            conn,
            &coland_storage::AppletWidgetInstallSelector {
                applet_id: intent.applet_id.clone(),
                effective_scope: intent.effective_scope.clone(),
                registration_event_ref: intent.registration_ref.event_id.clone(),
                registration_epoch: intent.registration_epoch.clone(),
            },
            true,
        )
        .await?;
        if install
            .pointer("/package/service_id")
            .and_then(Value::as_str)
            != Some(intent.service_id.as_str())
        {
            return Err(invalid(
                "configuration Service differs from the current installation",
            ));
        }
        let registration = crate::committed_disclosure::accepted_full_event_in_connection(
            conn,
            &intent.registration_ref.event_id,
        )
        .await?
        .ok_or_else(|| invalid("configuration registration is not accepted"))?;
        if registration.commit.commit_id != intent.registration_ref.commit_id
            || registration.commit.stream_ref != intent.registration_ref.stream_ref
            || registration.commit.stream_position != intent.registration_ref.stream_position
            || registration.event.scope_ref
                != arkret_wire::ScopeRef::realm(intent.effective_scope.realm_id().clone())
        {
            return Err(invalid(
                "configuration registration reference differs from its original",
            ));
        }
    }
    Ok(())
}

async fn read(conn: &mut AsyncPgConnection, intent: &Intent) -> PersistenceResult<Option<Outcome>> {
    let row = sql_query(
        "SELECT intent,outcome,candidate FROM applet_configurations \
         WHERE realm_id=$1 AND request_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(intent.effective_scope.realm_id().as_str())
    .bind::<Text, _>(intent.request_id.as_str())
    .get_result::<Row>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    row.map(|row| {
        let original: Intent = serde_json::from_value(row.intent).map_err(invalid)?;
        let outcome: Outcome = serde_json::from_value(row.outcome).map_err(invalid)?;
        if original != *intent
            || outcome.request_id != intent.request_id
            || outcome.intent_digest != intent.digest().map_err(invalid)?
        {
            return Err(invalid(
                "duplicate_conflict: configuration original intent differs",
            ));
        }
        if let Some(source) = &outcome.source_outcome {
            source.validate_for(intent).map_err(invalid)?;
        }
        Ok(outcome)
    })
    .transpose()
}

pub(crate) async fn original_intent(
    conn: &mut AsyncPgConnection,
    governor: &DidCoreId,
    applet: &arkret_wire::AppletId,
    actor: &arkret_wire::ActorId,
    request: &arkret_models_integration::AppletConfigurationIntent,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<Option<Intent>> {
    request.validate().map_err(invalid)?;
    require_account(
        conn,
        governor,
        request.effective_scope.realm_id(),
        actor,
        current,
    )
    .await?;
    crate::realm_actor_control::require_current_governor(
        conn,
        request.effective_scope.realm_id(),
        governor,
    )
    .await?;
    let row = sql_query(
        "SELECT intent,outcome,candidate FROM applet_configurations \
        WHERE realm_id=$1 AND request_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(request.effective_scope.realm_id().as_str())
    .bind::<Text, _>(request.request_id.as_str())
    .get_result::<Row>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let original: Intent = serde_json::from_value(row.intent).map_err(invalid)?;
    if original.service_id != request.service_id
        || original.applet_id != *applet
        || original.originating_actor_id != *actor
        || original.effective_scope != request.effective_scope
        || original.selection != request.selection
    {
        return Err(invalid(
            "duplicate_conflict: configuration caller or intent differs",
        ));
    }
    gate(conn, governor, &original, false, current).await?;
    Ok(Some(original))
}

async fn write(
    conn: &mut AsyncPgConnection,
    intent: &Intent,
    outcome: &Outcome,
    ingress: Option<&coland_storage::AppletConfigurationIngress>,
) -> PersistenceResult<()> {
    crate::realm_management_archive::require_unfrozen(conn, intent.effective_scope.realm_id())
        .await?;
    let candidate = outcome
        .source_outcome
        .as_ref()
        .and_then(|source| source.create_event.as_ref())
        .map(|event| serde_json::to_value(event).map_err(invalid))
        .transpose()?;
    let candidate_id = candidate
        .as_ref()
        .and_then(|event| event["event_id"].as_str());
    if ingress.is_none() {
        let changed = sql_query(
            "UPDATE applet_configurations SET outcome=$1,candidate_event_id=COALESCE(candidate_event_id,$2),candidate=COALESCE(candidate,$6) \
            WHERE realm_id=$3 AND applet_id=$4 AND request_id=$5",
        )
        .bind::<Jsonb, _>(serde_json::to_value(outcome).map_err(invalid)?)
        .bind::<Nullable<Text>, _>(candidate_id)
        .bind::<Text, _>(intent.effective_scope.realm_id().as_str())
        .bind::<Text, _>(intent.applet_id.as_str())
        .bind::<Text, _>(intent.request_id.as_str())
        .bind::<Nullable<Jsonb>, _>(candidate.as_ref())
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
        if changed != 1 {
            return Err(invalid("configuration original ledger is missing"));
        }
        return Ok(());
    }
    sql_query("INSERT INTO applet_configurations \
        (realm_id,applet_id,request_id,intent,outcome,candidate_event_id,ingress,candidate) VALUES($1,$2,$3,$4,$5,$6,$7,$8) \
        ON CONFLICT(realm_id,request_id) DO UPDATE SET \
        outcome=EXCLUDED.outcome,candidate_event_id=COALESCE(applet_configurations.candidate_event_id,EXCLUDED.candidate_event_id),candidate=COALESCE(applet_configurations.candidate,EXCLUDED.candidate)")
        .bind::<Text, _>(intent.effective_scope.realm_id().as_str())
        .bind::<Text, _>(intent.applet_id.as_str())
        .bind::<Text, _>(intent.request_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(intent).map_err(invalid)?)
        .bind::<Jsonb, _>(serde_json::to_value(outcome).map_err(invalid)?)
        .bind::<Nullable<Text>, _>(candidate_id)
        .bind::<Nullable<Jsonb>, _>(ingress.map(serde_json::to_value).transpose().map_err(invalid)?)
        .bind::<Nullable<Jsonb>, _>(candidate.as_ref())
        .execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn command(
    conn: &mut AsyncPgConnection,
    governor: &DidCoreId,
    intent: &Intent,
    command: Command,
    current: &coland_storage::ManagementReviewCurrent,
    ingress: &coland_storage::AppletConfigurationIngress,
) -> PersistenceResult<Outcome> {
    ingress.request.validate().map_err(invalid)?;
    if intent.originating_actor_id.as_account_id() != Some(&ingress.requester_account_id)
        || intent.service_id != ingress.request.intent.service_id
        || intent.request_id != ingress.request.intent.request_id
        || intent.effective_scope != ingress.request.intent.effective_scope
        || intent.selection != ingress.request.intent.selection
        || command != ingress.request.command
    {
        return Err(invalid(
            "configuration ingress differs from the original caller or request",
        ));
    }
    match &ingress.source {
        coland_storage::AppletConfigurationIngressSource::LocalSession
            if ingress.requester_account_id.station_id != *governor =>
        {
            return Err(invalid("foreign Account requires verified peer ingress"));
        }
        coland_storage::AppletConfigurationIngressSource::Peer(peer)
            if peer.source_service_id != ingress.requester_account_id.station_id =>
        {
            return Err(invalid(
                "configuration peer source differs from Account Station",
            ));
        }
        _ => {}
    }
    gate(conn, governor, intent, false, current).await?;
    let existing = read(conn, intent).await?;
    if existing.is_none()
        || (command == Command::Configure
            && existing.as_ref().is_some_and(|outcome| {
                matches!(
                    outcome.admission_status,
                    Admission::NotStarted | Admission::Pending
                )
            }))
    {
        gate(conn, governor, intent, true, current).await?;
    }
    let mut outcome = existing.unwrap_or(Outcome {
        request_id: intent.request_id.clone(),
        intent_digest: intent.digest().map_err(invalid)?,
        source_outcome: None,
        admission_status: Admission::NotStarted,
        review_request_id: None,
    });
    if let Some(review_id) = &outcome.review_request_id {
        #[derive(QueryableByName)]
        struct ReviewStatus {
            #[diesel(sql_type = Text)]
            status: String,
        }
        let status = sql_query("SELECT status FROM management_review_requests WHERE request_id=$1")
            .bind::<Text, _>(review_id.as_str())
            .get_result::<ReviewStatus>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        if matches!(
            outcome.admission_status,
            Admission::NotStarted | Admission::Pending
        ) && matches!(
            status.status.as_str(),
            "rejected" | "cancelled" | "expired" | "superseded"
        ) {
            outcome.admission_status = Admission::Denied;
        }
    }
    if command == Command::Cancel
        && matches!(
            outcome.admission_status,
            Admission::NotStarted | Admission::Pending
        )
    {
        outcome.admission_status = Admission::Cancelled;
    }
    write(conn, intent, &outcome, Some(ingress)).await?;
    Ok(outcome)
}

pub(crate) async fn source(
    conn: &mut AsyncPgConnection,
    governor: &DidCoreId,
    intent: &Intent,
    source: &Source,
    producer: &AppletEventProducerGuard,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<Outcome> {
    gate(conn, governor, intent, false, current).await?;
    source.validate_for(intent).map_err(invalid)?;
    if source.evaluated_at > chrono::Utc::now() {
        return Err(invalid("configuration outcome evaluation is in the future"));
    }
    let document = &producer.service_did_document;
    if arkret_wire::project_did_to_core_id(&document.id).map_err(invalid)? != intent.service_id {
        return Err(invalid("configuration outcome signer is another Service"));
    }
    arkret_identity::validate_verification_method_relationship(
        document,
        &source.proof.verification_method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(invalid)?;
    let key = arkret_identity::public_key_material_from_document(
        document,
        &source.proof.verification_method,
    )
    .map_err(invalid)?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &source.proof.jws,
            &source.signature_payload().map_err(invalid)?,
            &key,
        )
        .map_err(invalid)?;
    let mut outcome = read(conn, intent)
        .await?
        .ok_or_else(|| invalid("configuration result has no frozen administrator intent"))?;
    if let Some(original) = &outcome.source_outcome
        && arkret_canonical::canonical_json_bytes(original).map_err(invalid)?
            != arkret_canonical::canonical_json_bytes(source).map_err(invalid)?
        && original.status != SourceStatus::Pending
        && !(original.status == SourceStatus::Candidate
            && source.status == SourceStatus::Created
            && original.create_event.as_deref().is_some_and(|event| {
                source.creation_refs.as_ref().is_some_and(|refs| {
                    refs.as_slice()
                        .first()
                        .is_some_and(|reference| reference.event_id == event.event_id)
                })
            }))
    {
        return Err(invalid("configuration terminal source result changed"));
    }
    if let Some(event) = source.create_event.as_deref() {
        let original = sql_query("SELECT intent,outcome,candidate FROM applet_configurations WHERE realm_id=$1 AND request_id=$2 FOR UPDATE")
            .bind::<Text,_>(intent.effective_scope.realm_id().as_str()).bind::<Text,_>(intent.request_id.as_str())
            .get_result::<Row>(&mut *conn).await.map_err(PersistenceError::database)?;
        if original
            .candidate
            .as_ref()
            .is_some_and(|frozen| frozen != &serde_json::json!(event))
        {
            return Err(invalid(
                "configuration source changed the reviewed candidate",
            ));
        }
    }
    outcome.source_outcome = Some(source.clone());
    if matches!(
        outcome.admission_status,
        Admission::NotStarted | Admission::Pending
    ) {
        match source.status {
            SourceStatus::Denied => outcome.admission_status = Admission::Denied,
            SourceStatus::Cancelled => outcome.admission_status = Admission::Cancelled,
            _ => {}
        }
    }
    if let Some(event) = &source.create_event {
        if let Some(original) =
            crate::committed_disclosure::accepted_full_event_in_connection(conn, &event.event_id)
                .await?
        {
            if original.event != **event {
                return Err(invalid(
                    "configuration candidate differs from the accepted original",
                ));
            }
            outcome.admission_status = Admission::Accepted;
        } else if !matches!(
            outcome.admission_status,
            Admission::Cancelled | Admission::Denied
        ) {
            outcome.admission_status = Admission::Pending;
        }
    } else if matches!(source.status, SourceStatus::Created | SourceStatus::Reused) {
        let actor = source
            .actor_id
            .as_ref()
            .ok_or_else(|| invalid("accepted source omits actor"))?;
        let reference = source
            .creation_refs
            .as_ref()
            .and_then(|refs| refs.as_slice().first())
            .ok_or_else(|| invalid("accepted source omits original"))?;
        let original = crate::committed_disclosure::accepted_full_event_in_connection(
            conn,
            &reference.event_id,
        )
        .await?
        .ok_or_else(|| invalid("source creation is not accepted in this Realm"))?;
        let candidate = crate::realm_actor_control::creation(&original.event)?
            .ok_or_else(|| invalid("source reference is not an original creation"))?;
        if original.commit.commit_id != reference.commit_id
            || original.commit.stream_ref != reference.stream_ref
            || original.commit.stream_position != reference.stream_position
            || candidate.actor_id != *actor
            || candidate.applet_id != intent.applet_id
        {
            return Err(invalid("source accepted identity or Commit differs"));
        }
        let (manager, _) = crate::realm_actor_control::current_source(
            conn,
            actor,
            serde_json::json!({
                "kind": "realm_actor_manager", "actor_id": actor,
            }),
        )
        .await?;
        let manager: arkret_models_integration::RealmActorManagerValue =
            serde_json::from_value(manager).map_err(invalid)?;
        if manager.service_id != intent.service_id
            || manager.registration_ref != intent.registration_ref.event_id
        {
            return Err(invalid(
                "source identity is no longer managed by this installation",
            ));
        }
        if outcome.admission_status != Admission::Cancelled {
            outcome.admission_status = Admission::Accepted;
        }
    }
    write(conn, intent, &outcome, None).await?;
    Ok(outcome)
}

/// Called under the accepting transaction's Realm lock. Cancellation and a
/// successful original creation therefore cannot both win.
pub(crate) async fn require_candidate(
    conn: &mut AsyncPgConnection,
    event: &Event,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if let Some((intent, outcome, candidate)) = by_candidate(conn, &event.event_id).await? {
        if matches!(
            outcome.admission_status,
            Admission::Cancelled | Admission::Denied
        ) {
            return Err(invalid("configuration candidate was cancelled or denied"));
        }
        if candidate.as_ref() != Some(event) {
            return Err(invalid("configuration candidate bytes differ"));
        }
        let current = prepared
            .and_then(|prepared| prepared.management_current.as_ref())
            .ok_or_else(|| {
                invalid("configuration requires current administrator Account evidence")
            })?;
        crate::agent_management_review::require_current_accounts(
            conn,
            &event.realm_id,
            std::slice::from_ref(
                intent
                    .originating_actor_id
                    .as_account_id()
                    .ok_or_else(|| invalid("configuration original is not an Account"))?,
            ),
            current,
        )
        .await?;
        crate::agent_management_review::require_active_caller(
            &intent.originating_actor_id,
            current,
        )?;
        // The initial click is not a permanent authorization.
        let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
            conn,
            &event.realm_id,
            &intent.originating_actor_id,
        )
        .await?;
        if !cut.permits_unreserved_current_actions(
            &[CapabilityActionId::REALM_ADMIN],
            &WireResourceSelector::realm(event.realm_id.clone()),
            chrono::Utc::now(),
        ) {
            return Err(invalid(
                "configuration administrator no longer has authority",
            ));
        }
    }
    Ok(())
}

/// Read without locking before the shared ordered lock plan. The locked
/// admission path re-reads the exact binding and refuses missing observations.
pub(crate) async fn candidate_account(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> PersistenceResult<Option<arkret_wire::AccountId>> {
    if event.kind != arkret_wire::EventKind::RealmActorCreate {
        return Ok(None);
    }
    let row = sql_query(
        "SELECT intent,outcome,candidate FROM applet_configurations WHERE candidate_event_id=$1",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .get_result::<Row>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let intent: Intent = serde_json::from_value(row.intent).map_err(invalid)?;
    let outcome: Outcome = serde_json::from_value(row.outcome).map_err(invalid)?;
    if row.candidate.as_ref() != Some(&serde_json::to_value(event).map_err(invalid)?) {
        return Err(invalid("configuration candidate original differs"));
    }
    // An exact already-accepted replay has no new mutation to authorize.
    if outcome.admission_status == Admission::Accepted {
        return Ok(None);
    }
    Ok(Some(
        intent
            .originating_actor_id
            .as_account_id()
            .ok_or_else(|| invalid("configuration original is not an Account"))?
            .clone(),
    ))
}

async fn by_candidate(
    conn: &mut AsyncPgConnection,
    candidate: &EventId,
) -> PersistenceResult<Option<(Intent, Outcome, Option<Event>)>> {
    sql_query(
        "SELECT intent,outcome,candidate FROM applet_configurations WHERE candidate_event_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(candidate.as_str())
    .get_result::<Row>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(|row| {
        Ok((
            serde_json::from_value(row.intent).map_err(invalid)?,
            serde_json::from_value(row.outcome).map_err(invalid)?,
            row.candidate.map(serde_json::from_value).transpose().map_err(invalid)?,
        ))
    })
    .transpose()
}

pub(crate) async fn accepted(conn: &mut AsyncPgConnection, event: &Event) -> PersistenceResult<()> {
    if let Some((intent, mut outcome, _)) = by_candidate(conn, &event.event_id).await? {
        outcome.admission_status = Admission::Accepted;
        write(conn, &intent, &outcome, None).await?;
    }
    Ok(())
}

/// Authenticated Service preparation. The lookup discloses only the Account
/// bound to the exact private intent, never an arbitrary administrator roster.
async fn review_intent(
    conn: &mut AsyncPgConnection,
    request: &arkret_models_integration::ManagementReviewRequestBody,
) -> PersistenceResult<Option<Intent>> {
    let Some(reference) = &request.configuration_ref else {
        return Ok(None);
    };
    request.validate().map_err(invalid)?;
    let row = sql_query("SELECT intent,outcome,candidate FROM applet_configurations WHERE realm_id=$1 AND request_id=$2")
        .bind::<Text,_>(request.effective_scope.realm_id().as_str())
        .bind::<Text,_>(reference.request_id.as_str()).get_result::<Row>(conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| invalid("configuration review has no original intent"))?;
    let intent: Intent = serde_json::from_value(row.intent).map_err(invalid)?;
    let arkret_models_integration::ManagementReviewTarget::Event { event } = &request.target;
    let candidate: arkret_models_integration::RealmActorCreatePayload =
        serde_json::from_value(serde_json::json!(event.payload)).map_err(invalid)?;
    if intent.digest().map_err(invalid)? != reference.intent_digest
        || request.requester_actor_id != arkret_wire::ActorId::service(intent.service_id.clone())
        || request.effective_scope != intent.effective_scope
        || request.management_operation != arkret_wire::ManagementOperation::CreateBot
        || !matches!(
            intent.selection,
            arkret_models_integration::AppletConfigurationSelection::NewBot { .. }
        )
        || candidate.applet_id != intent.applet_id
        || candidate.service_id != intent.service_id
        || candidate.registration_ref != intent.registration_ref.event_id
        || candidate.creation_scope != intent.effective_scope
        || row
            .candidate
            .as_ref()
            .is_some_and(|frozen| frozen != &serde_json::json!(event))
    {
        return Err(invalid(
            "configuration review differs from the frozen intent or candidate",
        ));
    }
    Ok(Some(intent))
}

pub(crate) async fn review_account(
    conn: &mut AsyncPgConnection,
    request: &arkret_models_integration::ManagementReviewRequestBody,
) -> PersistenceResult<Option<arkret_wire::AccountId>> {
    review_intent(conn, request)
        .await?
        .map(|intent| {
            intent
                .originating_actor_id
                .as_account_id()
                .cloned()
                .ok_or_else(|| invalid("configuration original is not an Account"))
        })
        .transpose()
}

/// The Service-signed request binds the original candidate and real review in
/// one transaction. Failure of Policy evaluation rolls back both bindings.
pub(crate) async fn bind_review(
    conn: &mut AsyncPgConnection,
    request: &arkret_models_integration::ManagementReviewRequestBody,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<()> {
    let Some(intent) = review_intent(conn, request).await? else {
        return Ok(());
    };
    gate(conn, &current.station_id, &intent, true, current).await?;
    let mut outcome = read(conn, &intent)
        .await?
        .ok_or_else(|| invalid("configuration intent disappeared"))?;
    if matches!(
        outcome.admission_status,
        Admission::Cancelled | Admission::Denied | Admission::Accepted
    ) {
        return Err(invalid("configuration no longer accepts a new review"));
    }
    let review_id: arkret_wire::RequestId = request.request_id.parse().map_err(invalid)?;
    if outcome
        .review_request_id
        .as_ref()
        .is_some_and(|original| original != &review_id)
    {
        return Err(invalid("configuration already binds another review"));
    }
    let arkret_models_integration::ManagementReviewTarget::Event { event } = &request.target;
    let changed = sql_query("UPDATE applet_configurations SET candidate=$1,candidate_event_id=$2 WHERE realm_id=$3 AND request_id=$4 AND (candidate IS NULL OR candidate=$1)")
        .bind::<Jsonb,_>(serde_json::json!(event)).bind::<Text,_>(event.event_id.as_str())
        .bind::<Text,_>(intent.effective_scope.realm_id().as_str()).bind::<Text,_>(intent.request_id.as_str())
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(invalid("configuration candidate binding changed"));
    }
    outcome.review_request_id = Some(review_id);
    outcome.admission_status = Admission::Pending;
    write(conn, &intent, &outcome, None).await
}
