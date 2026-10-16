//! The closed local Applet authoring aggregate; no generic batch admission.
use arkret_models_collaboration::events_payloads::{
    ActorProfileCreatePayload, RealmGenesis, RealmPurpose,
};
use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityProjection,
};
use arkret_models_integration::{
    AppletManagedActorAuthoringBundle, AppletManagedActorAuthoringRequest,
    AppletManagedActorCommittedRequest, AppletManagedActorProvisionPayload, AppletManagedActorRole,
    AppletRegistrationEpochEvidence,
};
use arkret_wire::{
    ActorId, CommitStreamHead, CommitStreamRef, DidUrl, Event, EventKind, RealmCommit, RealmId,
    ScopeRef,
};
use coland_storage::{
    AppletAuthoringUnitOutcome, AppletAuthoringUnitWrite, AppletCommitAuthor,
    AppletResolutionAttester, AppletUnitFinalizer, AuthorityCommitTransaction,
    AuthorityCommitWriteOutcome, PersistenceError, PersistenceResult,
};

use super::{
    AsyncConnection, AsyncPgConnection, Binary, Jsonb, OptionalExtension, PgPool,
    PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz, Value, pg_conn, sql_query,
};

fn rejected(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {error}"))
}
fn signature_rejected(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("signature_invalid: {error}"))
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(rejected)
}
fn request(
    input: &coland_storage::AppletAuthoringCandidate,
) -> PersistenceResult<&AppletManagedActorAuthoringRequest> {
    match &input.request {
        coland_storage::AppletAdmissionRequest::Managed(
            AppletManagedActorCommittedRequest::Bot(body),
        ) => Ok(&body.authoring_request),
        coland_storage::AppletAdmissionRequest::Managed(
            AppletManagedActorCommittedRequest::Ghost(body),
        ) => Ok(&body.authoring_request),
        coland_storage::AppletAdmissionRequest::Install(_) => Err(rejected(
            "Service installation has no managed authoring request",
        )),
    }
}
fn bundle(
    input: &coland_storage::AppletAuthoringCandidate,
) -> Option<&AppletManagedActorAuthoringBundle> {
    match &input.request {
        coland_storage::AppletAdmissionRequest::Managed(
            AppletManagedActorCommittedRequest::Bot(body),
        ) => Some(&body.managed_actor_bundle),
        coland_storage::AppletAdmissionRequest::Managed(
            AppletManagedActorCommittedRequest::Ghost(body),
        ) => body.managed_actor_bundle.as_ref(),
        coland_storage::AppletAdmissionRequest::Install(_) => None,
    }
}
pub(crate) fn target_station(
    input: &coland_storage::AppletAuthoringCandidate,
) -> PersistenceResult<&arkret_wire::DidCoreId> {
    match &input.request {
        coland_storage::AppletAdmissionRequest::Install(body) => {
            Ok(&body.authoring_request_basis.target_station_id)
        }
        _ => Ok(request(input)?.basis.target_station_id()),
    }
}
pub(crate) fn effective_scope(
    input: &coland_storage::AppletAuthoringCandidate,
) -> PersistenceResult<&ScopeRef> {
    match &input.request {
        coland_storage::AppletAdmissionRequest::Install(body) => {
            Ok(&body.authoring_request_basis.effective_scope)
        }
        _ => {
            let req = request(input)?;
            req.basis
                .bot()
                .map(|b| &b.effective_scope)
                .or_else(|| req.basis.ghost().map(|b| &b.effective_scope))
                .ok_or_else(|| rejected("managed scope absent"))
        }
    }
}
fn controller(method: &DidUrl) -> PersistenceResult<arkret_wire::DidCoreId> {
    let full = method
        .as_str()
        .split_once('#')
        .ok_or_else(|| rejected("method has no fragment"))?
        .0;
    arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(full.to_owned()).map_err(rejected)?)
        .map_err(signature_rejected)
}
fn exact_ref(event: &Event, role: &str, target: &arkret_wire::EventId) -> bool {
    let refs: Vec<_> = event
        .semantic_refs
        .iter()
        .filter(|r| r.role == role)
        .collect();
    refs.len() == 1 && refs[0].critical && refs[0].id == target.as_str()
}
fn service_event(
    event: &Event,
    input: &coland_storage::AppletAuthoringCandidate,
) -> PersistenceResult<()> {
    event.validate_for_submit_structural().map_err(rejected)?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| rejected("unsigned managed Event"))?;
    if proof.verification_method != input.package.webhook_auth.key_ref
        || controller(&proof.verification_method)? != input.package.service_id
    {
        return Err(rejected(
            "managed producer is outside the exact Service epoch",
        ));
    }
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(rejected)?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(rejected)?;
    event
        .verify_producer_proof_self_consistency(suite)
        .map_err(rejected)?;
    let key = arkret_identity::public_key_material_from_document(
        &input.service_did_document,
        &proof.verification_method,
    )
    .map_err(rejected)?;
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(rejected)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        suite,
    )
    .map_err(signature_rejected)
}

pub(crate) struct ValidatedAppletUnit {
    pub events: Vec<Event>,
    pub portal_realm: RealmId,
    pub provision: Option<AppletManagedActorProvisionPayload>,
    pub managed_document: Option<arkret_identity::DidDocument>,
}

fn verify_package(
    input: &coland_storage::AppletAuthoringCandidate,
    epoch: &AppletRegistrationEpochEvidence,
) -> PersistenceResult<()> {
    input
        .package
        .validate_with_epoch_evidence(epoch)
        .map_err(rejected)?;
    let package_proof = input
        .package
        .proof
        .as_ref()
        .ok_or_else(|| rejected("package proof absent"))?;
    if controller(&package_proof.verification_method)? != input.package.controller_principal_id
        || arkret_wire::project_did_to_core_id(&input.controller_did_document.id)
            .map_err(rejected)?
            != input.package.controller_principal_id
    {
        return Err(rejected("package controller changed"));
    }
    let mut unsigned = input.package.clone();
    unsigned.proof = None;
    let package_bytes = arkret_canonical::canonical_json_bytes(&unsigned).map_err(rejected)?;
    if package_proof.payload_digest.as_str()
        != arkret_canonical::canonical::sha256_digest(&package_bytes)
    {
        return Err(rejected("package proof digest changed"));
    }
    arkret_identity::verify_jws_with_document(
        &package_bytes,
        &package_proof.jws,
        &package_proof.verification_method,
        &input.controller_did_document.id,
        &input.controller_did_document,
    )
    .map_err(signature_rejected)?;
    Ok(())
}

/// Verification is CPU work over receiver-owned public material. It returns
/// the original typed candidate result, never an authority boolean or cache.
pub(crate) async fn validate_candidate(
    input: &coland_storage::AppletAuthoringCandidate,
) -> PersistenceResult<ValidatedAppletUnit> {
    let input = Box::new(input.clone());
    tokio::task::spawn_blocking(move || validate_input(&input))
        .await
        .map_err(|error| {
            PersistenceError::Internal(format!("candidate verification task failed: {error}"))
        })?
}

pub(crate) fn validate_input(
    input: &coland_storage::AppletAuthoringCandidate,
) -> PersistenceResult<ValidatedAppletUnit> {
    if arkret_canonical::canonical_sha256(&input.request).map_err(rejected)?
        != input.canonical_request_hash.as_str()
    {
        return Err(rejected("canonical request identity changed"));
    }
    input.package.validate().map_err(rejected)?;
    if let coland_storage::AppletAdmissionRequest::Install(body) = &input.request {
        let basis = &body.authoring_request_basis;
        basis.validate().map_err(rejected)?;
        if body.applet_package != input.package {
            return Err(rejected("installation package mirror differs"));
        }
        let epoch: AppletRegistrationEpochEvidence = decode(
            basis
                .registration_event
                .payload
                .get("manifest")
                .and_then(|m| m.get("registration_epoch_evidence"))
                .cloned()
                .ok_or_else(|| rejected("registration epoch absent"))?,
        )?;
        if basis.install_actor_id != input.admin_actor_id
            || basis.applet_id != input.package.applet_id
            || basis.service_id != input.package.service_id
            || input.package.package_digest.as_ref() != Some(&basis.package_digest)
        {
            return Err(rejected("installation immutable basis changed"));
        }
        let plan = input
            .recomputed_install_plan
            .as_ref()
            .ok_or_else(|| rejected("fresh install plan absent"))?;
        if body.plan_digest != plan.plan_digest
            || plan.compute_plan_digest().map_err(rejected)? != plan.plan_digest
            || plan.applet_id != basis.applet_id
            || plan.package_digest != basis.package_digest
            || plan.effective_scope != basis.effective_scope
            || plan.registration_epoch != input.package.registration_epoch
            || !plan.namespace_conflicts.is_empty()
        {
            return Err(rejected("install plan differs from the signed request"));
        }
        let mut expected_resource = match &basis.effective_scope {
            ScopeRef::Realm { realm_id } => {
                arkret_wire::WireResourceSelector::realm(realm_id.clone())
            }
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => {
                let mut r =
                    arkret_wire::WireResourceSelector::circle(realm_id.clone(), circle_id.clone());
                r.match_scope = Some(arkret_wire::ResourceMatchScope::Exact);
                r
            }
            _ => return Err(rejected("unsupported install scope")),
        };
        let _ = &mut expected_resource;
        let mut unique_actions = std::collections::BTreeSet::new();
        for e in &basis.capability_grant_events {
            let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
                decode(serde_json::to_value(&e.payload).map_err(rejected)?)?;
            let g = payload.grant;
            if g.issuer_id!=input.admin_actor_id || g.realm_id.as_ref()!=Some(basis.effective_scope.realm_id()) || !matches!(g.subject,arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(ref actor) if actor==&applet_grant_subject(input)) || g.resources!=vec![expected_resource.clone()] || g.actions.is_empty() || g.constraints.iter().filter(|c|c.constraint_kind==arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::AuthorityControl && c.constraint_subkind==Some(arkret_models_collaboration::governance::grant_constraint::GrantConstraintSubkind::AppletAuthority) && c.applet_id.as_ref()==Some(&input.package.applet_id) && c.executed_by.as_ref()==Some(&ActorId::service(input.package.service_id.clone())) && c.registration_epoch.as_ref()==Some(&input.package.registration_epoch)).count()!=1 {return Err(rejected("staged grant immutable authority binding differs"));}
            for action in g.actions {
                if !input.package.requested_scopes.contains(&action)
                    || !unique_actions.insert(action)
                {
                    return Err(rejected(
                        "staged grant duplicates or exceeds package requests",
                    ));
                }
            }
        }
        let approved = plan
            .approved_scopes
            .iter()
            .flat_map(|scope| scope.actions.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>();
        if unique_actions != approved {
            return Err(rejected("staged grant differs from approved plan actions"));
        }
        let derived = input.package.to_registration(&epoch).map_err(rejected)?;
        if serde_json::to_value(derived).map_err(rejected)?
            != serde_json::to_value(&basis.registration_event.payload).map_err(rejected)?
        {
            return Err(rejected("registration differs from signed package"));
        }
        let mut events = vec![basis.registration_event.clone()];
        events.extend(basis.capability_grant_events.clone());
        if events.iter().any(|e| {
            e.actor_id != input.admin_actor_id
                || e.realm_id != *basis.effective_scope.realm_id()
                || e.scope_ref != basis.effective_scope
                || e.executed_by.is_some()
        }) {
            return Err(rejected("admin Event does not bind the installation scope"));
        }
        if events[0].kind != EventKind::AppletRegistration
            || events[1..]
                .iter()
                .any(|e| e.kind != EventKind::CapabilityGrant)
            || input.admin_producer_guards.len() != events.len()
        {
            return Err(rejected("admin fixed set or producer guards changed"));
        }
        epoch
            .validate_against_did_document(&input.service_did_document)
            .map_err(rejected)?;
        verify_package(input, &epoch)?;
        for event in &events {
            event.validate_for_submit_structural().map_err(rejected)?;
        }
        return Ok(ValidatedAppletUnit {
            events,
            portal_realm: basis.effective_scope.realm_id().clone(),
            provision: None,
            managed_document: None,
        });
    }
    let req = request(input)?;
    req.validate_bindings().map_err(rejected)?;
    if req.canonical_digest().map_err(rejected)? != input.request_digest
        || input.accepted_at >= req.expires_at
        || input.accepted_at < req.issued_at
        || req.proof.verification_method != input.station_verification_method
        || controller(&input.station_verification_method)? != req.governance_station_id
    {
        return Err(rejected("expired, replaced or differently signed preview"));
    }
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &req.proof.jws,
            &req.proof_binding_bytes().map_err(rejected)?,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: input.station_public_key.to_vec(),
            },
        )
        .map_err(signature_rejected)?;
    let epoch = if let Some(basis) = req.basis.bot() {
        if basis.applet_id != input.package.applet_id
            || basis.service_id != input.package.service_id
            || input.package.package_digest.as_ref() != Some(&basis.package_digest)
        {
            return Err(rejected("Bot immutable basis changed"));
        }
        basis.registration_epoch_evidence.clone()
    } else {
        let basis = req
            .basis
            .ghost()
            .ok_or_else(|| rejected("unknown authoring purpose"))?;
        if basis.applet_id != input.package.applet_id
            || basis.service_id != input.package.service_id
            || input.package.package_digest.as_ref() != Some(&basis.package_digest)
        {
            return Err(rejected("Ghost immutable basis changed"));
        }
        basis.registration_epoch_evidence.clone()
    };
    let portal = effective_scope(input)?.realm_id().clone();
    let mut events = vec![];
    epoch
        .validate_against_did_document(&input.service_did_document)
        .map_err(rejected)?;
    verify_package(input, &epoch)?;
    let Some(b) = bundle(input) else {
        if input.prior_managed_refs.len() != 4 {
            return Err(rejected("reuse accepted anchors absent"));
        }
        return Ok(ValidatedAppletUnit {
            events,
            portal_realm: portal,
            provision: None,
            managed_document: None,
        });
    };
    b.validate_bindings(req).map_err(rejected)?;
    if b.proof.verification_method != input.package.webhook_auth.key_ref
        || !epoch.contains_signing_key(b.proof.verification_method.as_str())
    {
        return Err(rejected("bundle proof outside epoch"));
    }
    arkret_identity::verify_jws_with_document(
        &b.proof_binding_bytes().map_err(rejected)?,
        &b.proof.jws,
        &b.proof.verification_method,
        &epoch.did,
        &input.service_did_document,
    )
    .map_err(signature_rejected)?;
    let provision: AppletManagedActorProvisionPayload =
        decode(serde_json::to_value(&b.managed_actor_provision_event.payload).map_err(rejected)?)?;
    provision.validate().map_err(rejected)?;
    let service = ActorId::service(input.package.service_id.clone());
    let role = if req.basis.bot().is_some() {
        AppletManagedActorRole::Bot
    } else {
        AppletManagedActorRole::Ghost
    };
    if provision.applet_id != input.package.applet_id
        || provision.service_id != input.package.service_id
        || provision.actor_role != role
        || provision.actor_id.route_service_id() != req.basis.target_station_id()
        || provision.actor_id.as_account_id().is_none()
        || provision.actor_id.signing_principal_id() == &input.package.controller_principal_id
    {
        return Err(rejected("managed Account identity changed"));
    }
    if let Some(basis) = req.basis.bot() {
        if provision.registration_ref != basis.registration_event_ref
            || provision.applet_authority_ref != basis.authorization_ref
            || provision.external_ref.is_some()
        {
            return Err(rejected("Bot exact authority binding changed"));
        }
    } else if let Some(basis) = req.basis.ghost()
        && (provision.registration_ref != basis.registration_event_ref
            || provision.applet_authority_ref != basis.authorization_ref
            || provision.external_ref.as_ref() != Some(&basis.external_ref))
    {
        return Err(rejected(
            "Ghost exact authority or external identity changed",
        ));
    }
    let genesis: RealmGenesis = decode(
        b.pcr_genesis_event
            .payload
            .get("object")
            .cloned()
            .ok_or_else(|| rejected("PCR object absent"))?,
    )?;
    if genesis.purpose != RealmPurpose::AppletManagedControl
        || genesis.initial_resolution.as_ref() != Some(&provision.initial_resolution)
        || genesis.governance_station_id != req.governance_station_id
        || b.pcr_genesis_event.realm_id != RealmId::from_event_id(&b.pcr_genesis_event.event_id)
        || !exact_ref(
            &b.pcr_genesis_event,
            "applet_managed_actor_provision",
            &b.managed_actor_provision_event.event_id,
        )
    {
        return Err(rejected("managed PCR founding closure changed"));
    }
    let four = [
        &b.managed_actor_provision_event,
        &b.pcr_genesis_event,
        &b.accountability_grant_event,
        &b.profile_event,
    ];
    let kinds = [
        EventKind::AppletManagedActorProvision,
        EventKind::RealmCreate,
        EventKind::IdentityAccountabilityGrant,
        EventKind::ProfileCreate,
    ];
    // Provision and accountability are portal-scoped; the Profile is
    // principal-scoped state in the managed actor's own PCR founded by index 1.
    let principal_control_realm = RealmId::from_event_id(&b.pcr_genesis_event.event_id);
    let creation_scope = effective_scope(input)?.clone();
    for (index, e) in four.iter().enumerate() {
        service_event(e, input)?;
        let expected_realm = match index {
            1 => None,
            3 => Some(&principal_control_realm),
            _ => Some(&portal),
        };
        if e.kind != kinds[index]
            || e.applet_id.as_ref() != Some(&provision.applet_id)
            || e.authorization_ref.as_deref() != Some(provision.applet_authority_ref.as_str())
            || e.created_at != req.issued_at
            || expected_realm.is_some_and(|realm| {
                &e.realm_id != realm
                    || e.scope_ref
                        != if index == 3 {
                            ScopeRef::Realm {
                                realm_id: realm.clone(),
                            }
                        } else {
                            creation_scope.clone()
                        }
            })
            || (index == 0 || index == 2) && (e.actor_id != service || e.executed_by.is_some())
            || (index == 1 || index == 3)
                && (e.actor_id != provision.actor_id || e.executed_by.as_ref() != Some(&service))
        {
            return Err(rejected(
                "four-Event producer, scope or authorization closure changed",
            ));
        }
    }
    if !exact_ref(
        &b.profile_event,
        "accountability",
        &b.accountability_grant_event.event_id,
    ) {
        return Err(rejected("Profile accountability anchor absent"));
    }
    let grant: AccountabilityGrantPayload =
        decode(serde_json::to_value(&b.accountability_grant_event.payload).map_err(rejected)?)?;
    grant
        .validate_lifecycle_at(input.accepted_at)
        .map_err(rejected)?;
    if grant.grant_status!=arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus::Active
        || grant.accountability_scope!=arkret_models_collaboration::governance::accountability::AccountabilityScope::Single(arkret_models_collaboration::governance::accountability::AccountabilityScopeKind::ContractedService)
        || grant.issuer_id != provision.service_id
        || grant.subject_id != *provision.actor_id.signing_principal_id()
        || grant.proof.verification_method != input.package.webhook_auth.key_ref
    {
        return Err(rejected("accountability issuer, subject or epoch changed"));
    }
    arkret_identity::verify_jws_with_document(
        &grant.canonical_proof_binding_bytes().map_err(rejected)?,
        &grant.proof.jws,
        &grant.proof.verification_method,
        &epoch.did,
        &input.service_did_document,
    )
    .map_err(signature_rejected)?;
    let profile: ActorProfileCreatePayload =
        decode(serde_json::to_value(&b.profile_event.payload).map_err(rejected)?)?;
    profile.object.validate().map_err(rejected)?;
    if let Some(value) = profile.object.profile_fields.get("applet_interaction") {
        let intent: arkret_models_identity::actor_profile::AppletInteractionIntent =
            decode(value.clone())?;
        if intent.mode == arkret_models_identity::actor_profile::AppletInteractionMode::Public {
            return Err(rejected(
                "initial managed Profile cannot publish a business service",
            ));
        }
        if intent.effective_scope != b.profile_event.scope_ref {
            return Err(rejected(
                "initial Profile interaction scope differs from its actual PCR Profile",
            ));
        }
    }
    let kind_matches = match role {
        AppletManagedActorRole::Bot => profile.object.actor_kind == arkret_wire::ActorKind::Bot,
        AppletManagedActorRole::Ghost => {
            profile.object.actor_kind == arkret_wire::ActorKind::Integration
        }
    };
    if profile.object.principal_id != *provision.actor_id.signing_principal_id()
        || !kind_matches
        || profile.object.accountable_principal_ids != vec![provision.service_id.clone()]
        || profile
            .object
            .profile_fields
            .get("managed_by_applet")
            .and_then(Value::as_str)
            != Some(provision.applet_id.as_str())
    {
        return Err(rejected(
            "managed Profile identity or accountability changed",
        ));
    }
    if let Some(external_ref) = provision.external_ref.as_ref() {
        let fields: arkret_models_integration::GhostActorProfileFields =
            arkret_models_integration::GhostActorProfileFields::from_profile_fields(
                &profile.object.profile_fields,
            )
            .map_err(rejected)?;
        if fields.external_ref != *external_ref || fields.managed_by_applet != provision.applet_id {
            return Err(rejected(
                "Ghost Profile external identity differs from its provision",
            ));
        }
    }
    let (_, logs, witnesses) = provision.method_history_evidence.webvh_material();
    let mut bytes = Vec::new();
    for l in logs {
        bytes.extend(arkret_canonical::canonical_json_bytes(l).map_err(rejected)?);
        bytes.push(b'\n');
    }
    let verified = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &provision.initial_resolution.did,
        &bytes,
        Some(&serde_json::to_vec(witnesses).map_err(rejected)?),
    )
    .map_err(rejected)?;
    let last = verified
        .log
        .raw_entries
        .last()
        .ok_or_else(|| rejected("empty managed DID history"))?;
    if verified.log.head_version_id != provision.initial_resolution.version_id
        || arkret_canonical::canonical_sha256(last).map_err(rejected)?
            != provision.initial_resolution.method_history_head
    {
        return Err(rejected("managed history terminal differs from provision"));
    }
    let managed_document: arkret_identity::DidDocument = decode(verified.log.head_state.clone())?;
    events.extend(four.into_iter().cloned());
    Ok(ValidatedAppletUnit {
        events,
        portal_realm: portal,
        provision: Some(provision),
        managed_document: Some(managed_document),
    })
}

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct CompletionRow {
    #[diesel(sql_type=Text)]
    canonical_request_hash: String,
    #[diesel(sql_type=Jsonb)]
    committed_event_refs: Value,
    #[diesel(sql_type=Jsonb)]
    response_body: Value,
}
#[derive(QueryableByName)]
struct PreviewRow {
    #[diesel(sql_type=Text)]
    request_digest: String,
    #[diesel(sql_type=Jsonb)]
    signed_request: Value,
    #[diesel(sql_type=Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}
pub(crate) async fn admit_authoring_unit(
    pool: &PgPool,
    mut input: AppletAuthoringUnitWrite,
    author: AppletCommitAuthor,
    attester: AppletResolutionAttester,
    finalize: AppletUnitFinalizer,
) -> PersistenceResult<AppletAuthoringUnitOutcome> {
    // The local observation becomes the one canonical acceptance instant
    // before any Commit is authored or same-cut evidence is evaluated.
    input.accepted_at = arkret_canonical::normalize_timestamp_canonical(input.accepted_at);
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    (*conn)
        .transaction::<_, PgTransactionError, _>(async move |conn| {
            Box::pin(admit_in_connection(
                conn, &input, &author, &attester, &finalize,
            ))
            .await
            .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
}
async fn accepted_pair(
    conn: &mut AsyncPgConnection,
    reference: &arkret_wire::CommittedEventRef,
) -> PersistenceResult<(Event, RealmCommit)> {
    #[derive(QueryableByName)]
    struct Pair {
        #[diesel(sql_type=Jsonb)]
        envelope: Value,
        #[diesel(sql_type=Jsonb)]
        commit_json: Value,
    }
    let row=sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND c.commit_id=$2 AND e.state='committed'")
        .bind::<Binary,_>(reference.event_id.token_bytes().to_vec())
        .bind::<Text,_>(reference.commit_id.as_str()).get_result::<Pair>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("prior accepted anchor missing"))?;
    let e: Event = decode(row.envelope)?;
    let c: RealmCommit = decode(row.commit_json)?;
    if e.event_id != reference.event_id
        || c.event_ref != reference.event_id
        || &c.realm_id != reference.stream_ref.realm_id()
        || c.stream_ref != reference.stream_ref
        || c.stream_position != reference.stream_position
    {
        return Err(rejected("prior accepted anchor misbinding"));
    }
    Ok((e, c))
}
async fn stream_head(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<Option<CommitStreamHead>> {
    stream_head_for(
        conn,
        &CommitStreamRef::Realm {
            realm_id: realm.clone(),
        },
    )
    .await
}
async fn stream_head_for(
    conn: &mut AsyncPgConnection,
    stream: &CommitStreamRef,
) -> PersistenceResult<Option<CommitStreamHead>> {
    let key = crate::authority_commit::stream_key(stream)?;
    let row=sql_query("SELECT commit_json AS value FROM realm_commits WHERE stream_key=$1 ORDER BY stream_position DESC LIMIT 1 FOR UPDATE")
        .bind::<Text,_>(key).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    row.map(|r| {
        let c: RealmCommit = decode(r.value)?;
        Ok(CommitStreamHead {
            stream_ref: c.stream_ref,
            stream_position: c.stream_position,
            commit_id: c.commit_id,
        })
    })
    .transpose()
}
async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringUnitWrite,
    author: &AppletCommitAuthor,
    attester: &AppletResolutionAttester,
    finalize: &AppletUnitFinalizer,
) -> PersistenceResult<AppletAuthoringUnitOutcome> {
    let operation = match &input.request {
        coland_storage::AppletAdmissionRequest::Install(_) => {
            arkret_wire::ServiceOperationId::SelfAppletCommandInstallV1
        }
        coland_storage::AppletAdmissionRequest::Managed(
            AppletManagedActorCommittedRequest::Bot(_),
        ) => arkret_wire::ServiceOperationId::SelfAppletBotCommandProvisionV1,
        coland_storage::AppletAdmissionRequest::Managed(
            AppletManagedActorCommittedRequest::Ghost(_),
        ) => arkret_wire::ServiceOperationId::SelfAppletGhostCommandProvisionV1,
    };
    if input.operation_id
        != operation
            .as_str()
            .strip_suffix(".v1")
            .ok_or_else(|| rejected("creation operation has no v1 identity"))?
    {
        return Err(rejected(
            "authoring operation differs from its original request purpose",
        ));
    }
    if arkret_canonical::canonical_sha256(&input.request).map_err(rejected)?
        != input.canonical_request_hash.as_str()
    {
        return Err(rejected(
            "exact retry request differs from its canonical identity",
        ));
    }
    let actor_key = input.admin_actor_id.canonical_key().map_err(rejected)?;
    let identity_lock = format!(
        "applet:{}:{}",
        input.package.applet_id,
        target_station(input)?
    );
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(&identity_lock)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let previous=sql_query("SELECT canonical_request_hash,committed_event_refs,response_body FROM applet_authoring_units WHERE actor_key=$1 AND operation_id=$2 AND idempotency_key=$3 FOR UPDATE")
        .bind::<Text,_>(&actor_key).bind::<Text,_>(&input.operation_id).bind::<Text,_>(&input.idempotency_key).get_result::<CompletionRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(row) = previous {
        if row.canonical_request_hash != input.canonical_request_hash.as_str() {
            return Err(rejected(
                "idempotency payload differs from first accepted request",
            ));
        }
        return Ok(AppletAuthoringUnitOutcome {
            committed_event_refs: decode(row.committed_event_refs)?,
            response_body: row.response_body,
            replayed: true,
        });
    }
    if matches!(
        &input.request,
        coland_storage::AppletAdmissionRequest::Managed(
            AppletManagedActorCommittedRequest::Ghost(body)
        ) if body.managed_actor_bundle.is_none()
    ) {
        // A mapping has no new Event identity. Its signed preview and complete
        // request identify the durable operation across HTTP retry keys.
        let previous = sql_query("SELECT canonical_request_hash,committed_event_refs,response_body FROM applet_authoring_units WHERE actor_key=$1 AND operation_id=$2 AND request_digest=$3 ORDER BY accepted_at LIMIT 1 FOR SHARE")
            .bind::<Text, _>(&actor_key)
            .bind::<Text, _>(&input.operation_id)
            .bind::<Text, _>(input.request_digest.as_str())
            .get_result::<CompletionRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        if let Some(row) = previous {
            if row.canonical_request_hash != input.canonical_request_hash.as_str() {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: accepted Ghost mapping request differs".to_owned(),
                ));
            }
            return Ok(AppletAuthoringUnitOutcome {
                committed_event_refs: decode(row.committed_event_refs)?,
                response_body: row.response_body,
                replayed: true,
            });
        }
    }
    if matches!(
        &input.request,
        coland_storage::AppletAdmissionRequest::Managed(_)
    ) {
        crate::agent_management_review::applet::lock_approval_accounts(
            conn,
            input,
            input.operation_approvals.as_ref(),
        )
        .await?;
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(
        conn,
        effective_scope(input)?.realm_id(),
    )
    .await?;
    let mut current_input = input.clone();
    current_input.accepted_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let input = &current_input;
    let mut validated = validate_candidate(input).await?;
    let managed_request = match &input.request {
        coland_storage::AppletAdmissionRequest::Install(_) => None,
        _ => Some(request(input)?),
    };
    if let Some(req) = managed_request {
        let preview=sql_query("SELECT request_digest,signed_request,expires_at FROM applet_authoring_previews WHERE subject_key=$1 AND status='current' FOR UPDATE")
            .bind::<Text,_>(&input.preview_subject_key).get_result::<PreviewRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("issued preview missing"))?;
        if preview.request_digest != input.request_digest.as_str()
            || preview.signed_request != serde_json::to_value(req).map_err(rejected)?
            || input.accepted_at >= preview.expires_at
        {
            return Err(rejected("issued preview was replaced or expired"));
        }
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &validated.portal_realm)
        .await?;
    let admin_count = input.admin_producer_guards.len();
    if admin_count > 0 {
        let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
            conn,
            &validated.portal_realm,
            &input.admin_actor_id,
        )
        .await?;
        cut.require_open_lifecycle(&validated.events[0])?;
        if !cut.actor_is_root_controller()
            && !cut.grants_cover_any(
                &[arkret_wire::CapabilityActionId::REALM_ADMIN],
                input.accepted_at,
            )
        {
            return Err(rejected("applet_registration_unauthorized"));
        }
        for (e, guard) in validated.events[..admin_count]
            .iter()
            .zip(&input.admin_producer_guards)
        {
            crate::authority_commit::check_self_producer_guard_in_connection(
                conn,
                e,
                guard,
                input.accepted_at,
            )
            .await?;
            verify_admin_producer(conn, e, guard, input.accepted_at).await?;
        }
    }
    if admin_count == 0 {
        validate_managed_current(conn, input, &mut validated).await?;
    }
    let management_qualified = if admin_count == 0 {
        Box::pin(crate::agent_management_review::applet::prepare_admission(
            conn,
            input,
            &validated,
            input.operation_approvals.as_ref(),
            input.accepted_at,
        ))
        .await?
    } else {
        if input.operation_approvals.is_some() {
            return Err(rejected("install does not accept management approval"));
        }
        Vec::new()
    };
    let provision = validated.provision.as_ref();
    let mut action_qualified = Vec::new();
    if admin_count == 0 {
        let authority =
            crate::applet_action_approval::CreationAuthority::read(conn, input, &validated).await?;
        let (reservations, qualified) =
            crate::boxed_future(|| authority.admit(conn, input.operation_approvals.as_ref()))
                .await?;
        action_qualified = qualified;
        if let Some(bundle) = bundle(input) {
            // Identity creation and its quota share this aggregate transaction.
            // The accepted provision is the operation identity, independent of
            // HTTP retry keys; rollback restores every reservation on failure.
            if !crate::capability_quota::try_reserve_in_connection(
                conn,
                &reservations,
                bundle.managed_actor_provision_event.event_id.as_str(),
            )
            .await?
            {
                return Err(PersistenceError::Conflict(
                    "rate_limited: managed creation quota is exhausted".to_owned(),
                ));
            }
        } else {
            // Reserve only the current mapping grant. The original accepted
            // provision's creation grant and Event are never consumed again.
            let operation_identity = format!("applet-ghost-map:{}", input.canonical_request_hash);
            if !crate::capability_quota::try_reserve_in_connection(
                conn,
                &reservations,
                &operation_identity,
            )
            .await?
            {
                return Err(PersistenceError::Conflict(
                    "rate_limited: Ghost mapping quota is exhausted".to_owned(),
                ));
            }
        }
    }
    let mut refs = if admin_count == 0 && bundle(input).is_none() {
        input.prior_managed_refs.clone()
    } else {
        Vec::new()
    };
    for (index, event) in validated.events.iter().enumerate() {
        if index == admin_count && bundle(input).is_some() {
            require_exact_service_grant(
                conn,
                input,
                provision.ok_or_else(|| rejected("managed provision absent"))?,
                &validated.portal_realm,
            )
            .await?;
        }
        if event.kind == EventKind::RealmCreate {
            let authority_ref =
                arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
            let inserted=sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref,last_handoff_ref) VALUES($1,0,$2,$3,NULL) ON CONFLICT DO NOTHING")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(target_station(input)?.as_str()).bind::<Jsonb,_>(serde_json::to_value(authority_ref).map_err(rejected)?).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            if inserted != 1 {
                return Err(rejected("managed PCR already exists"));
            }
        }
        let authority = crate::authority_commit::locked_authority(conn, &event.realm_id)
            .await
            .map_err(PgTransactionError::into_persistence)?
            .ok_or_else(|| rejected("local current authority unavailable"))?;
        if authority.service_id != *target_station(input)? {
            return Err(rejected("authoring unit crosses sovereign Stations"));
        }
        let stream = CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
            .map_err(rejected)?;
        let head = stream_head_for(conn, &stream).await?;
        // Native installation does not exempt its ordinary Human members from
        // the original signer-fact contract. Freeze under this same locked cut,
        // bind it before Commit ID/signature, and archive only with acceptance.
        let producer_signer_fact = Box::pin(
            crate::agent_producer_signer_keys::prepare_local_account_device_source_in_connection(
                conn,
                event,
                input.accepted_at,
            ),
        )
        .await?;
        let candidate = producer_signer_fact.clone().map(Into::into);
        let device_core = if let Some(fact) = producer_signer_fact.as_ref() {
            Some(
                crate::account_device_committed_evidence::prepare_core(
                    conn,
                    event,
                    fact,
                    input.accepted_at,
                    target_station(input)?,
                )
                .await?,
            )
        } else {
            None
        };
        let (commit, device_evidence) = author(
            event,
            &authority,
            head.as_ref(),
            input.accepted_at,
            candidate.as_ref(),
            device_core.as_ref(),
        )?;
        crate::account_device_committed_evidence::validate(
            event,
            &commit,
            producer_signer_fact.as_ref(),
            device_evidence.as_ref(),
        )?;
        crate::agent_producer_signer_keys::validate_account_device_fact_binding(
            event,
            &commit,
            producer_signer_fact.as_ref(),
        )?;
        let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: input.station_public_key.to_vec(),
        };
        if commit.signature.verification_method != input.station_verification_method
            || commit.committed_at != input.accepted_at
        {
            return Err(rejected(
                "covering Commit changed Station or acceptance instant",
            ));
        }
        arkret_signatures::detached_object::verify_detached_object_signature(
            &commit.signature,
            &arkret_canonical::unsigned_value(&commit, &["signature"])
                .map_err(signature_rejected)?,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &material,
        )
        .map_err(signature_rejected)?;
        let transaction = AuthorityCommitTransaction {
            expected_authority: authority,
            event: event.clone(),
            commit: commit.clone(),
            producer_signer_fact: candidate,
            mls_state: None,
            welcomes: vec![],
            recipient_queue_capacity: 0,
        };
        crate::authority_commit::queue_event_in_connection(conn, event, input.accepted_at)
            .await
            .map_err(PgTransactionError::into_persistence)?;
        if !matches!(
            crate::authority_commit::commit_verified_applet_in_connection(conn, &transaction)
                .await
                .map_err(PgTransactionError::into_persistence)?,
            AuthorityCommitWriteOutcome::Committed
        ) {
            return Err(rejected("Applet Event was accepted outside this aggregate"));
        }
        if let Some(fact) = producer_signer_fact.as_ref() {
            crate::agent_producer_signer_keys::retain_prepared_account_device_in_connection(
                conn, event, &commit, fact,
            )
            .await?;
            crate::account_device_committed_evidence::retain(
                conn,
                &commit,
                fact,
                device_evidence
                    .as_ref()
                    .ok_or_else(|| rejected("original Device evidence absent"))?,
            )
            .await?;
        }
        if event.kind == EventKind::CapabilityGrant {
            crate::capability_grant_current_results::commit_capability_grant_current_result_in_connection(conn,event,&commit, None).await?;
        }
        crate::applet_current_results::project_applet_event_in_connection(
            conn, event, &commit, provision,
        )
        .await?;
        if event.kind == EventKind::IdentityAccountabilityGrant {
            let payload: AccountabilityGrantPayload =
                decode(serde_json::to_value(&event.payload).map_err(rejected)?)?;
            crate::actor_profiles::write_identity_accountability_in_connection(
                conn,
                &event.realm_id,
                &commit,
                &AccountabilityProjection::from_grant(&payload).map_err(rejected)?,
            )
            .await
            .map_err(PgTransactionError::into_persistence)?;
        }
        if event.kind == EventKind::ProfileCreate {
            let payload: ActorProfileCreatePayload =
                decode(serde_json::to_value(&event.payload).map_err(rejected)?)?;
            let profile = payload.materialize(event).map_err(rejected)?;
            if !crate::actor_profiles::accountability_holds_in_connection(
                conn,
                &profile.accountable_principal_ids,
                &profile.principal_id,
                input.accepted_at,
            )
            .await
            .map_err(PgTransactionError::into_persistence)?
            {
                return Err(rejected("accepted accountability closure missing"));
            }
            crate::actor_profiles::write_profile_current_in_connection(
                conn, event, &commit, &profile,
            )
            .await
            .map_err(PgTransactionError::into_persistence)?;
        }
        let _ = index;
        refs.push(arkret_wire::CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: commit.commit_id,
            stream_ref: commit.stream_ref,
            stream_position: commit.stream_position,
        });
    }
    let finalization = finalize(&refs)?;
    validate_finalized_refs(input, &refs, provision, &finalization.response_body)?;
    if finalization.applet_record.applet_id != input.package.applet_id
        || finalization.applet_record.expected_record != input.expected_installation
        || finalization.applet_record.identity.expected_record != input.expected_identity
        || finalization.idempotency_record.authenticated_actor != input.admin_actor_id
        || finalization.idempotency_record.operation_id != input.operation_id
        || finalization.idempotency_record.idempotency_key != input.idempotency_key
        || finalization.idempotency_record.request_hash != input.canonical_request_hash.as_str()
        || finalization.idempotency_record.response_body != finalization.response_body
    {
        return Err(rejected("finalization changed immutable request bindings"));
    }
    crate::unit_of_work::commit_applet_record(conn, finalization.applet_record).await?;
    crate::idempotency::record_idempotency_in_connection(conn, &finalization.idempotency_record)
        .await?;
    let context_json = if managed_request.is_some() && bundle(input).is_some() {
        let provision = provision.ok_or_else(|| rejected("managed provision absent"))?;
        require_current_managed_method(conn, provision, input.accepted_at).await?;
        let portal_head = stream_head(conn, &validated.portal_realm)
            .await?
            .ok_or_else(|| rejected("accepted Portal head unavailable"))?;
        let managed_document = if let Some(doc) = validated.managed_document.as_ref() {
            doc.clone()
        } else {
            verified_managed_document(provision)?
        };
        let (managed_vm, managed_key) =
            managed_signing_key(provision, &managed_document, input.accepted_at)?;
        let context = Box::pin(
            crate::applet_authoring_context::materialize_context_in_connection(
                conn,
                input,
                &portal_head,
                provision,
                &managed_vm,
                &managed_key,
                attester,
            ),
        )
        .await?;
        sql_query("UPDATE applet_authoring_previews SET status='committed',committed_at=$3 WHERE subject_key=$1 AND request_digest=$2 AND status='current'")
        .bind::<Text,_>(&input.preview_subject_key).bind::<Text,_>(input.request_digest.as_str()).bind::<Timestamptz,_>(input.accepted_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        serde_json::to_value(context).map_err(rejected)?
    } else {
        Value::Null
    };
    if managed_request.is_some() && bundle(input).is_none() {
        sql_query("UPDATE applet_authoring_previews SET status='committed',committed_at=$3 WHERE subject_key=$1 AND request_digest=$2 AND status='current'")
            .bind::<Text,_>(&input.preview_subject_key).bind::<Text,_>(input.request_digest.as_str()).bind::<Timestamptz,_>(input.accepted_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    }
    crate::applet_action_approval::consume(
        conn,
        input,
        &action_qualified,
        &refs,
        &finalization.response_body,
    )
    .await?;
    crate::agent_management_review::applet::consume(
        conn,
        input,
        &management_qualified,
        &refs,
        &finalization.response_body,
    )
    .await?;
    sql_query("INSERT INTO applet_authoring_units(actor_key,operation_id,idempotency_key,canonical_request_hash,request_digest,committed_event_refs,response_body,request_body,authoring_context,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind::<Text,_>(&actor_key).bind::<Text,_>(&input.operation_id).bind::<Text,_>(&input.idempotency_key).bind::<Text,_>(input.canonical_request_hash.as_str()).bind::<Text,_>(input.request_digest.as_str()).bind::<Jsonb,_>(serde_json::to_value(&refs).map_err(rejected)?).bind::<Jsonb,_>(&finalization.response_body).bind::<Jsonb,_>(serde_json::to_value(&input.request).map_err(rejected)?).bind::<Jsonb,_>(context_json).bind::<Timestamptz,_>(input.accepted_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(AppletAuthoringUnitOutcome {
        committed_event_refs: refs,
        response_body: finalization.response_body,
        replayed: false,
    })
}

fn verified_managed_document(
    provision: &AppletManagedActorProvisionPayload,
) -> PersistenceResult<arkret_identity::DidDocument> {
    let (_, logs, witnesses) = provision.method_history_evidence.webvh_material();
    let mut bytes = Vec::new();
    for l in logs {
        bytes.extend(arkret_canonical::canonical_json_bytes(l).map_err(rejected)?);
        bytes.push(b'\n');
    }
    let verified = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &provision.initial_resolution.did,
        &bytes,
        Some(&serde_json::to_vec(witnesses).map_err(rejected)?),
    )
    .map_err(rejected)?;
    if verified.log.head_version_id != provision.initial_resolution.version_id
        || arkret_canonical::canonical_sha256(
            verified
                .log
                .raw_entries
                .last()
                .ok_or_else(|| rejected("empty method history"))?,
        )
        .map_err(rejected)?
            != provision.initial_resolution.method_history_head
    {
        return Err(rejected(
            "managed method history differs from accepted provision",
        ));
    }
    decode(verified.log.head_state)
}
fn managed_signing_key(
    provision: &AppletManagedActorProvisionPayload,
    document: &arkret_identity::DidDocument,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<(DidUrl, [u8; 32])> {
    // Principal evidence binds method-native control material. A managed
    // principal's valid document need not expose any ordinary signing method.
    let (_, logs, _) = provision.method_history_evidence.webvh_material();
    let point = arkret_signatures::webvh::validate_webvh_history_at(
        &provision.initial_resolution.did,
        logs,
        at,
    )
    .map_err(rejected)?;
    let selected_document: arkret_identity::DidDocument = decode(point.document)?;
    if point.did != provision.initial_resolution.did
        || point.version_id != provision.initial_resolution.version_id
        || &selected_document != document
    {
        return Err(rejected(
            "managed Principal control material differs from the verified exact method head",
        ));
    }
    let key = arkret_canonical::decode_ed25519_multibase(&point.active_update_key_multibase)
        .map_err(rejected)?;
    let method = DidUrl::new(format!(
        "did:key:{0}#{0}",
        point.active_update_key_multibase
    ))
    .map_err(rejected)?;
    Ok((method, key))
}

async fn verify_admin_producer(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &coland_storage::SelfProducerCommitGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if controller(
        &event
            .producer_proof
            .as_ref()
            .ok_or_else(|| signature_rejected("unsigned admin Event"))?
            .verification_method,
    )? != *event.actor_id.signing_principal_id()
    {
        return Err(signature_rejected(
            "admin method belongs to another signing principal",
        ));
    }
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(rejected)?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(rejected)?;
    match guard {
        coland_storage::SelfProducerCommitGuard::MimiFacade { .. } => {
            return Err(rejected("MIMI facade is not an Applet admin producer"));
        }
        coland_storage::SelfProducerCommitGuard::HumanDevice(selector)
        | coland_storage::SelfProducerCommitGuard::HumanDeviceEvidence { selector, .. } => {
            let account = event
                .actor_id
                .as_account_id()
                .ok_or_else(|| rejected("admin producer is not a full Account"))?;
            let device =
                arkret_wire::DeviceId::new(selector.device_id.clone()).map_err(rejected)?;
            crate::actor_profiles::verify_device_signer_in_connection(
                conn,
                event,
                account,
                &device,
                selector.authorization_ref.stream_ref.realm_id(),
                at,
                suite,
                "Applet admin",
            )
            .await
            .map_err(PgTransactionError::into_persistence)?;
        }
        coland_storage::SelfProducerCommitGuard::Agent {
            authorization_ref, ..
        } => {
            let (source, _) = accepted_pair(conn, authorization_ref).await?;
            let payload:arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload=decode(serde_json::to_value(&source.payload).map_err(rejected)?)?;
            let bytes = arkret_canonical::base64url_decode(payload.public_key.key.as_str())
                .map_err(rejected)?;
            let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes };
            arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
                event
                    .producer_proof
                    .as_ref()
                    .ok_or_else(|| rejected("unsigned admin"))?,
                &arkret_signatures::EventProofBuilder::new()
                    .envelope_bytes(event)
                    .map_err(signature_rejected)?,
                &event.actor_id,
                &material,
                suite,
            )
            .map_err(signature_rejected)?;
        }
    }
    Ok(())
}

async fn require_current_managed_method(
    conn: &mut AsyncPgConnection,
    provision: &AppletManagedActorProvisionPayload,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    #[derive(QueryableByName)]
    struct CurrentMethodRow {
        #[diesel(sql_type=Jsonb)]
        did_document: Value,
        #[diesel(sql_type=super::Nullable<Text>)]
        key_log_head: Option<String>,
        #[diesel(sql_type=Timestamptz)]
        expires_at: chrono::DateTime<chrono::Utc>,
    }
    let row = sql_query(
        "SELECT did_document,key_log_head,expires_at FROM webvh_documents WHERE id=$1 FOR SHARE",
    )
    .bind::<Text, _>(provision.initial_resolution.did.as_str())
    .get_result::<CurrentMethodRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| rejected("managed DID has no trusted current method state"))?;
    let stored: arkret_identity::DidDocument = decode(row.did_document)?;
    let verified = verified_managed_document(provision)?;
    if row.expires_at <= at
        || row.key_log_head.as_deref()
            != Some(provision.initial_resolution.method_history_head.as_str())
        || arkret_models_identity::did_document::normalized_did_document_digest(&stored)
            .map_err(rejected)?
            != arkret_models_identity::did_document::normalized_did_document_digest(&verified)
                .map_err(rejected)?
    {
        return Err(rejected(
            "managed DID history is not the fresh accepted method head",
        ));
    }
    Ok(())
}
fn validate_finalized_refs(
    input: &AppletAuthoringUnitWrite,
    refs: &[arkret_wire::CommittedEventRef],
    provision: Option<&AppletManagedActorProvisionPayload>,
    response: &Value,
) -> PersistenceResult<()> {
    match &input.request {
        coland_storage::AppletAdmissionRequest::Install(body) => {
            let outcome: arkret_models_integration::AppletInstallOutcome =
                decode(response.clone())?;
            let grants = body
                .authoring_request_basis
                .capability_grant_events
                .iter()
                .map(|e| arkret_wire::GrantId::from_event_id(&e.event_id))
                .collect::<Vec<_>>();
            if refs.first().map(|r| &r.event_id) != Some(&outcome.registration_event_ref)
                || refs.len() != 1 + grants.len()
                || outcome.applet_id != input.package.applet_id
                || outcome.registration_epoch != input.package.registration_epoch
                || outcome.capability_grant_refs != grants
                || !outcome.e2ee_authorization_refs.is_empty()
                || outcome.widget_policy_ref.is_some()
            {
                return Err(rejected(
                    "Service install outcome fabricates managed anchors",
                ));
            }
        }
        coland_storage::AppletAdmissionRequest::Managed(body) => {
            let p = provision.ok_or_else(|| rejected("managed provision absent"))?;
            let (actor, provision_ref, pcr, accountability, profile, authorization) = match body {
                AppletManagedActorCommittedRequest::Bot(_) => {
                    let o: arkret_models_integration::AppletBotProvisionOutcome =
                        decode(response.clone())?;
                    (
                        o.bot_actor_id,
                        o.managed_actor_provision_ref,
                        o.principal_control_realm_id,
                        o.accountability_grant_ref,
                        o.profile_event_ref,
                        o.authorization_ref,
                    )
                }
                AppletManagedActorCommittedRequest::Ghost(_) => {
                    let o: arkret_models_integration::GhostActorProvisionOutcome =
                        decode(response.clone())?;
                    (
                        o.ghost_actor_id,
                        o.managed_actor_provision_ref,
                        o.principal_control_realm_id,
                        o.accountability_grant_ref,
                        o.profile_event_ref,
                        o.authorization_ref,
                    )
                }
            };
            if refs.len() != 4
                || provision_ref != refs[0].event_id
                || &pcr != refs[1].stream_ref.realm_id()
                || accountability != refs[2].event_id
                || profile != refs[3].event_id
                || actor != p.actor_id
                || authorization != creation_authorization_ref(input, p)?
            {
                return Err(rejected("managed outcome fabricates accepted anchors"));
            }
        }
    }
    Ok(())
}

pub(crate) async fn require_exact_service_grant(
    conn: &mut AsyncPgConnection,
    input: &coland_storage::AppletAuthoringCandidate,
    provision: &AppletManagedActorProvisionPayload,
    realm: &RealmId,
) -> PersistenceResult<Option<arkret_models_integration::AppletRegistrationPayload>> {
    let actor = applet_grant_subject(input);
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, realm, &actor).await?;
    let creation_authority = creation_authorization_ref(input, provision)?;
    let grant = cut
        .effective_grants(input.accepted_at)
        .find(|(id, _)| *id == &creation_authority)
        .map(|(_, g)| g)
        .ok_or_else(|| rejected("exact Applet grant is not active at this accepted cut"))?;
    let bindings=grant.constraints.iter().filter(|c|c.constraint_kind==arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::AuthorityControl && c.constraint_subkind==Some(arkret_models_collaboration::governance::grant_constraint::GrantConstraintSubkind::AppletAuthority)).collect::<Vec<_>>();
    if bindings.len() != 1
        || bindings[0].applet_id.as_ref() != Some(&input.package.applet_id)
        || bindings[0].executed_by.as_ref() != Some(&ActorId::service(provision.service_id.clone()))
        || bindings[0].registration_epoch.as_ref() != Some(&input.package.registration_epoch)
    {
        return Err(rejected("exact grant epoch or executor binding differs"));
    }
    let req = request(input)?;
    let (epoch, registration_ref) = if let Some(basis) = req.basis.bot() {
        (
            &basis.registration_epoch_evidence,
            &basis.registration_event_ref,
        )
    } else {
        let basis = req
            .basis
            .ghost()
            .ok_or_else(|| rejected("creation basis absent"))?;
        (
            &basis.registration_epoch_evidence,
            &basis.registration_event_ref,
        )
    };
    #[derive(QueryableByName)]
    struct RegistrationRow {
        #[diesel(sql_type=Jsonb)]
        value: Value,
    }
    // Compare the accepted instance, rather than the latest Event reference:
    // independent scopes may reassert an identical security snapshot. The
    // projection rotates this provenance on replacement and never revives it.
    let registration=sql_query("SELECT r.value FROM applet_registration_current_results r JOIN applet_registration_instances a ON a.realm_id=r.realm_id AND a.applet_id=r.applet_id AND a.instance_event_ref=r.instance_event_ref JOIN realm_commits c ON c.commit_id=a.accepted_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE r.realm_id=$1 AND r.applet_id=$2 AND a.registration_event_ref=$3 AND e.id=$4 AND e.state='committed' AND e.kind='ak.applet.registration' AND e.envelope->'scope_ref'=$5 AND ((e.envelope->'payload') - 'proof')=(r.value - 'proof')")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(input.package.applet_id.as_str())
        .bind::<Text,_>(registration_ref.as_str()).bind::<Binary,_>(registration_ref.token_bytes().to_vec())
        .bind::<Jsonb,_>(serde_json::to_value(effective_scope(input)?).map_err(rejected)?)
        .get_result::<RegistrationRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||rejected("accepted Applet registration instance was replaced or scope differs"))?;
    let expected = serde_json::to_value(input.package.to_registration(epoch).map_err(rejected)?)
        .map_err(rejected)?;
    if crate::applet_current_results::registration_security_value(&registration.value)
        != crate::applet_current_results::registration_security_value(&expected)
    {
        return Err(rejected(
            "active registration security snapshot differs from the managed basis",
        ));
    }
    let accepted_registration = Some(decode(registration.value)?);
    if provision.actor_role == AppletManagedActorRole::Ghost
        && !input.package.namespaces.actors.is_empty()
        && !input.package.namespaces.actors.iter().any(|n| {
            arkret_models_integration::namespace_pattern_matches(
                arkret_models_integration::AppletNamespaceDomain::Actors,
                &n.pattern,
                provision.initial_resolution.did.as_str(),
            )
        })
    {
        return Err(rejected("applet_namespace_mismatch"));
    }
    Ok(accepted_registration)
}

pub(crate) fn creation_authorization_ref(
    input: &coland_storage::AppletAuthoringCandidate,
    provision: &AppletManagedActorProvisionPayload,
) -> PersistenceResult<arkret_wire::GrantId> {
    if bundle(input).is_none() {
        return request(input)?
            .basis
            .ghost()
            .map(|basis| basis.authorization_ref.clone())
            .ok_or_else(|| rejected("mapping authority absent"));
    }
    Ok(provision.applet_authority_ref.clone())
}

fn applet_grant_subject(input: &coland_storage::AppletAuthoringCandidate) -> ActorId {
    ActorId::service(input.package.service_id.clone())
}

async fn verify_prior_service_event(
    conn: &mut AsyncPgConnection,
    event: &Event,
    input: &coland_storage::AppletAuthoringCandidate,
    provision_id: &arkret_wire::EventId,
) -> PersistenceResult<()> {
    let row=sql_query("SELECT context AS value FROM applet_authoring_completions WHERE applet_id=$1 AND context#>>'{committed_request,managed_actor_bundle,managed_actor_provision_event,event_id}'=$2")
        .bind::<Text,_>(input.package.applet_id.as_str()).bind::<Text,_>(provision_id.as_str()).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("original accepted Applet signer closure absent"))?;
    let context: arkret_models_integration::AppletManagedActorAuthoringContext = decode(row.value)?;
    context.validate().map_err(rejected)?;
    let evidence = &context
        .applet_service_signer_evidence
        .authenticated_signer_evidence;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| rejected("prior Event proof absent"))?;
    if evidence.subject_id != input.package.service_id
        || proof.verification_method != evidence.verification_method
        || input
            .prior_service_signer_evidence
            .as_ref()
            .is_some_and(|provided| {
                serde_json::to_value(provided).ok()
                    != serde_json::to_value(&context.applet_service_signer_evidence).ok()
            })
    {
        return Err(rejected("prior exact Service root differs"));
    }
    let jwk = evidence.public_key_jwk.as_map();
    if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
    {
        return Err(rejected("prior Service root is not Ed25519"));
    }
    let raw = arkret_canonical::base64url_decode(
        jwk.get("x")
            .and_then(Value::as_str)
            .ok_or_else(|| rejected("prior Service root has no key"))?,
    )
    .map_err(rejected)?;
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(rejected)?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(rejected)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(event)
            .map_err(rejected)?,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes: raw },
        suite,
    )
    .map_err(signature_rejected)
}

/// Same-cut managed provenance and collision checks, without business writes.
pub(crate) async fn validate_managed_current(
    conn: &mut AsyncPgConnection,
    input: &coland_storage::AppletAuthoringCandidate,
    validated: &mut ValidatedAppletUnit,
) -> PersistenceResult<()> {
    if validated.provision.is_none() {
        let body = match &input.request {
            coland_storage::AppletAdmissionRequest::Managed(
                AppletManagedActorCommittedRequest::Ghost(body),
            ) => body,
            _ => return Err(rejected("only Ghost mapping can reuse accepted provenance")),
        };
        body.validate().map_err(rejected)?;
        let basis = body
            .authoring_basis()
            .ok_or_else(|| rejected("reuse Ghost basis absent"))?;
        let existing = body
            .existing_managed_actor
            .as_ref()
            .ok_or_else(|| rejected("reuse anchors absent"))?;
        if basis.existing_managed_actor.as_ref() != Some(existing)
            || input.prior_managed_refs.len() != 4
        {
            return Err(rejected(
                "reuse anchors differ from the signed current preview",
            ));
        }
        let mut prior = Vec::new();
        for reference in &input.prior_managed_refs {
            prior.push(accepted_pair(conn, reference).await?.0);
        }
        let p: AppletManagedActorProvisionPayload =
            decode(serde_json::to_value(&prior[0].payload).map_err(rejected)?)?;
        p.validate().map_err(rejected)?;
        if p.actor_role != AppletManagedActorRole::Ghost
            || p.applet_id != input.package.applet_id
            || p.service_id != input.package.service_id
            || p.actor_id != existing.ghost_actor_id
            || p.external_ref.as_ref() != Some(&basis.external_ref)
            || p.actor_id.route_service_id() != target_station(input)?
            || p.actor_id.as_account_id().is_none()
            || existing.managed_actor_provision_ref != prior[0].event_id
            || existing.principal_control_realm_id != RealmId::from_event_id(&prior[1].event_id)
            || existing.accountability_grant_ref != prior[2].event_id
            || existing.profile_event_ref != prior[3].event_id
        {
            return Err(rejected(
                "reuse immutable identity or external tuple differs",
            ));
        }
        for (event, kind) in prior.iter().zip([
            EventKind::AppletManagedActorProvision,
            EventKind::RealmCreate,
            EventKind::IdentityAccountabilityGrant,
            EventKind::ProfileCreate,
        ]) {
            if event.kind != kind {
                return Err(rejected("reuse accepted fixed set differs"));
            }
            verify_prior_service_event(conn, event, input, &prior[0].event_id).await?;
        }
        if !exact_ref(
            &prior[1],
            "applet_managed_actor_provision",
            &prior[0].event_id,
        ) || !exact_ref(&prior[3], "accountability", &prior[2].event_id)
        {
            return Err(rejected("reuse accepted lineage differs"));
        }
        let registration = require_exact_service_grant(conn, input, &p, &validated.portal_realm)
            .await?
            .ok_or_else(|| rejected("reuse registration absent"))?;
        crate::managed_message_actor::require_managed_identity_in_connection(
            conn,
            &p.actor_id,
            &p.applet_id,
            &registration,
            input.accepted_at,
        )
        .await?;
        validated.provision = Some(p);
    }
    if bundle(input).is_some() {
        let p = validated
            .provision
            .as_ref()
            .ok_or_else(|| rejected("managed provision absent"))?;
        let occupied=sql_query("SELECT to_jsonb(EXISTS(SELECT 1 FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2)) AS value")
            .bind::<Text,_>(p.actor_id.signing_principal_id().as_str()).bind::<Text,_>(target_station(input)?.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        if occupied.value.as_bool() != Some(false) {
            return Err(rejected("managed creation Principal is already occupied"));
        }
    }
    if bundle(input).is_some()
        && validated
            .provision
            .as_ref()
            .is_some_and(|p| p.actor_role == AppletManagedActorRole::Ghost)
    {
        let p = validated.provision.as_ref().expect("Ghost creation branch");
        let existing=sql_query("SELECT to_jsonb(EXISTS(SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.state='committed' AND e.kind='ak.applet.managed_actor.provision' AND e.envelope#>>'{payload,applet_id}'=$1 AND e.envelope#>>'{payload,service_id}'=$2 AND e.envelope#>>'{payload,actor_id,account_id,station_id}'=$3 AND e.envelope#>'{payload,external_ref}'=$4)) AS value")
            .bind::<Text,_>(input.package.applet_id.as_str()).bind::<Text,_>(input.package.service_id.as_str()).bind::<Text,_>(target_station(input)?.as_str()).bind::<Jsonb,_>(serde_json::to_value(&p.external_ref).map_err(rejected)?).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        if existing.value.as_bool() != Some(false) {
            return Err(rejected(
                "duplicate_conflict: Ghost tuple already has accepted identity; current reuse preview required",
            ));
        }
    }
    Ok(())
}
