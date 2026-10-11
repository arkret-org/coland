//! Exact Applet authoring completion at the accepted portal cut.

use arkret_models_identity::{
    PrincipalResolutionProjection, PrincipalResolutionProjectionAttestationCore,
    build_principal_signer_evidence, build_service_signer_evidence,
};
use arkret_models_integration::{
    AppletManagedActorAuthoringContext, AppletManagedActorCommittedRequest,
    AppletManagedActorProvisionPayload, AppletServiceSignerEvidence,
    ManagedActorPrincipalSignerEvidence,
};
use arkret_wire::{CommitStreamHead, CommitStreamRef, DidUrl, Hash, NonEmptyJsonObject};
use coland_storage::{
    AppletAuthoringUnitWrite, AppletResolutionAttester, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

fn corrupt(message: impl Into<String>) -> PersistenceError {
    PersistenceError::Internal(message.into())
}

fn jwk(key: &[u8; 32]) -> PersistenceResult<NonEmptyJsonObject> {
    serde_json::from_value(
        json!({"kty":"OKP", "crv":"Ed25519", "x":arkret_canonical::base64url_encode(key)}),
    )
    .map_err(PersistenceError::database)
}

#[derive(QueryableByName)]
struct ProjectionRow {
    #[diesel(sql_type = Jsonb)]
    projection: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

#[derive(QueryableByName)]
struct HeadRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

/// The caller has verified the unit's method history and exact key. This
/// helper additionally requires the accepted local resolution and portal
/// head to exist, and verifies the Station callback before persisting roots.
pub(crate) async fn materialize_context_in_connection(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringUnitWrite,
    portal_head: &CommitStreamHead,
    provision: &AppletManagedActorProvisionPayload,
    managed_verification_method: &DidUrl,
    managed_public_key: &[u8; 32],
    attester: &AppletResolutionAttester,
) -> PersistenceResult<AppletManagedActorAuthoringContext> {
    let committed_request = match &input.request {
        coland_storage::AppletAdmissionRequest::Managed(request) => request,
        _ => {
            return Err(corrupt(
                "Service-only installation has no managed authoring completion",
            ));
        }
    };
    let (request, portal_realm) = match committed_request {
        AppletManagedActorCommittedRequest::Bot(body) => (
            &body.authoring_request,
            body.authoring_request
                .basis
                .bot()
                .ok_or_else(|| corrupt("missing Bot basis"))?
                .effective_scope
                .realm_id(),
        ),
        AppletManagedActorCommittedRequest::Ghost(body) => (
            &body.authoring_request,
            body.authoring_basis()
                .ok_or_else(|| corrupt("missing Ghost basis"))?
                .effective_scope
                .realm_id(),
        ),
    };
    if portal_head.stream_ref
        != (CommitStreamRef::Realm {
            realm_id: portal_realm.clone(),
        })
        || provision.service_id != input.package.service_id
        || provision.applet_id != input.package.applet_id
        || provision.actor_id.route_service_id() != request.basis.target_station_id()
    {
        return Err(corrupt(
            "Applet completion head or principal binding differs from its accepted request",
        ));
    }
    let key = crate::authority_commit::stream_key(&portal_head.stream_ref)?;
    let row = sql_query("SELECT commit_json FROM realm_commits WHERE stream_key=$1 ORDER BY stream_position DESC LIMIT 1")
        .bind::<Text,_>(&key).get_result::<HeadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| corrupt("Applet completion has no accepted portal head"))?;
    let commit: arkret_wire::RealmCommit =
        serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
    if commit.commit_id != portal_head.commit_id
        || commit.stream_position != portal_head.stream_position
        || commit.stream_ref != portal_head.stream_ref
    {
        return Err(corrupt(
            "Applet completion portal head is not the locked accepted head",
        ));
    }
    let row = sql_query("SELECT p.projection,c.commit_json FROM principal_resolutions p JOIN canonical_events e ON e.envelope->>'event_id'=p.current_event_id JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=p.pcr_realm_id WHERE p.principal_id=$1 AND p.station_id=$2 AND c.stream_ref->>'kind'='realm' FOR SHARE OF p,c")
        .bind::<Text,_>(provision.actor_id.signing_principal_id().as_str())
        .bind::<Text,_>(provision.actor_id.route_service_id().as_str())
        .get_result::<ProjectionRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| corrupt("Applet principal has no accepted local resolution"))?;
    let principal_control_commit: arkret_wire::RealmCommit =
        serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
    principal_control_commit
        .validate_shape()
        .map_err(PersistenceError::database)?;
    let projection: PrincipalResolutionProjection =
        serde_json::from_value(row.projection).map_err(PersistenceError::database)?;
    if projection.did != provision.initial_resolution.did
        || projection.method_history_head != provision.initial_resolution.method_history_head
        || projection.version_id != provision.initial_resolution.version_id
    {
        return Err(PersistenceError::Conflict("failed_precondition: Applet initial resolution no longer matches the accepted current method".to_owned()));
    }
    let account = provision
        .actor_id
        .as_account_id()
        .ok_or_else(|| corrupt("Applet managed principal is not an Account"))?;
    let history_digest = Hash::new(
        arkret_canonical::canonical_sha256(&provision.method_history_evidence)
            .map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    let at = arkret_canonical::normalize_timestamp_canonical(input.accepted_at);
    let core = PrincipalResolutionProjectionAttestationCore {
        account_id: account.clone(),
        resolution_projection: projection,
        method_history_evidence_digest: history_digest,
        issued_at: at,
        expires_at: at + chrono::Duration::minutes(5),
    };
    let projection_attestation = attester(core.clone())?;
    if projection_attestation.attestation != core
        || projection_attestation.proof.verification_method != input.station_verification_method
        || projection_attestation.proof.created_at != at
    {
        return Err(corrupt(
            "Applet projection attester changed the accepted material",
        ));
    }
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &projection_attestation.proof.jws,
            &projection_attestation
                .proof_signing_bytes()
                .map_err(PersistenceError::database)?,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: input.station_public_key.to_vec(),
            },
        )
        .map_err(PersistenceError::database)?;
    let service_key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        &input.service_did_document,
        input.package.webhook_auth.key_ref.as_str(),
    )
    .map_err(PersistenceError::database)?;
    let service = build_service_signer_evidence(
        input.package.service_id.clone(),
        input.package.webhook_auth.key_ref.clone(),
        jwk(service_key.as_bytes())?,
        portal_head.commit_id.clone(),
        at,
    )
    .map_err(PersistenceError::database)?;
    let service_root = if let Some(prior) = &input.prior_service_signer_evidence {
        prior.validate().map_err(PersistenceError::database)?;
        let evidence = &prior.authenticated_signer_evidence;
        let prior_key = arkret_signatures::PublicKeyMaterial::Jwk {
            value: serde_json::to_value(&evidence.public_key_jwk)
                .map_err(PersistenceError::database)?,
        }
        .ed25519_bytes()
        .map_err(PersistenceError::database)?;
        if evidence.subject_id != input.package.service_id
            || evidence.verification_method != input.package.webhook_auth.key_ref
            || prior_key != *service_key.as_bytes()
        {
            return Err(corrupt(
                "reused Applet root differs from the exact original Service material",
            ));
        }
        prior.clone()
    } else {
        AppletServiceSignerEvidence {
            signer_resolution_evidence_ref: service
                .signer_evidence_ref()
                .map_err(PersistenceError::database)?,
            authenticated_signer_evidence: service,
        }
    };
    let principal = build_principal_signer_evidence(
        account.principal_id.clone(),
        managed_verification_method.clone(),
        jwk(managed_public_key)?,
        principal_control_commit.commit_id.clone(),
        principal_control_commit.committed_at,
    )
    .map_err(PersistenceError::database)?;
    let station = build_service_signer_evidence(
        account.station_id.clone(),
        input.station_verification_method.clone(),
        jwk(&input.station_public_key)?,
        principal_control_commit.commit_id.clone(),
        principal_control_commit.committed_at,
    )
    .map_err(PersistenceError::database)?;
    let context = AppletManagedActorAuthoringContext {
        committed_request: committed_request.clone(),
        realm_stream_head: portal_head.clone(),
        principal_control_commit,
        applet_service_signer_evidence: service_root,
        managed_actor_signer_evidence: ManagedActorPrincipalSignerEvidence {
            signer_resolution_evidence_ref: principal
                .signer_evidence_ref()
                .map_err(PersistenceError::database)?,
            authenticated_signer_evidence: principal,
            attester_signer_evidence: station,
        },
        resolution_update: None,
    };
    context.validate().map_err(PersistenceError::database)?;
    let context_json = serde_json::to_value(&context).map_err(PersistenceError::database)?;
    let attestation_json =
        serde_json::to_value(&projection_attestation).map_err(PersistenceError::database)?;
    let inserted = sql_query("INSERT INTO applet_authoring_completions (applet_id,request_digest,source_id,destination_id,endpoint,idempotency_key,context,projection_attestation,accepted_at,delivered_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL) ON CONFLICT DO NOTHING")
        .bind::<Text,_>(input.package.applet_id.as_str()).bind::<Text,_>(input.request_digest.as_str())
        .bind::<Text,_>(account.station_id.as_str()).bind::<Text,_>(input.package.service_id.as_str())
        .bind::<Text,_>(&input.package.base_url).bind::<Text,_>(&input.idempotency_key)
        .bind::<Jsonb,_>(&context_json).bind::<Jsonb,_>(&attestation_json).bind::<Timestamptz,_>(at)
        .execute(conn).await.map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: Applet completion already exists with a different transaction"
                .to_owned(),
        ));
    }
    Ok(context)
}
