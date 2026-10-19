//! Complete private managed first-forward preparation and immutable recovery.

use arkret_models_collaboration::authority_commit::{
    ForwardManagedActorProvenance, PeerAuthoritySubmitRequest,
};
use arkret_models_crypto::ForwardDeviceProjectionAttestationCore;
use arkret_models_identity::ForwardAccountDeviceSignerEvidence;
use coland_storage::PreparedManagedForward;

use super::*;

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_string())
}

pub(super) fn parts(
    request: &PeerAuthoritySubmitRequest,
) -> PersistenceResult<(
    &arkret_wire::Event,
    Option<&ForwardAccountDeviceSignerEvidence>,
    Option<&ForwardManagedActorProvenance>,
)> {
    match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(body) => Ok((
            &body.event_submission.event,
            body.producer_device_evidence.as_ref(),
            body.producer_managed_provenance.as_ref(),
        )),
        PeerAuthoritySubmitRequest::AuthorityForwardMls(body) => Ok((
            &body.mls_submission.commit_event,
            body.producer_device_evidence.as_ref(),
            body.producer_managed_provenance.as_ref(),
        )),
        _ => Err(invalid(
            "managed source requires the registered Event or MLS forward branch",
        )),
    }
}

pub(super) async fn prepare_in_connection(
    conn: &mut AsyncPgConnection,
    request: &PeerAuthoritySubmitRequest,
    destination: &arkret_wire::DidCoreId,
    attested_at: chrono::DateTime<chrono::Utc>,
) -> Result<PreparedManagedForward, PgTransactionError> {
    let event = parts(request)?.0;
    let context = forward_source::prepare_context_in_connection(conn, event, attested_at)
        .await?
        .ok_or_else(|| invalid("managed forward has no original native Device source"))?;
    let authority = context
        .managed
        .as_ref()
        .ok_or_else(|| invalid("managed source requires an actual managed Device authorization"))?;
    let managed = crate::applet_managed_provenance::prepare_managed_source(
        conn,
        event,
        authority,
        &context.fact,
        attested_at,
        context.expires_at,
    )
    .await?;
    let mut request = request.clone();
    match &mut request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(body) => {
            body.producer_device_evidence = None;
            body.producer_managed_provenance = Some(managed);
            if body.producer_agent_evidence.is_some() {
                return Err(invalid("managed Device cannot acquire an Agent sibling").into());
            }
        }
        PeerAuthoritySubmitRequest::AuthorityForwardMls(body) => {
            body.producer_device_evidence = None;
            body.producer_managed_provenance = Some(managed);
            if body.producer_agent_evidence.is_some() {
                return Err(invalid("managed Device cannot acquire an Agent sibling").into());
            }
        }
        _ => unreachable!("parts checked the closed forward branch"),
    }
    // The source sibling is part of this digest. The only excluded sibling is
    // the attestation that will sign it; no placeholder digest is ever issued.
    let digest =
        arkret_models_collaboration::authority_commit::authority_forward_body_digest(&request)
            .map_err(invalid)?;
    let core = context.attestation(destination, &digest)?;
    Ok(PreparedManagedForward { request, core })
}

async fn require_same_source(
    conn: &mut AsyncPgConnection,
    request: &PeerAuthoritySubmitRequest,
    core: &ForwardDeviceProjectionAttestationCore,
) -> Result<(), PgTransactionError> {
    let prepared = prepare_in_connection(
        conn,
        request,
        &core.event_authorization.destination_service_id,
        core.attested_at,
    )
    .await?;
    if prepared.core != *core
        || parts(&prepared.request)?.2 != parts(request)?.2
        || core.expires_at <= chrono::Utc::now()
    {
        return Err(PersistenceError::Conflict(
            "temporarily_unavailable: complete managed forward source changed before issuance"
                .into(),
        )
        .into());
    }
    Ok(())
}

#[derive(QueryableByName)]
struct RequestRow {
    #[diesel(sql_type = Jsonb)]
    request_json: Value,
}

pub(super) async fn retain(
    pool: &PgPool,
    request: &PeerAuthoritySubmitRequest,
) -> PersistenceResult<SignerEvidenceRef> {
    request.validate().map_err(invalid)?;
    let (event, evidence, managed) = parts(request)?;
    let evidence =
        evidence.ok_or_else(|| invalid("managed forward has no signed Device sibling"))?;
    let managed =
        managed.ok_or_else(|| invalid("managed forward has no original creation source"))?;
    let provenance = serde_json::to_value(managed).map_err(PersistenceError::database)?;
    let core = &evidence.device_projection_attestation.attestation;
    let source = &core.event_authorization;
    let digest =
        arkret_models_collaboration::authority_commit::authority_forward_body_digest(request)
            .map_err(invalid)?;
    let fact = arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
        evidence, event, &core.account_id.station_id, &source.destination_service_id,
        &digest, event.realm_id.digest_suite_code().digest_suite(), core.attested_at,
    ).map_err(invalid)?.into_fact();
    let reference = coland_storage::forwarded_producer_device_evidence_ref(evidence)?;
    let body = serde_json::to_value(evidence).map_err(PersistenceError::database)?;
    let request_json = serde_json::to_value(request).map_err(PersistenceError::database)?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        let arkret_wire::CommitStreamRef::Realm { .. } = &source.authorization_ref.stream_ref else {
            return Err(invalid("managed source requires its original PCR Realm stream").into());
        };
        crate::managed_forward_source::lock_source(conn, event).await?;
        require_same_source(conn, request, core).await?;
        sql_query("INSERT INTO account_device_signer_evidence(evidence_ref,principal_id,station_id,device_id,authorization_event_id,authorization_commit_id,attested_at,evidence_json,managed_provenance_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(evidence_ref) DO NOTHING")
            .bind::<Text,_>(reference.as_ref()).bind::<Text,_>(core.account_id.principal_id.as_str())
            .bind::<Text,_>(core.account_id.station_id.as_str()).bind::<Text,_>(core.device_id.as_str())
            .bind::<Text,_>(fact.key.authorization_ref.event_id.as_str()).bind::<Text,_>(fact.key.authorization_ref.commit_id.as_str())
            .bind::<Timestamptz,_>(core.attested_at).bind::<Jsonb,_>(&body).bind::<Jsonb,_>(&provenance).execute(&mut *conn).await?;
        let stored = sql_query("SELECT evidence_json,authorization_commit_id FROM account_device_signer_evidence WHERE evidence_ref=$1 FOR SHARE")
            .bind::<Text,_>(reference.as_ref()).get_result::<ArchiveRow>(&mut *conn).await?;
        if stored.evidence_json != body || stored.authorization_commit_id != fact.key.authorization_ref.commit_id.as_str() {
            return Err(invalid("managed forward immutable Device root collision").into());
        }
        let stored_source = sql_query("SELECT managed_provenance_json AS request_json FROM account_device_signer_evidence WHERE evidence_ref=$1 FOR SHARE")
            .bind::<Text,_>(reference.as_ref()).get_result::<RequestRow>(&mut *conn).await?;
        if stored_source.request_json != provenance { return Err(invalid("managed forward original source archive collision").into()); }
        sql_query("INSERT INTO account_device_managed_forward_requests(evidence_ref,request_json) VALUES($1,$2) ON CONFLICT(evidence_ref) DO NOTHING")
            .bind::<Text,_>(reference.as_ref()).bind::<Jsonb,_>(&request_json).execute(&mut *conn).await?;
        let stored = sql_query("SELECT request_json FROM account_device_managed_forward_requests WHERE evidence_ref=$1 FOR SHARE")
            .bind::<Text,_>(reference.as_ref()).get_result::<RequestRow>(&mut *conn).await?;
        if stored.request_json != request_json {
            return Err(invalid("managed forward immutable complete request collision").into());
        }
        // This final check is inside the same PCR/current locks and after every
        // potentially blocking write. Any physical expiry rolls both inserts back.
        require_same_source(conn, request, core).await?;
        Ok(())
    }).await.map_err(retention_transaction_error)?;
    Ok(reference)
}

pub(super) async fn get(
    pool: &PgPool,
    account: &AccountId,
    device: &DeviceId,
    reference: &SignerEvidenceRef,
) -> PersistenceResult<Option<PeerAuthoritySubmitRequest>> {
    let mut conn = pg_conn(pool).await?;
    let row = sql_query("SELECT r.request_json FROM account_device_managed_forward_requests r JOIN account_device_signer_evidence e USING(evidence_ref) WHERE r.evidence_ref=$1 AND e.principal_id=$2 AND e.station_id=$3 AND e.device_id=$4")
        .bind::<Text,_>(reference.as_ref()).bind::<Text,_>(account.principal_id.as_str())
        .bind::<Text,_>(account.station_id.as_str()).bind::<Text,_>(device.as_str())
        .get_result::<RequestRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    row.map(|row| {
        let request: PeerAuthoritySubmitRequest = serde_json::from_value(row.request_json)
            .map_err(PersistenceError::database)?;
        request.validate().map_err(invalid)?;
        let (event, evidence, managed) = parts(&request)?;
        let evidence = evidence.ok_or_else(|| invalid("retained managed request lost its Device sibling"))?;
        managed.ok_or_else(|| invalid("retained managed request lost its creation source"))?;
        evidence.validate_binding(account, device).map_err(invalid)?;
        if coland_storage::forwarded_producer_device_evidence_ref(evidence)? != *reference {
            return Err(invalid("retained managed request differs from its immutable address"));
        }
        let core = &evidence.device_projection_attestation.attestation;
        let digest = arkret_models_collaboration::authority_commit::authority_forward_body_digest(&request)
            .map_err(invalid)?;
        // Historical verification of immutable bytes is distinct from permission
        // to send a new request. Recovery callers perform that authorization.
        arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
            evidence, event, &account.station_id, &core.event_authorization.destination_service_id,
            &digest, event.realm_id.digest_suite_code().digest_suite(), core.attested_at,
        ).map_err(invalid)?;
        Ok(request)
    }).transpose()
}
