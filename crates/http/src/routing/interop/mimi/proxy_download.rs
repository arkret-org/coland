//! Native public asset references selected under a held accepted Room cut.
use super::*;

fn unsupported() -> AppError {
    crate::app_error!(
        UnsupportedFeature,
        "MIMI asset proxy is not available for this asset or privacy mode"
    )
    .with_internal_reason("mimi_asset_proxy_unavailable")
}

pub(super) async fn download(
    state: &AppState,
    req: &mut Request,
    body: MimiProxyDownloadRequestBody,
) -> JsonResult<MimiProxyDownloadResponseBody> {
    let room = body
        .strand_id
        .as_ref()
        .map(|strand| mimi_room_uri(state, strand.as_str()))
        .transpose()?;
    let source =
        verify_mimi_source_service_signature(state, req, room.as_ref().map(|room| room.as_str()))
            .await?;
    if source != body.requester_id.as_str() {
        return Err(AppError::capability_denied(
            "MIMI download requester does not match the authenticated provider",
        ));
    }
    enforce_mimi_proxy_download_egress_policy(state, body.asset_ref.as_str())?;
    if body.ohttp_context.is_some() || body.range.is_some() {
        return Err(unsupported());
    }
    let reference =
        arkret_wire::BlobRef::new(body.asset_ref.as_str()).map_err(|_| unsupported())?;
    if !state.config().public_blob_refs.contains(&reference) {
        return Err(unsupported());
    }
    let strand = body.strand_id.as_ref().ok_or_else(unsupported)?;
    let room = room.as_ref().ok_or_else(unsupported)?;
    let (blob, mut guard) = state
        .authority_commits()
        .acquire_mimi_public_blob_delivery(
            &state.service_core_id(),
            &body.requester_id,
            room,
            strand,
            &reference,
        )
        .await
        .map_err(|_| AppError::not_found("MIMI asset is unavailable"))?;
    if !super::super::blob::public_global_blob_allowed(state, reference.as_str(), &blob)
        || !guard.prepare_handoff().await
    {
        return Err(AppError::not_found("MIMI asset is unavailable"));
    }
    let issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let expires_at =
        issued_at + chrono::Duration::seconds(super::super::blob::BLOB_PRESIGN_MAX_TTL_SECONDS);
    let envelope = super::super::blob::issue_presign_envelope(
        state,
        reference.as_str(),
        None,
        "download",
        body.requester_id.as_str(),
        issued_at,
        expires_at,
    )?;
    let mut target = url::Url::parse(&state.config().public_base_url)
        .map_err(|_| AppError::internal("MIMI public asset origin is invalid"))?;
    let path = format!(
        "{}/_arkret/self/blob/get",
        target.path().trim_end_matches('/')
    );
    target.set_path(&path);
    target
        .query_pairs_mut()
        .append_pair("blob_ref", reference.as_str())
        .append_pair("purpose", "download")
        .append_pair("presign", &envelope);
    if !guard.permits_handoff() {
        return Err(AppError::not_found("MIMI asset is unavailable"));
    }
    guard
        .finish()
        .await
        .map_err(|_| AppError::not_found("MIMI asset is unavailable"))?;
    append_audit_log(state, Some(body.requester_id.as_str()), "mimi.public_asset_download", json!({
        "blob_ref":reference,"mimi_room_uri":room,"strand_id":strand,
        "presign_digest":arkret_canonical::sha256_digest(envelope.as_bytes()),"expires_at":expires_at,
    }), "accepted").await;
    json_ok(MimiProxyDownloadResponseBody {
        download_ref: target
            .to_string()
            .try_into()
            .map_err(|_| AppError::internal("MIMI asset reference is invalid"))?,
        download_request_headers: Default::default(),
        expires_at: Some(expires_at),
    })
}
