//! Native Blob access keeps the exact original content and current Device cut.
use super::*;

pub(super) async fn commit_upload(
    mut guard: Box<NativeDeliveryGuard>,
    reference: &arkret_wire::BlobRef,
    record: &coland_storage::BlobRecord,
    max_actor_bytes: u64,
    max_realm_bytes: u64,
) -> PersistenceResult<coland_storage::BlobRecord> {
    let [proof] = guard.proofs.as_slice() else {
        return Err(refused("native upload has no unique original proof"));
    };
    if proof.operations.len() != 1
        || proof.operations[0].action != CapabilityActionId::SelfBlobUploadCreateV1
        || record.realm_id.as_deref()
            != Some(proof.context.endpoint.effective_scope.realm_id().as_str())
        || record.uploaded_by != proof.context.endpoint.authority.actor_id.to_string()
        || record.size_bytes < 0
        || record.redacted
        || record.legal_hold
        || record.visibility
            != arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound
        || reference.as_str() != format!("ak:blob:sha256:{}", record.sha256)
        || !guard.permits_handoff()
    {
        return Err(refused(
            "native upload record differs from its held authority",
        ));
    }
    let endpoint = proof.context.endpoint.clone();
    // Serialize metadata publication with all Blob writers, including writers
    // that do not use the native Device path. The object bytes are already in
    // private storage; only this transaction makes the metadata visible.
    sql_query("LOCK TABLE blobs IN SHARE ROW EXCLUSIVE MODE")
        .execute(guard.held.connection())
        .await
        .map_err(PersistenceError::database)?;
    let existing =
        crate::blobs::blob_for_delivery_in_connection(guard.held.connection(), reference).await?;
    let retained = if let Some(existing) = existing {
        let binding = sql_query("SELECT jsonb_build_object('effective_scope',effective_scope,'actor_id',actor_id,'device_id',device_id,'authorization_ref',authorization_ref) AS value FROM realm_actor_blob_uploads WHERE blob_ref=$1 FOR SHARE")
            .bind::<Text,_>(reference.as_str())
            .get_result::<JsonRow>(guard.held.connection()).await.optional()
            .map_err(PersistenceError::database)?;
        let expected = serde_json::json!({
            "effective_scope": endpoint.effective_scope,
            "actor_id": endpoint.authority.actor_id,
            "device_id": endpoint.authority.device_id,
            "authorization_ref": endpoint.authority.authorization_ref,
        });
        if binding.is_none_or(|binding| binding.value != expected) {
            return Err(refused(
                "native Blob replay has another or missing immutable upload binding",
            ));
        }
        if existing.realm_id != record.realm_id
            || existing.uploaded_by != record.uploaded_by
            || existing.encryption != record.encryption
            || existing.sha256 != record.sha256
            || existing.size_bytes != record.size_bytes
            || existing.redacted
            || existing.legal_hold
            || existing.visibility != record.visibility
        {
            return Err(refused(
                "native Blob replay differs from its original binding",
            ));
        }
        existing
    } else {
        #[derive(QueryableByName)]
        struct Usage {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            actor_bytes: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            realm_bytes: i64,
        }
        let usage = sql_query("SELECT COALESCE(SUM(GREATEST(size_bytes,0)) FILTER (WHERE uploaded_by=$1),0)::bigint AS actor_bytes, COALESCE(SUM(GREATEST(size_bytes,0)) FILTER (WHERE realm_id=$2),0)::bigint AS realm_bytes FROM blobs")
            .bind::<Text,_>(&record.uploaded_by)
            .bind::<Text,_>(record.realm_id.as_deref().expect("held Realm upload"))
            .get_result::<Usage>(guard.held.connection()).await.map_err(PersistenceError::database)?;
        let size = record.size_bytes as u64;
        if (usage.actor_bytes as u64).saturating_add(size) > max_actor_bytes
            || (usage.realm_bytes as u64).saturating_add(size) > max_realm_bytes
        {
            return Err(PersistenceError::Conflict("blob_quota_exceeded".into()));
        }
        crate::blobs::put_blob_if_absent_in_connection(
            guard.held.connection(),
            reference.as_str(),
            record,
        )
        .await?;
        sql_query("INSERT INTO realm_actor_blob_uploads (blob_ref,effective_scope,actor_id,device_id,authorization_ref,accepted_at) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind::<Text,_>(reference.as_str())
            .bind::<Jsonb,_>(serde_json::json!(endpoint.effective_scope))
            .bind::<Jsonb,_>(serde_json::json!(endpoint.authority.actor_id))
            .bind::<Text,_>(endpoint.authority.device_id.as_str())
            .bind::<Jsonb,_>(serde_json::json!(endpoint.authority.authorization_ref))
            .bind::<diesel::sql_types::Timestamptz,_>(arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()))
            .execute(guard.held.connection()).await.map_err(PersistenceError::database)?;
        record.clone()
    };
    if !guard.permits_handoff() {
        return Err(refused(
            "native upload authority expired before metadata commit",
        ));
    }
    guard.held.commit().await?;
    Ok(retained)
}

pub(super) async fn prepare(
    conn: &mut diesel_async::AsyncPgConnection,
    station: &DidCoreId,
    endpoint: &AppletManagedDeviceScopeGuard,
    current: &coland_storage::AppletManagedDeviceAuthority,
    at: chrono::DateTime<chrono::Utc>,
    expiry: chrono::DateTime<chrono::Utc>,
    input: &AccountContentDeliveryInput,
) -> PersistenceResult<ReadProof> {
    if let Some(realm) = &input.native_blob_upload {
        if endpoint.effective_scope.realm_id() != realm {
            return Err(refused(
                "Blob upload metadata does not prove the exact resource scope",
            ));
        }
        let action = CapabilityActionId::SelfBlobUploadCreateV1;
        let context =
            Arc::new(operation_context(conn, endpoint, current, at, expiry, &[action]).await?);
        context.cut.require_open_business_mutation()?;
        if !context.cut.actor_is_joined() {
            return Err(refused("native Blob uploader is not a Realm member"));
        }
        if let ScopeRef::Circle {
            realm_id,
            circle_id,
        } = &endpoint.effective_scope
        {
            let basis =
                crate::circle_current_results::locked_circle_basis(conn, realm_id, circle_id)
                    .await?;
            if basis["value"]["state"] != "active"
                || !crate::circle_current_results::effective_member_in_connection(
                    conn,
                    realm_id,
                    circle_id,
                    &endpoint.authority.actor_id,
                )
                .await?
            {
                return Err(refused(
                    "native Blob upload target has no active Circle membership",
                ));
            }
        }
        let mut operation = scope_operation(&context);
        operation.action = action;
        return Ok(ReadProof {
            resources: scope_resources(&endpoint.effective_scope),
            context,
            operations: vec![operation],
            complete_resources: true,
        });
    }
    let (reference, original, action) = input
        .blobs
        .as_slice()
        .first()
        .ok_or_else(|| refused("missing Blob source"))?;
    if !matches!(
        action,
        CapabilityActionId::SelfBlobResourceGetV1
            | CapabilityActionId::SelfBlobResourceHeadV1
            | CapabilityActionId::SelfBlobCommandPresignV1
    ) || original.realm_id.as_deref() != Some(endpoint.effective_scope.realm_id().as_str())
    {
        return Err(refused("native Blob operation or Realm differs"));
    }
    let held = crate::blobs::blob_for_delivery_in_connection(conn, reference)
        .await?
        .ok_or_else(|| refused("Blob metadata is unavailable"))?;
    if &held != original || held.redacted || held.legal_hold {
        return Err(refused("Blob metadata or visibility changed"));
    }
    let binding = sql_query(
        "SELECT effective_scope AS value FROM realm_actor_blob_uploads WHERE blob_ref=$1 FOR SHARE",
    )
    .bind::<Text, _>(reference.as_str())
    .get_result::<JsonRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let native_upload = serde_json::from_str::<ActorId>(&held.uploaded_by)
        .is_ok_and(|actor| actor.as_realm_actor_id().is_some());
    if binding
        .as_ref()
        .is_some_and(|binding| binding.value != serde_json::json!(endpoint.effective_scope))
        || (native_upload && binding.is_none())
    {
        return Err(refused(
            "Blob upload binding is unavailable or has another exact scope",
        ));
    }
    let sources = sql_query("SELECT e.envelope AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.realm_id=$1 AND e.state='committed' AND e.kind='ak.message.create' AND e.envelope->'payload'->'blob_refs' ? $2 ORDER BY e.envelope->>'event_id'")
        .bind::<Text,_>(endpoint.effective_scope.realm_id().as_str())
        .bind::<Text,_>(reference.as_str()).load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let context = Arc::new(read_context(conn, endpoint, current, at, expiry).await?);
    for source in sources {
        let event: arkret_wire::Event =
            serde_json::from_value(source.value).map_err(PersistenceError::database)?;
        if event.scope_ref != endpoint.effective_scope {
            continue;
        }
        let full =
            crate::committed_disclosure::accepted_full_event_in_connection(conn, &event.event_id)
                .await?
                .ok_or_else(|| refused("Blob source original is unavailable"))?;
        let proof = match event_proof(
            conn,
            station,
            Arc::clone(&context),
            &CommittedEventView::Full(full),
        )
        .await
        {
            Ok(proof) if proof.permits_at(at) => proof,
            _ => continue,
        };
        let mut actions: Vec<_> = proof.operations.iter().map(|op| op.action).collect();
        actions.push(*action);
        actions.push(CapabilityActionId::ObjectReadContent);
        let resource = PolicyResourceSelector {
            kind: PolicyResourceKind::Object,
            realm_id: Some(endpoint.effective_scope.realm_id().clone()),
            resource_ref: Some(reference.to_string()),
        };
        let proof = source_read_proof(Arc::clone(&context), &event, &actions, &[resource])?;
        if proof.permits_at(at) {
            return Ok(proof);
        }
    }
    Err(refused(
        "Blob has no visible original binding in this exact scope",
    ))
}
