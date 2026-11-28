//! Reconcile frozen endpoint sources before publishing the private preparation.
use std::collections::{BTreeMap, BTreeSet};

use arkret_models_crypto::{
    ContentEndpoint, ContentRecoveryInventory, ContentRecoveryInventoryEntry,
    ContentRecoveryOldLeaf,
};
use arkret_wire::{
    BlobRef, CommittedEventRef, DidCoreId, EventId, EventKind, MlsWelcomeRecipientEndpoint,
    ScopeRef,
};
use coland_storage::{
    HumanPcrHistoryRead, HumanPcrHistoryReader, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{BigInt, Binary, Jsonb, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncConnection as _;
use horme::{OptionalExtension as _, RunQueryDsl as _};
use serde_json::{Value, json};

use super::content_recovery_preparation;
use super::content_recovery_source::original_in_scope;
use crate::{AsyncPgConnection, JsonPayloadRow, PgPool, PgTransactionError, pg_conn};

fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("revision_unavailable: recovery inventory {error}"))
}

#[derive(QueryableByName)]
struct Document {
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Text)]
    inventory_digest: String,
}

pub(super) async fn read(
    pool: &PgPool,
    reader: &HumanPcrHistoryReader,
    authorization: &EventId,
    reference: &BlobRef,
) -> PersistenceResult<HumanPcrHistoryRead<Vec<u8>>> {
    use coland_storage::AccountContentDeliveryGuard as _;
    use content_recovery_preparation::EpisodeRead;
    let mut episode =
        match content_recovery_preparation::qualify(pool, reader, authorization).await? {
            EpisodeRead::NotApplicable => return Ok(HumanPcrHistoryRead::NotApplicable),
            EpisodeRead::CurrentStatusRequired => {
                return Ok(HumanPcrHistoryRead::CurrentStatusRequired);
            }
            EpisodeRead::Qualified(episode) => episode,
        };
    let value = &episode.value;
    if value.inventory_blob_ref.as_ref() != Some(reference) {
        episode.held.finish().await?;
        return Ok(HumanPcrHistoryRead::NotApplicable);
    }
    let document=sql_query("SELECT i.canonical_bytes,i.inventory_digest FROM content_recovery_inventory_blobs i JOIN blobs b ON b.id=i.blob_ref WHERE i.authorization_event_ref=$1 AND i.blob_ref=$2 AND b.storage_backend='recovery_inventory' AND b.visibility='device_bound' AND NOT b.redacted AND NOT b.legal_hold FOR SHARE OF i,b")
        .bind::<Text,_>(authorization.as_str()).bind::<Text,_>(reference.as_str()).get_result::<Document>(episode.held.connection()).await.optional().map_err(PersistenceError::database)?;
    let Some(document) = document else {
        episode.held.finish().await?;
        return Ok(HumanPcrHistoryRead::NotApplicable);
    };
    let inventory: ContentRecoveryInventory =
        serde_json::from_slice(&document.canonical_bytes).map_err(invalid)?;
    if inventory.replacement != value.replacement
        || inventory.pcr_cut != value.pcr_cut
        || inventory.authorization_event_ref != *authorization
        || arkret_canonical::canonical_json_bytes(&inventory).map_err(invalid)?
            != document.canonical_bytes
        || arkret_crypto::content_history::recovery_inventory_digest(&inventory)
            .map_err(invalid)?
            .as_str()
            != document.inventory_digest
        || format!(
            "ak:blob:sha256:{}",
            arkret_canonical::sha256_hex(&document.canonical_bytes)
        ) != reference.as_str()
    {
        return Err(invalid(
            "stored private bytes differ from the prepared episode",
        ));
    }
    episode.held.probe().await?;
    Ok(crate::pcr_history_read::guarded(
        episode.held,
        episode.expires_at,
        document.canonical_bytes,
    ))
}

type GovernorHeads = BTreeMap<arkret_wire::RealmId, arkret_wire::RealmAuthorityCurrentAssertion>;

async fn confirm_governors(
    pool: &PgPool,
    authorization: &EventId,
    service: &DidCoreId,
    materials: Option<&dyn coland_storage::RecoveryInventoryPublicMaterial>,
) -> PersistenceResult<GovernorHeads> {
    let mut heads = GovernorHeads::new();
    let Some(materials) = materials else {
        return Ok(heads);
    };
    let mut conn = pg_conn(pool).await?;
    let rows=sql_query("SELECT DISTINCT jsonb_build_object('realm',a.realm_id,'service',a.service_id) AS payload
          FROM content_recovery_episodes e JOIN content_recovery_episodes prior ON prior.actor_id=e.actor_id
          JOIN content_recovery_census_sources s ON s.authorization_event_ref=prior.authorization_event_ref
          JOIN realm_authorities a ON a.realm_id=s.effective_scope->>'realm_id'
         WHERE e.authorization_event_ref=$1 AND e.state='pending' AND prior.security_completed_at IS NULL AND a.service_id<>$2")
        .bind::<Text,_>(authorization.as_str()).bind::<Text,_>(service.as_str()).get_results::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    drop(conn);
    for row in rows {
        let realm = serde_json::from_value(row.payload["realm"].clone()).map_err(invalid)?;
        let governor = serde_json::from_value(row.payload["service"].clone()).map_err(invalid)?;
        let assertion = materials.governor_head(&realm, &governor).await?;
        if assertion.realm_id != realm || assertion.current_service_id != governor {
            return Err(invalid("governor changed during confirmation"));
        }
        heads.insert(realm, assertion);
    }
    Ok(heads)
}

async fn public_material(
    conn: &mut AsyncPgConnection,
    store: &dyn coland_storage::RecoveryInventoryPublicMaterial,
    realm: &arkret_wire::RealmId,
    reference: &BlobRef,
    limit: usize,
) -> PersistenceResult<Option<Vec<u8>>> {
    use arkret_models_collaboration::objects::blob::BlobVisibility;
    let Some(blob) = crate::blobs::blob_for_delivery_in_connection(conn, reference).await? else {
        return Ok(None);
    };
    if blob.redacted
        || blob.legal_hold
        || blob.encryption.is_some()
        || !matches!(
            blob.visibility,
            BlobVisibility::Public | BlobVisibility::RealmBound
        )
        || blob
            .realm_id
            .as_deref()
            .is_some_and(|id| id != realm.as_str())
        || reference.as_str().strip_prefix("ak:blob:sha256:") != Some(blob.sha256.as_str())
        || usize::try_from(blob.size_bytes).map_or(true, |size| size > limit)
    {
        return Ok(None);
    }
    store.publication(&blob).await
}

async fn entry(
    heads: &GovernorHeads,
    materials: Option<&dyn coland_storage::RecoveryInventoryPublicMaterial>,
    pcr_cut: &CommittedEventRef,
    conn: &mut AsyncPgConnection,
    service: &DidCoreId,
    scope: ScopeRef,
    genesis: EventId,
    replacement: &ContentEndpoint,
) -> PersistenceResult<Option<ContentRecoveryInventoryEntry>> {
    let realm = scope
        .realm_id_opt()
        .ok_or_else(|| invalid("no governing Realm"))?;
    let local = sql_query("SELECT to_jsonb(service_id) AS payload FROM realm_authorities WHERE realm_id=$1 AND service_id=$2 FOR SHARE")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(service.as_str()).get_result::<JsonPayloadRow>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?;
    let key = crate::mls_group_current_states::scope_key(&scope)?;
    let (value, local_state) = if local.is_some() {
        let Some(group) = crate::mls_group_current_states::locked_group(conn, &key).await? else {
            return Ok(None);
        };
        (group.value, Some(group.public_state))
    } else {
        // Only an anchored, exact remote projection can select publication
        // bytes. An older cached prefix cannot establish a post-fence cut.
        let stream = arkret_wire::CommitStreamRef::from_scope(&scope, None).map_err(invalid)?;
        let selector = arkret_wire::CurrentSelector::MlsGroup {
            scope_ref: scope.clone(),
        };
        let Some((head, rows)) =
            crate::replica_authorization::exact_current_evidence(conn, &stream, &[selector])
                .await?
        else {
            return Ok(None);
        };
        let Some(assertion) = heads.get(realm) else {
            return Ok(None);
        };
        if assertion.expires_at <= chrono::Utc::now() {
            return Ok(None);
        }
        let authority=sql_query("SELECT to_jsonb(generation) AS payload FROM realm_authorities WHERE realm_id=$1 AND service_id=$2 FOR SHARE")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(assertion.current_service_id.as_str()).get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        if authority.and_then(|row| row.payload.as_u64()) != Some(assertion.current_generation) {
            return Ok(None);
        }
        if head.stream_ref == assertion.realm_stream_head.stream_ref {
            if head != assertion.realm_stream_head {
                return Ok(None);
            }
        } else {
            // The public assertion names the Realm stream only. A Sidecar
            // additionally needs its own post-fence verified replication head.
            let confirmed=sql_query("SELECT to_jsonb(h.commit_id) AS payload FROM realm_commits h JOIN realm_commits cut ON cut.commit_id=$2 JOIN replica_authorization_cuts c ON c.head_commit_id=h.commit_id AND c.source_stream_ref=$3 WHERE h.commit_id=$1 AND h.committed_at>=cut.committed_at AND c.verified_at>=cut.committed_at FOR SHARE OF c")
                .bind::<Text,_>(head.commit_id.as_str()).bind::<Text,_>(pcr_cut.commit_id.as_str()).bind::<Jsonb,_>(json!(stream))
                .get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            if confirmed.is_none() {
                return Ok(None);
            }
        }
        let Some(arkret_wire::CurrentState::Value { value, .. }) = rows.into_iter().next() else {
            return Ok(None);
        };
        (serde_json::from_value(value).map_err(invalid)?, None)
    };
    if value.effective_scope != scope || value.genesis_event_ref != genesis {
        return Ok(None);
    }
    let base = value.current_mls_commit_event_ref;
    let (first, _) = original_in_scope(conn, &genesis, &scope).await?;
    let (event, _) = original_in_scope(conn, &base, &scope).await?;
    if first.kind != EventKind::MlsGenesis
        || !(event.kind == EventKind::MlsCommit || (base == genesis && value.epoch == 0))
    {
        return Err(invalid("group head differs from its originals"));
    }
    use arkret_event_draft::EventPayloadExt as _;
    let (info_ref, published_tree) = if event.kind == EventKind::MlsGenesis {
        let p = event.as_mls_genesis().map_err(invalid)?;
        (p.group_info_ref, p.ratchet_tree_ref)
    } else {
        let p = event.as_mls_commit().map_err(invalid)?;
        (p.group_info_ref().clone(), p.ratchet_tree_ref().clone())
    };
    let group_id = scope.canonical_mls_group_id().map_err(invalid)?;
    let tracker = if let Some(state) = local_state {
        arkret_mls::MlsPublicGroupTracker::restore(&state, group_id.as_str(), value.epoch)
    } else {
        let Some(store) = materials else {
            return Ok(None);
        };
        let limit = arkret_models_collaboration::mls_group_state_material::MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES as usize;
        let Some(info) = public_material(conn, store, realm, &info_ref, limit).await? else {
            return Ok(None);
        };
        let Some(tree) = public_material(conn, store, realm, &published_tree, limit.saturating_sub(info.len())).await? else {
            return Ok(None);
        };
        arkret_mls::MlsPublicGroupTracker::from_external(
            &info,
            &tree,
            group_id.as_str(),
            value.epoch,
        )
    }
    .map_err(invalid)?;
    let tree = tracker.ratchet_tree_bytes().map_err(invalid)?;
    if value.public_tree_ref != published_tree
        || published_tree.as_str()
            != format!("ak:blob:sha256:{}", arkret_canonical::sha256_hex(tree))
    {
        return Err(invalid("RFC tree does not match the accepted publication"));
    }
    let mut old_leaves = Vec::new();
    for leaf in tracker.leaves().map_err(invalid)? {
        if leaf.actor_id != replacement.actor_id {
            continue;
        }
        let endpoint = if local.is_some() {
            sql_query("SELECT h.binding AS payload FROM mls_endpoint_current_bindings b JOIN content_endpoint_admission_history h ON h.effective_scope=$1 AND h.genesis_event_ref=$2 AND h.binding=b.binding WHERE b.scope_key=$3 AND b.leaf_index=$4 AND b.actor_id=$5 AND b.leaf_signature_key=$6 AND b.current_event_ref=$7")
        .bind::<Jsonb,_>(json!(scope)).bind::<Text,_>(genesis.as_str()).bind::<Text,_>(&key).bind::<BigInt,_>(i64::from(leaf.leaf_index))
        .bind::<Jsonb,_>(json!(leaf.actor_id)).bind::<Text,_>(leaf.signature_key.as_str()).bind::<Text,_>(base.as_str())
        .get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        } else {
            let matches=sql_query("SELECT binding AS payload FROM content_endpoint_admission_history WHERE effective_scope=$1 AND genesis_event_ref=$2 AND binding->'actor_id'=$3 AND binding->>'signature_key_base64url'=$4 LIMIT 2")
                .bind::<Jsonb,_>(json!(scope)).bind::<Text,_>(genesis.as_str()).bind::<Jsonb,_>(json!(leaf.actor_id)).bind::<Text,_>(leaf.signature_key.as_str())
                .get_results::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
            if matches.len() != 1 {
                return Ok(None);
            }
            matches.into_iter().next()
        };
        let Some(endpoint) = endpoint else {
            return Ok(None);
        };
        let endpoint: ContentEndpoint =
            serde_json::from_value(endpoint.payload).map_err(invalid)?;
        if endpoint.actor_id != leaf.actor_id
            || endpoint.signature_key_base64url != leaf.signature_key.as_str()
        {
            return Err(invalid("leaf and attested endpoint disagree"));
        }
        old_leaves.push(ContentRecoveryOldLeaf {
            leaf_index: leaf.leaf_index,
            endpoint,
        });
    }
    old_leaves.sort_by_key(|leaf| leaf.leaf_index);
    Ok(Some(ContentRecoveryInventoryEntry {
        effective_scope: scope,
        genesis_event_ref: genesis,
        base_group_state_ref: base,
        epoch: value.epoch,
        old_leaves,
    }))
}

/// One request may allocate several packages. Each one needs its own accepted
/// Add, not just the first Welcome or a terminal allocation ledger state.
async fn claim_commits(
    conn: &mut AsyncPgConnection,
    scope: &ScopeRef,
    source: &Value,
) -> PersistenceResult<Option<Vec<EventId>>> {
    use arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody;
    use arkret_models_identity::AuthenticatedServiceResolution;
    #[derive(QueryableByName)]
    struct Installed {
        #[diesel(sql_type=Jsonb)]
        request_json: Value,
        #[diesel(sql_type=Text)]
        attestation_digest: String,
        #[diesel(sql_type=Nullable<Binary>)]
        attestor_resolution_canonical_json: Option<Vec<u8>>,
        #[diesel(sql_type=Nullable<Binary>)]
        claim_issuer_resolution_canonical_json: Option<Vec<u8>>,
    }
    let rows=sql_query("SELECT a.request_json,a.attestation_digest,a.attestor_resolution_canonical_json,a.claim_issuer_resolution_canonical_json
        FROM mls_add_authority_attestations a JOIN mls_consumed_proposal_provenance p USING(scope_key,commit_event_ref,consumed_proposal_ordinal)
        WHERE a.scope_key=$1 AND a.request_json#>>'{attestation,claim_receipt,source_id}'=$2
          AND a.request_json#>>'{attestation,claim_receipt,claim_request_id}'=$3 AND a.request_json#>>'{attestation,claim_receipt,request_digest}'=$4
          AND p.proposal_type=1 AND p.target_after_actor_id=a.request_json#>'{attestation,actor_id}'
          AND p.target_after_signature_key=a.request_json#>>'{attestation,leaf_signature_key_base64url}'
        UNION ALL SELECT a.request_json,a.attestation_digest,NULL::bytea,NULL::bytea
          FROM mls_add_authority_attestation_outbox a
         WHERE a.acknowledged_at IS NOT NULL AND a.scope_key=$1
           AND a.request_json#>>'{attestation,claim_receipt,source_id}'=$2
           AND a.request_json#>>'{attestation,claim_receipt,claim_request_id}'=$3
           AND a.request_json#>>'{attestation,claim_receipt,request_digest}'=$4")
        .bind::<Text,_>(crate::mls_group_current_states::scope_key(scope)?).bind::<Text,_>(field(source,"source_id")?).bind::<Text,_>(field(source,"claim_request_id")?).bind::<Text,_>(field(source,"request_digest")?)
        .get_results::<Installed>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut claims = None;
    let mut accepted = BTreeSet::new();
    let mut events = Vec::new();
    for row in rows {
        let proof: MlsAttestAddRequestBody =
            serde_json::from_value(row.request_json).map_err(invalid)?;
        match (
            row.claim_issuer_resolution_canonical_json,
            row.attestor_resolution_canonical_json,
        ) {
            (Some(issuer), Some(attestor)) => {
                let issuer: AuthenticatedServiceResolution =
                    serde_json::from_slice(&issuer).map_err(invalid)?;
                let attestor: AuthenticatedServiceResolution =
                    serde_json::from_slice(&attestor).map_err(invalid)?;
                arkret::verify_mls_attest_add_request(&proof, &issuer, &attestor)
                    .map_err(invalid)?;
            }
            // A recipient's immutable original is independently acknowledged
            // by the governor only after its signed Add has been installed.
            (None, None) => proof.validate_claim_binding().map_err(invalid)?,
            _ => return Err(invalid("incomplete Add signer history")),
        }
        let a = &proof.attestation;
        if &a.effective_scope != scope
            || a.claim_receipt.request_digest.as_str() != field(source, "request_digest")?
            || arkret_canonical::canonical_sha256(&proof).map_err(invalid)?
                != row.attestation_digest
        {
            return Err(invalid("durable Add differs from frozen claim"));
        }
        let (event, commit) = original_in_scope(conn, &a.commit_event_ref, scope).await?;
        if event.kind != EventKind::MlsCommit || commit.stream_position != a.commit_stream_position
        {
            return Err(invalid("Add and winning Commit differ"));
        }
        let expected = proof
            .claim_outcome
            .claims
            .iter()
            .map(|claim| claim.claim_id.clone())
            .collect::<BTreeSet<_>>();
        if claims.as_ref().is_some_and(|prior| prior != &expected) {
            return Err(invalid("claim has conflicting signed outcomes"));
        }
        claims = Some(expected);
        accepted.insert(a.claim_id.to_string());
        events.push(a.commit_event_ref.clone());
    }
    Ok((!accepted.is_empty() && claims.as_ref() == Some(&accepted)).then_some(events))
}

async fn prepare(
    heads: &GovernorHeads,
    materials: Option<&dyn coland_storage::RecoveryInventoryPublicMaterial>,
    conn: &mut AsyncPgConnection,
    service: &DidCoreId,
    authorization: &EventId,
) -> PersistenceResult<bool> {
    let row=sql_query("SELECT jsonb_build_object('replacement',replacement,'cut',pcr_cut) AS payload FROM content_recovery_episodes WHERE authorization_event_ref=$1 AND state='pending' AND security_completed_at IS NULL")
        .bind::<Text,_>(authorization.as_str()).get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(row) = row else { return Ok(false) };
    let replacement: ContentEndpoint =
        serde_json::from_value(row.payload["replacement"].clone()).map_err(invalid)?;
    let cut: CommittedEventRef =
        serde_json::from_value(row.payload["cut"].clone()).map_err(invalid)?;
    let account = replacement
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("missing Account"))?;
    let MlsWelcomeRecipientEndpoint::Device { device_id } = &replacement.endpoint else {
        return Err(invalid("missing replacement Device"));
    };
    // Identity acceptance locks its PCR before its episode. Use the same
    // order, including across two coordinators and a superseding recovery.
    crate::pcr_private_authority::lock_holder(conn, account, Some(service)).await?;
    let pending=sql_query("SELECT to_jsonb(authorization_event_ref) AS payload FROM content_recovery_episodes WHERE authorization_event_ref=$1 AND state='pending' AND security_completed_at IS NULL FOR UPDATE SKIP LOCKED")
        .bind::<Text,_>(authorization.as_str()).get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if pending.is_none() {
        return Ok(false);
    }
    let current = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        account,
        device_id,
        chrono::Utc::now(),
    )
    .await
    .map_err(PgTransactionError::into_persistence)?;
    let Some(current) = current else {
        return Ok(false);
    };
    if current.admission() != arkret_wire::AccountDeviceRevocationAdmissionDecision::Allow
        || current
            .authority
            .authorization
            .as_ref()
            .is_none_or(|native| native.event_id != *authorization)
    {
        return Ok(false);
    }
    let valid_until = current
        .authority
        .authorization
        .as_ref()
        .and_then(|grant| grant.payload.expires_at.flatten());
    let realm_id = current.authority.realm_id.clone();
    let completion =
        super::content_recovery_source::native_completion(conn, account, device_id, current)
            .await?;
    if completion.device_authorization_event_ref != cut {
        return Err(invalid("PCR cut differs from signed completion"));
    }
    let (authorize, commit) =
        original_in_scope(conn, authorization, &ScopeRef::Realm { realm_id }).await?;
    if cut.event_id != *authorization
        || cut.commit_id != commit.commit_id
        || cut.stream_position != commit.stream_position
        || cut.stream_ref != commit.stream_ref
        || super::content_recovery_preparation::replacement(account, &authorize)? != replacement
    {
        return Err(invalid("replacement differs from native PCR unit"));
    }
    // All prior unfinished cuts contribute obligations, even when today's tree is empty.
    let sources=sql_query("WITH RECURSIVE episodes(id) AS (SELECT $1::text UNION SELECT s.source->>'authorization_event_ref' FROM episodes e JOIN content_recovery_census_sources s ON s.authorization_event_ref=e.id WHERE s.source_kind='predecessor') SELECT jsonb_build_object('kind',s.source_kind,'scope',s.effective_scope,'source',s.source) AS payload FROM episodes e JOIN content_recovery_census_sources s ON s.authorization_event_ref=e.id WHERE s.source_kind<>'predecessor'")
        .bind::<Text,_>(authorization.as_str()).get_results::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut groups = BTreeMap::new();
    let mut outcomes = Vec::new();
    for row in sources {
        let scope: ScopeRef =
            serde_json::from_value(row.payload["scope"].clone()).map_err(invalid)?;
        let source = &row.payload["source"];
        match row.payload["kind"].as_str() {
            Some("admission") => {
                let genesis: EventId =
                    serde_json::from_value(source["genesis_event_ref"].clone()).map_err(invalid)?;
                super::recovery_census_cut::verify_admission(
                    conn,
                    &replacement.actor_id,
                    &scope,
                    &genesis,
                    source,
                )
                .await?;
                let key = arkret_canonical::canonical_json_bytes(
                    &json!({"effective_scope":scope,"genesis_event_ref":genesis}),
                )
                .map_err(invalid)?;
                groups.insert(key, (scope, genesis));
            }
            Some("outgoing_event") => {
                let event: EventId =
                    serde_json::from_value(source["event_ref"].clone()).map_err(invalid)?;
                // Only the durable, non-retryable decision for this exact
                // frozen submission discharges a forward without admission.
                let refused=sql_query("SELECT f.terminal_outcome_json AS payload FROM account_device_signer_evidence s JOIN canonical_events e ON e.pk=s.forward_event_pk JOIN authority_forward_attempts f ON f.event_pk=e.pk WHERE s.evidence_ref=$1 AND e.envelope->>'event_id'=$2 AND e.scope_ref=$3 AND (f.original_submission_json->'event'=e.envelope OR f.original_submission_json->'commit_event'=e.envelope) AND f.terminal_outcome_json->>'status'='rejected' AND NOT EXISTS(SELECT 1 FROM realm_commits c WHERE c.event_pk=e.pk)")
                    .bind::<Text,_>(field(source,"evidence_ref")?).bind::<Text,_>(event.as_str()).bind::<Jsonb,_>(json!(scope))
                    .get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                if let Some(row) = refused {
                    let outcome: arkret_wire::AuthoritySubmitResponseBody =
                        serde_json::from_value(row.payload).map_err(invalid)?;
                    outcome.validate_shape().map_err(invalid)?;
                    continue;
                }
                outcomes.push((scope, event));
            }
            Some("outgoing_claim" | "incoming_claim") => {
                let Some(commits) = claim_commits(conn, &scope, source).await? else {
                    return Ok(false);
                };
                outcomes.extend(commits.into_iter().map(|event| (scope.clone(), event)));
            }
            _ => return Err(invalid("unknown frozen source")),
        }
    }
    // A remote winner can be installed after the fence for an exact frozen
    // intent. Its first admission was then necessarily absent from the cut.
    for (scope, event) in &outcomes {
        let retained=sql_query("SELECT jsonb_build_object('genesis_event_ref',h.genesis_event_ref,'first_source',h.first_source,'admission_key',h.admission_key) AS payload FROM content_endpoint_admission_history h WHERE h.effective_scope=$1 AND h.binding->'actor_id'=$2 AND h.first_source->>'event_id'=$3")
            .bind::<Jsonb,_>(json!(scope)).bind::<Jsonb,_>(json!(replacement.actor_id)).bind::<Text,_>(event.as_str())
            .get_results::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        for row in retained {
            let genesis: EventId = serde_json::from_value(row.payload["genesis_event_ref"].clone())
                .map_err(invalid)?;
            super::recovery_census_cut::verify_admission(
                conn,
                &replacement.actor_id,
                scope,
                &genesis,
                &row.payload,
            )
            .await?;
            let key = arkret_canonical::canonical_json_bytes(
                &json!({"effective_scope":scope,"genesis_event_ref":genesis}),
            )
            .map_err(invalid)?;
            groups.insert(key, (scope.clone(), genesis));
        }
    }
    // A missing endpoint index must not turn a real Genesis, Add, or old
    // binding into a false empty inventory. In particular an unattested Add
    // can leave the tree again before recovery. The consumed RFC proposal
    // remains independent evidence that the group belongs in the census.
    let discovered=sql_query(
        "SELECT DISTINCT scope AS payload FROM (
            SELECT e.scope_ref AS scope FROM canonical_events e
             WHERE e.kind IN ('ak.mls.genesis','ak.mls.commit') AND e.state='committed'
               AND COALESCE(NULLIF(e.envelope->'executed_by','null'::jsonb), e.envelope->'actor_id')=$1
            UNION ALL SELECT p.scope_key::jsonb FROM mls_consumed_proposal_provenance p
             WHERE p.proposal_type=1 AND p.target_after_actor_id=$1
            UNION ALL SELECT b.scope_key::jsonb FROM mls_endpoint_current_bindings b WHERE b.actor_id=$1
            UNION ALL SELECT a.scope_key::jsonb FROM mls_add_authority_attestations a
             WHERE a.request_json->'attestation'->'actor_id'=$1
         ) native_scopes")
        .bind::<Jsonb,_>(json!(replacement.actor_id)).get_results::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let known_scopes = groups
        .values()
        .map(|(scope, _)| crate::mls_group_current_states::scope_key(scope))
        .collect::<PersistenceResult<BTreeSet<_>>>()?;
    for row in discovered {
        let scope: ScopeRef = serde_json::from_value(row.payload).map_err(invalid)?;
        if !known_scopes.contains(&crate::mls_group_current_states::scope_key(&scope)?) {
            return Ok(false);
        }
    }
    for (scope, event) in outcomes {
        if !known_scopes.contains(&crate::mls_group_current_states::scope_key(&scope)?) {
            return Ok(false);
        }
        let (original, _) = original_in_scope(conn, &event, &scope).await?;
        if !matches!(original.kind, EventKind::MlsCommit | EventKind::MlsGenesis) {
            return Err(invalid("outcome lacks a winning MLS original"));
        }
    }
    let mut entries = Vec::new();
    for (scope, genesis) in groups.into_values() {
        let Some(entry) = entry(
            heads,
            materials,
            &cut,
            conn,
            service,
            scope,
            genesis,
            &replacement,
        )
        .await?
        else {
            return Ok(false);
        };
        entries.push(entry);
    }
    let now = chrono::Utc::now();
    if valid_until.is_some_and(|until| until <= now)
        || heads.values().any(|assertion| assertion.expires_at <= now)
    {
        return Ok(false);
    }
    let inventory = ContentRecoveryInventory {
        actor_id: replacement.actor_id.clone(),
        replacement,
        authorization_event_ref: authorization.clone(),
        pcr_cut: cut,
        entries,
    };
    let digest =
        arkret_crypto::content_history::recovery_inventory_digest(&inventory).map_err(invalid)?;
    let bytes = arkret_canonical::canonical_json_bytes(&inventory).map_err(invalid)?;
    let sha = arkret_canonical::sha256_hex(&bytes);
    let reference = format!("ak:blob:sha256:{sha}");
    let inserted=sql_query("INSERT INTO blobs(id,sha256,media_type,uploaded_by,size_bytes,storage_backend,storage_key,visibility) VALUES($1,$2,'application/json',$3,$4,'recovery_inventory',$5,'device_bound') ON CONFLICT DO NOTHING")
        .bind::<Text,_>(&reference).bind::<Text,_>(&sha).bind::<Text,_>(inventory.actor_id.to_string()).bind::<BigInt,_>(i64::try_from(bytes.len()).map_err(invalid)?)
        .bind::<Text,_>(authorization.as_str()).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(invalid("Blob address already reserved"));
    }
    sql_query("INSERT INTO content_recovery_inventory_blobs(blob_ref,authorization_event_ref,inventory_digest,canonical_bytes) VALUES($1,$2,$3,$4)")
        .bind::<Text,_>(&reference).bind::<Text,_>(authorization.as_str()).bind::<Text,_>(digest.as_str()).bind::<Binary,_>(&bytes)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let published=sql_query("UPDATE content_recovery_episodes SET state='prepared',inventory_blob_ref=$2 WHERE authorization_event_ref=$1 AND state='pending' AND inventory_blob_ref IS NULL")
        .bind::<Text,_>(authorization.as_str()).bind::<Text,_>(&reference).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if published != 1 {
        return Err(invalid("episode changed during publication"));
    }
    Ok(true)
}

fn field<'a>(source: &'a Value, key: &str) -> PersistenceResult<&'a str> {
    source[key]
        .as_str()
        .ok_or_else(|| invalid(format!("missing {key}")))
}

pub(super) async fn sweep(
    pool: &PgPool,
    service: &DidCoreId,
    materials: Option<&dyn coland_storage::RecoveryInventoryPublicMaterial>,
) -> PersistenceResult<usize> {
    let mut conn = pg_conn(pool).await?;
    let pending=sql_query("SELECT to_jsonb(authorization_event_ref) AS payload FROM content_recovery_episodes WHERE state='pending' AND security_completed_at IS NULL ORDER BY created_at,authorization_event_ref")
        .get_results::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    drop(conn);
    let mut count = 0;
    let mut first_error = None;
    for row in pending {
        let authorization: EventId = serde_json::from_value(row.payload).map_err(invalid)?;
        let heads = match confirm_governors(pool, &authorization, service, materials).await {
            Ok(heads) => heads,
            Err(error) => {
                first_error.get_or_insert(error);
                continue;
            }
        };
        let mut conn = pg_conn(pool).await?;
        match conn
            .transaction::<_, PgTransactionError, _>(async |conn| {
                Ok(prepare(&heads, materials, conn, service, &authorization).await?)
            })
            .await
        {
            Ok(true) => count += 1,
            Ok(false) => (),
            Err(error) => {
                first_error.get_or_insert_with(|| error.into_persistence());
            }
        }
    }
    first_error.map_or(Ok(count), Err)
}
