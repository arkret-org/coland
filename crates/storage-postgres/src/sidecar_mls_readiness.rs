//! Endpoint readiness consumes formal delivery/claim evidence at the read cut.
use arkret_wire::{ActorId, EventId, MlsWelcomeDelivery, MlsWelcomeRecipientEndpoint, ScopeRef};
use diesel::sql_types::{Binary, Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName};
use diesel_async::RunQueryDsl;

#[derive(QueryableByName)]
struct Evidence {
    #[diesel(sql_type = Jsonb)]
    delivery: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    receipt: serde_json::Value,
    #[diesel(sql_type = Text)]
    claim_request_id: String,
    #[diesel(sql_type = Text)]
    keypackage_ref: String,
}

#[derive(QueryableByName)]
struct PublicState {
    #[diesel(sql_type = Binary)]
    public_state: Vec<u8>,
}

#[derive(QueryableByName)]
struct AcceptedGroup {
    #[diesel(sql_type = Binary)]
    public_state: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    genesis: serde_json::Value,
}

/// Validate every occupied endpoint, including leaves outside the projected
/// desired subset. Accepted Add/Genesis provenance pins the endpoint and its
/// authorization dot; a newer authorization for the same Actor is not a lease
/// for an old leaf. Pending desired endpoints need not have a leaf yet.
pub(crate) async fn tree_authorized_in_connection(
    conn: &mut crate::AsyncPgConnection,
    cut: &crate::sidecar_authority_cut::SidecarParticipantAuthorityCut,
    current: &arkret_wire::MlsGroupCurrent,
    public_state: &[u8],
    candidate: Option<&coland_storage::AuthorityCommitTransaction>,
) -> coland_storage::PersistenceResult<bool> {
    use coland_storage::PersistenceError;
    use diesel::sql_types::Jsonb;
    let scope = ScopeRef::Sidecar {
        realm_id: cut.realm_id.clone(),
        sidecar_id: cut.sidecar_id.clone(),
    };
    if current.effective_scope != scope {
        return Ok(false);
    }
    let group = scope
        .canonical_mls_group_id()
        .map_err(PersistenceError::database)?;
    let leaves =
        arkret_mls::MlsPublicGroupTracker::restore(public_state, group.as_str(), current.epoch)
            .and_then(|tracker| tracker.leaves())
            .map_err(PersistenceError::database)?;
    for leaf in leaves {
        let Some(account) = leaf.actor_id.as_account_id() else {
            return Ok(false);
        };
        if account != &cut.controller_account_id
            && (account.station_id != cut.controller_account_id.station_id
                || !cut.desired_agent_ids.contains(&account.principal_id))
        {
            return Ok(false);
        }
        let Some((endpoint, authorization)) =
            leaf_origin_in_connection(conn, current, &leaf, candidate).await?
        else {
            return Ok(false);
        };
        match endpoint {
            MlsWelcomeRecipientEndpoint::Device { device_id } => {
                if account != &cut.controller_account_id {
                    return Ok(false);
                }
                let Some(status) =
                    crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
                        conn,
                        account,
                        &device_id,
                        chrono::Utc::now(),
                    )
                    .await
                    .map_err(crate::PgTransactionError::into_persistence)?
                else {
                    return Ok(false);
                };
                if status.lifecycle != crate::pcr_device_status_fold::PcrDeviceLifecycle::Active {
                    return Ok(false);
                }
                let Some(source) = status.authority.authorization else {
                    return Ok(false);
                };
                if source.event_id != authorization {
                    return Ok(false);
                }
                let Some(key) = source
                    .payload
                    .device_public_key_did
                    .as_str()
                    .strip_prefix("did:key:")
                else {
                    return Ok(false);
                };
                let key = arkret_canonical::multibase::decode_ed25519_multibase(key)
                    .map_err(PersistenceError::database)?;
                if arkret_canonical::base64url_encode(key) != leaf.signature_key.as_str() {
                    return Ok(false);
                }
            }
            MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method,
            } => {
                if account == &cut.controller_account_id {
                    return Ok(false);
                }
                #[derive(QueryableByName)]
                struct RuntimeRow {
                    #[diesel(sql_type = Jsonb)]
                    value: serde_json::Value,
                    #[diesel(sql_type = Text)]
                    agent_key_id: String,
                }
                let keys = diesel::sql_query("SELECT k.value,k.agent_key_id FROM agent_key_current_results k \
                    JOIN agent_status_current_results s ON s.realm_id=k.realm_id AND s.agent_id=k.agent_id \
                    JOIN realm_commits c ON c.realm_id=k.realm_id AND c.commit_id=k.current_commit_id AND c.stream_position=k.current_stream_position \
                    JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
                    WHERE k.agent_id=$1 AND s.actor_id=$2::jsonb")
                    .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(leaf.actor_id.to_string())
                    .load::<RuntimeRow>(&mut *conn).await.map_err(PersistenceError::database)?;
                let tag = format!("{}:1", authorization);
                let mut authorized = false;
                for key in keys {
                    let Some(entries) = key
                        .value
                        .get("authorizations")
                        .and_then(serde_json::Value::as_array)
                    else {
                        return Ok(false);
                    };
                    for entry in entries {
                        if entry.get("tag_id").and_then(serde_json::Value::as_str)
                            != Some(tag.as_str())
                        {
                            continue;
                        }
                        let payload: arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload =
                            serde_json::from_value(entry["value"].clone()).map_err(PersistenceError::database)?;
                        if payload.agent_id != account.principal_id
                            || payload.key_id.as_str() != key.agent_key_id
                            || payload.verification_method != verification_method
                            || payload
                                .expires_at
                                .is_some_and(|expiry| expiry <= chrono::Utc::now())
                        {
                            continue;
                        }
                        arkret_signatures::agent::validate_agent_runtime_public_key(
                            &payload.public_key,
                            &verification_method,
                        )
                        .map_err(PersistenceError::database)?;
                        let value = serde_json::to_value(&payload.public_key)
                            .map_err(PersistenceError::database)?;
                        if value.get("key").and_then(serde_json::Value::as_str)
                            != Some(leaf.signature_key.as_str())
                        {
                            continue;
                        }
                        #[derive(QueryableByName)]
                        struct Source {
                            #[diesel(sql_type = Jsonb)]
                            payload: serde_json::Value,
                        }
                        let source = diesel::sql_query("SELECT e.envelope->'payload' AS payload FROM canonical_events e \
                            JOIN realm_commits c ON c.event_pk=e.pk JOIN agent_status_current_results s ON s.realm_id=c.realm_id \
                            WHERE e.envelope->>'event_id'=$1 AND e.state='committed' AND e.kind=$3 \
                            AND e.envelope->'actor_id'=$2::jsonb AND s.actor_id=$2::jsonb")
                            .bind::<Text,_>(authorization.as_str()).bind::<Jsonb,_>(serde_json::to_value(&leaf.actor_id).map_err(PersistenceError::database)?)
                            .bind::<Text,_>(arkret_wire::EventKind::AgentKeyAuthorize.as_str())
                            .get_result::<Source>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                        authorized |= source.is_some_and(|source| serde_json::from_value::<arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload>(source.payload).ok().is_some_and(|original|
                            serde_json::to_value(original).ok() == serde_json::to_value(&payload).ok()));
                    }
                }
                if !authorized {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

async fn leaf_origin_in_connection(
    conn: &mut crate::AsyncPgConnection,
    current: &arkret_wire::MlsGroupCurrent,
    leaf: &arkret_mls::MlsPublicEndpointLeaf,
    candidate: Option<&coland_storage::AuthorityCommitTransaction>,
) -> coland_storage::PersistenceResult<Option<(MlsWelcomeRecipientEndpoint, EventId)>> {
    use arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody;
    use coland_storage::PersistenceError;
    use diesel::sql_types::{BigInt, Jsonb};
    if let Some(candidate) = candidate {
        if candidate.event.kind == arkret_wire::EventKind::MlsGenesis {
            let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
                serde_json::from_value(
                    serde_json::to_value(&candidate.event.payload)
                        .map_err(PersistenceError::database)?,
                )
                .map_err(PersistenceError::database)?;
            if leaf.leaf_index == 0
                && leaf.actor_id == candidate.event.actor_id
                && leaf.signature_key == payload.creator_leaf_authority.leaf_signature_key_b64u
            {
                return Ok(Some((
                    payload.creator_leaf_authority.endpoint,
                    payload.creator_leaf_authority.authorization_event_ref,
                )));
            }
            return Ok(None);
        }
        if candidate
            .mls_state
            .as_ref()
            .and_then(|state| {
                state.consumed_proposals.iter().find(|proposal| {
                    proposal.proposal_type == 1
                        && proposal.target_after.as_ref().is_some_and(|target| {
                            target.leaf_index == leaf.leaf_index
                                && target.actor_id == leaf.actor_id
                                && target.signature_key == leaf.signature_key
                        })
                })
            })
            .is_some()
        {
            for welcome in &candidate.welcomes {
                let Some(witness) = &welcome.roster_witness else {
                    continue;
                };
                let proof: MlsAttestAddRequestBody =
                    serde_json::from_slice(&witness.signed_attest_add_request_canonical_json)
                        .map_err(PersistenceError::database)?;
                proof
                    .validate_claim_binding()
                    .map_err(PersistenceError::database)?;
                let a = proof.attestation;
                if a.effective_scope == current.effective_scope
                    && a.genesis_event_ref == current.genesis_event_ref
                    && a.mls_group_id
                        == current
                            .effective_scope
                            .canonical_mls_group_id()
                            .map_err(PersistenceError::database)?
                    && a.commit_event_ref == candidate.event.event_id
                    && a.epoch == current.epoch
                    && welcome.delivery.commit_event_ref == candidate.event.event_id
                    && welcome.delivery.recipient_actor_id == leaf.actor_id
                    && welcome.delivery.recipient_endpoint == a.endpoint
                    && a.actor_id == leaf.actor_id
                    && a.leaf_signature_key_b64u == leaf.signature_key
                {
                    return Ok(Some((a.endpoint, a.authorization_event_ref)));
                }
            }
            return Ok(None);
        }
    }
    #[derive(QueryableByName)]
    struct Origin {
        #[diesel(sql_type = Jsonb)]
        request_json: serde_json::Value,
    }
    let scope_key = crate::mls_group_current_results::scope_key(&current.effective_scope)?;
    let origin = diesel::sql_query("SELECT a.request_json FROM mls_consumed_proposal_provenance p \
        JOIN mls_add_authority_attestations a ON a.scope_key=p.scope_key AND a.commit_event_ref=p.commit_event_ref AND a.consumed_proposal_ordinal=p.consumed_proposal_ordinal \
        JOIN canonical_events e ON e.envelope->>'event_id'=p.commit_event_ref AND e.state='committed' \
        JOIN realm_commits c ON c.event_pk=e.pk AND c.stream_position=p.commit_stream_position \
        WHERE p.scope_key=$1 AND p.proposal_type=1 AND p.epoch<=$2 AND p.target_after_leaf_index=$3 \
        ORDER BY p.commit_stream_position DESC,p.consumed_proposal_ordinal DESC LIMIT 1")
        .bind::<Text,_>(&scope_key).bind::<BigInt,_>(i64::try_from(current.epoch).map_err(PersistenceError::database)?)
        .bind::<BigInt,_>(i64::from(leaf.leaf_index)).get_result::<Origin>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(origin) = origin {
        let proof: MlsAttestAddRequestBody =
            serde_json::from_value(origin.request_json).map_err(PersistenceError::database)?;
        proof
            .validate_claim_binding()
            .map_err(PersistenceError::database)?;
        let a = proof.attestation;
        return Ok((a.effective_scope == current.effective_scope
            && a.genesis_event_ref == current.genesis_event_ref
            && a.actor_id == leaf.actor_id
            && a.leaf_signature_key_b64u == leaf.signature_key)
            .then_some((a.endpoint, a.authorization_event_ref)));
    }
    let genesis = diesel::sql_query("SELECT e.envelope AS payload FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
        WHERE e.envelope->>'event_id'=$1 AND e.state='committed' AND e.kind='ak.mls.genesis' AND e.envelope->'scope_ref'=$2")
        .bind::<Text,_>(current.genesis_event_ref.as_str()).bind::<Jsonb,_>(serde_json::to_value(&current.effective_scope).map_err(PersistenceError::database)?)
        .get_result::<super::JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(genesis) = genesis else {
        return Ok(None);
    };
    let event: arkret_wire::Event =
        serde_json::from_value(genesis.payload).map_err(PersistenceError::database)?;
    let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
        serde_json::from_value(
            serde_json::to_value(event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
    Ok((leaf.leaf_index == 0
        && event.actor_id == leaf.actor_id
        && payload.creator_leaf_authority.leaf_signature_key_b64u == leaf.signature_key)
        .then_some((
            payload.creator_leaf_authority.endpoint,
            payload.creator_leaf_authority.authorization_event_ref,
        )))
}

pub(crate) async fn controller_device_ready_in_connection(
    conn: &mut crate::AsyncPgConnection,
    cut: &crate::sidecar_authority_cut::SidecarParticipantAuthorityCut,
    current: &arkret_wire::MlsGroupCurrent,
    device: &arkret_wire::DeviceId,
) -> coland_storage::PersistenceResult<bool> {
    use coland_storage::PersistenceError;
    let Some(status) =
        crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
            conn,
            &cut.controller_account_id,
            device,
            chrono::Utc::now(),
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)?
    else {
        return Ok(false);
    };
    if status.lifecycle != crate::pcr_device_status_fold::PcrDeviceLifecycle::Active {
        return Ok(false);
    }
    let Some(authorization) = status.authority.authorization else {
        return Ok(false);
    };
    let key = authorization
        .payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            PersistenceError::SchemaViolation("Sidecar controller key is not did:key".into())
        })?;
    let key = arkret_canonical::multibase::decode_ed25519_multibase(key)
        .map_err(PersistenceError::database)?;
    let key = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(key))
        .map_err(PersistenceError::database)?;
    let actor = ActorId::account(cut.controller_account_id.clone());
    let scope = ScopeRef::Sidecar {
        realm_id: cut.realm_id.clone(),
        sidecar_id: cut.sidecar_id.clone(),
    };
    if current.effective_scope != scope {
        return Ok(false);
    }
    let scope_key = crate::mls_group_current_results::scope_key(&scope)?;
    let group = diesel::sql_query("SELECT g.public_state,e.envelope,genesis.envelope AS genesis FROM mls_group_current_results g \
        JOIN realm_commits c ON c.commit_id=g.current_commit_id AND c.realm_id=g.realm_id AND c.stream_position=g.current_stream_position \
        JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
        JOIN canonical_events genesis ON genesis.envelope->>'event_id'=g.value->>'genesis_event_ref' AND genesis.state='committed' \
        WHERE g.scope_key=$1 AND (g.value->>'epoch')::bigint=$2")
        .bind::<Text,_>(&scope_key).bind::<diesel::sql_types::BigInt,_>(i64::try_from(current.epoch).map_err(PersistenceError::database)?)
        .get_result::<AcceptedGroup>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(group) = group else {
        return Ok(false);
    };
    if !tree_authorized_in_connection(conn, cut, current, &group.public_state, None).await? {
        return Ok(false);
    }
    let event: arkret_wire::Event =
        serde_json::from_value(group.envelope).map_err(PersistenceError::database)?;
    let binding = match event.kind {
        arkret_wire::EventKind::MlsGenesis => serde_json::from_value::<
            arkret_models_collaboration::events_payloads::MlsGenesisPayload,
        >(
            serde_json::to_value(event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?
        .governance_binding,
        arkret_wire::EventKind::MlsCommit => serde_json::from_value::<
            arkret_models_collaboration::events_payloads::MlsCommitPayload,
        >(
            serde_json::to_value(event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?
        .governance_binding()
        .clone(),
        _ => return Ok(false),
    };
    if binding.effective_scope() != &scope
        || binding.sidecar_binding().is_none_or(|binding| {
            binding.participant_authority_digest != cut.participant_authority_digest
                || binding.authority_stream_head != cut.authority_stream_head
        })
    {
        return Ok(false);
    }
    let leaves = arkret_mls::MlsPublicGroupTracker::restore(
        &group.public_state,
        scope
            .canonical_mls_group_id()
            .map_err(PersistenceError::database)?
            .as_str(),
        current.epoch,
    )
    .and_then(|tracker| tracker.leaves())
    .map_err(PersistenceError::database)?;
    if !leaves
        .iter()
        .any(|leaf| leaf.actor_id == actor && leaf.signature_key == key)
    {
        return Ok(false);
    }
    let genesis: arkret_wire::Event =
        serde_json::from_value(group.genesis).map_err(PersistenceError::database)?;
    if genesis.scope_ref == scope
        && genesis.actor_id == actor
        && genesis
            .account_device_producer()
            .map_err(PersistenceError::database)?
            .is_some_and(|producer| producer.device_id == *device)
    {
        return Ok(true);
    }
    consumed_endpoint_in_connection(
        conn,
        &scope,
        &actor,
        &cut.controller_account_id,
        &MlsWelcomeRecipientEndpoint::Device {
            device_id: device.clone(),
        },
        &authorization.event_id,
        &key,
        current.epoch,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Consumed endpoint checks retain group, member, device and readiness inputs."
)]
pub(crate) async fn consumed_endpoint_in_connection(
    conn: &mut crate::AsyncPgConnection,
    scope: &ScopeRef,
    actor: &ActorId,
    owner_account: &arkret_wire::AccountId,
    endpoint: &MlsWelcomeRecipientEndpoint,
    authorization_ref: &EventId,
    signature_key: &arkret_wire::Base64UrlString,
    current_epoch: u64,
) -> coland_storage::PersistenceResult<bool> {
    use arkret_models_crypto::http_bodies::{KeyPackageConsumeReceipt, RecipientMlsDurableSigner};
    use coland_storage::PersistenceError;
    let invalid = |message: &str| PersistenceError::SchemaViolation(message.to_owned());
    let scope_key = crate::mls_group_current_results::scope_key(scope)?;
    let group = scope
        .canonical_mls_group_id()
        .map_err(PersistenceError::database)?;
    let public = diesel::sql_query("SELECT public_state FROM mls_group_current_results WHERE scope_key=$1 AND (value->>'epoch')::bigint=$2")
        .bind::<Text,_>(&scope_key).bind::<diesel::sql_types::BigInt,_>(i64::try_from(current_epoch).map_err(PersistenceError::database)?)
        .get_result::<PublicState>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(public) = public else {
        return Ok(false);
    };
    let leaves = arkret_mls::MlsPublicGroupTracker::restore(
        &public.public_state,
        group.as_str(),
        current_epoch,
    )
    .and_then(|tracker| tracker.leaves())
    .map_err(PersistenceError::database)?;
    // An old consume receipt does not make a removed or replaced leaf ready.
    // The caller supplies the key from its accepted current authorization.
    if !leaves
        .iter()
        .any(|leaf| leaf.actor_id == *actor && leaf.signature_key == *signature_key)
    {
        return Ok(false);
    }
    let token = crate::ids::parse_event_id(authorization_ref.as_str())
        .ok_or_else(|| invalid("Sidecar endpoint authorization ref is invalid"))?;
    let account = actor
        .as_account_id()
        .ok_or_else(|| invalid("Sidecar endpoint actor is not an Account"))?;
    // Agent packages belong to their controller's local Account; device
    // packages belong to the recipient itself. Both keep the exact Station.
    if owner_account.station_id != account.station_id
        || (matches!(endpoint, MlsWelcomeRecipientEndpoint::Device { .. })
            && owner_account != account)
    {
        return Ok(false);
    }
    let (device, method) = match endpoint {
        MlsWelcomeRecipientEndpoint::Device { device_id } => (device_id.as_str(), ""),
        MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method,
        } => ("", verification_method.as_str()),
    };
    let evidence = diesel::sql_query("SELECT convert_from(w.delivery_canonical_json,'UTF8')::jsonb AS delivery, \
        p.consume_receipt AS receipt,p.claim_request_id,k.keypackage_ref \
        FROM mls_key_packages k JOIN accounts a ON a.principal_id=k.owner_account_id->>'principal_id' AND a.station_id=k.owner_account_id->>'station_id' \
        JOIN peer_keypackage_claims p ON p.keypackage_id=k.id \
        JOIN keypackage_claim_welcome_bindings b ON b.source_id=p.source_id AND b.claim_request_id=p.claim_request_id \
        JOIN mls_welcome_provenance w ON w.claim_id=b.claim_id AND w.welcome_id=b.welcome_id AND w.commit_event_ref=b.commit_event_ref \
        JOIN canonical_events e ON e.envelope->>'event_id'=w.commit_event_ref AND e.state='committed' \
        JOIN realm_commits c ON c.event_pk=e.pk \
        JOIN mls_group_current_results g ON g.scope_key=w.scope_key \
        WHERE k.actor_id=$1 AND a.principal_id=$9 AND a.station_id=$3 AND w.scope_key=$2 AND w.recipient_station_id=$3 \
        AND p.state='consumed' AND p.consume_receipt IS NOT NULL \
        AND b.welcome_digest=w.delivery_digest AND c.stream_ref=jsonb_build_object('kind','sidecar','realm_id',w.realm_id,'sidecar_id',$4) \
        AND c.stream_position<=g.current_stream_position \
        AND (($5<>'' AND k.device_id=$5 AND k.device_authorize_event_id=$7) \
          OR ($6<>'' AND k.endpoint_verification_method=$6 AND k.agent_key_authorize_event_id=$7)) \
        AND ((NOT k.last_resort AND p.key_package_use='single_use' AND k.consumed_at IS NOT NULL AND k.claimed_by_mls_group_id=$8) \
          OR (k.last_resort AND p.key_package_use='last_resort'))")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(&scope_key).bind::<Text,_>(account.station_id.as_str())
        .bind::<Text,_>(scope.sidecar_id().ok_or_else(|| invalid("Sidecar readiness requires native scope"))?.as_str())
        .bind::<Text,_>(device).bind::<Text,_>(method).bind::<Binary,_>(token.to_vec()).bind::<Text,_>(group.as_str()).bind::<Text,_>(owner_account.principal_id.as_str())
        .load::<Evidence>(&mut *conn).await.map_err(PersistenceError::database)?;
    for evidence in evidence {
        let delivery: MlsWelcomeDelivery =
            serde_json::from_value(evidence.delivery).map_err(PersistenceError::database)?;
        let receipt: KeyPackageConsumeReceipt =
            serde_json::from_value(evidence.receipt).map_err(PersistenceError::database)?;
        delivery
            .validate_shape()
            .map_err(PersistenceError::database)?;
        receipt.validate_shape().map_err(invalid)?;
        let durable = &receipt.recipient_durable_receipt;
        // The terminal receipt addresses the consume command, not the
        // original peer claim command retained by the claim ledger.
        let consume = arkret_models_crypto::KeyPackagesConsumeUnsignedRequest {
            claim_id: receipt.claim_id.clone(),
            recipient_durable_receipt: durable.clone(),
        };
        let consume_digest =
            arkret_canonical::canonical_sha256(&consume).map_err(PersistenceError::database)?;
        let signer_matches = match (&durable.recipient, endpoint) {
            (
                RecipientMlsDurableSigner::Device {
                    recipient_account_id,
                    recipient_device_id,
                    ..
                },
                MlsWelcomeRecipientEndpoint::Device { device_id },
            ) => recipient_account_id == account && recipient_device_id == device_id,
            (
                RecipientMlsDurableSigner::Agent {
                    recipient_agent_id,
                    recipient_agent_verification_method,
                    agent_key_authorize_event_id,
                },
                MlsWelcomeRecipientEndpoint::AgentRuntime {
                    verification_method,
                },
            ) => {
                recipient_agent_id == &account.principal_id
                    && recipient_agent_verification_method == verification_method
                    && agent_key_authorize_event_id == authorization_ref
            }
            _ => false,
        };
        if delivery.effective_scope == *scope
            && delivery.recipient_actor_id == *actor
            && delivery.recipient_endpoint == *endpoint
            && receipt.claim_id == delivery.keypackage_claim_ref
            && durable.welcome_ref == delivery.welcome_id
            && durable.welcome_digest
                == delivery
                    .durable_receipt_digest()
                    .map_err(PersistenceError::database)?
            && durable.claim_request_id.as_str() == evidence.claim_request_id
            && receipt.request_digest.as_str() == consume_digest
            && durable.key_package_ref.as_str() == evidence.keypackage_ref
            && durable.recipient_id == account.station_id
            && durable.realm_id == *scope.realm_id()
            && durable.mls_group_id == group
            && durable.mls_epoch <= current_epoch
            && signer_matches
        {
            return Ok(true);
        }
    }
    Ok(false)
}
