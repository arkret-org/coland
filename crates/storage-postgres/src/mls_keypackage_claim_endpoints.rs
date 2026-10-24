//! Current local claim endpoints, derived from their accepted SDK originals.
#[cfg(test)]
#[path = "mls_keypackage_claim_endpoints_tests.rs"]
mod tests;
use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload;
use arkret_models_crypto::{
    KeyPackagesClaimRequestBody, KeyPackagesClaimResponseBody, PeerKeyPackageRequesterAuthorization,
};
use arkret_wire::{
    AccountId, ActorId, CommittedEventRef, DeviceId, DidCoreId, DidUrl, EventId, EventKind, RealmId,
};

use super::*;

fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}

#[derive(Clone)]
pub(crate) struct EndpointWindow {
    not_before: Option<chrono::DateTime<Utc>>,
    expires_at: Option<chrono::DateTime<Utc>>,
}
impl EndpointWindow {
    pub(crate) fn permits_at(&self, at: chrono::DateTime<Utc>) -> bool {
        self.not_before.is_none_or(|start| at >= start)
            && self.expires_at.is_none_or(|end| at < end)
    }
}
enum Endpoint {
    RemoteDevice,
    RealmDevice {
        authority: Box<coland_storage::AppletManagedDeviceAuthority>,
    },
    Device {
        account: AccountId,
        device: DeviceId,
        original: CommittedEventRef,
    },
    Agent {
        agent: DidCoreId,
        method: DidUrl,
        original: CommittedEventRef,
    },
}
pub(crate) struct ClaimEndpoint {
    realm: RealmId,
    endpoint: Endpoint,
    window: EndpointWindow,
}
impl ClaimEndpoint {
    pub(crate) fn realm(&self) -> &RealmId {
        &self.realm
    }
    pub(crate) fn window(&self) -> EndpointWindow {
        self.window.clone()
    }
    pub(crate) async fn require_current(
        &self,
        conn: &mut AsyncPgConnection,
    ) -> PersistenceResult<()> {
        let at = Utc::now();
        if !self.window.permits_at(at) {
            return Err(denied("claim endpoint authorization window ended"));
        }
        match &self.endpoint {
            // The origin-signed evidence was checked in prepare; only its
            // unchanged bounded window can be held across this local cut.
            Endpoint::RemoteDevice => {}
            Endpoint::RealmDevice { authority } => {
                let current = crate::realm_actor_device_authority::current_in_connection(
                    conn,
                    &authority.actor_id,
                    &authority.device_id,
                    at,
                )
                .await
                .map_err(crate::PgTransactionError::into_persistence)?;
                if current.as_ref() != Some(authority) {
                    return Err(denied("Realm claim Device authorization instance changed"));
                }
            }
            Endpoint::Device {
                account,
                device,
                original,
            } => {
                let cut =
                    crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
                        conn, account, device, at,
                    )
                    .await
                    .map_err(crate::PgTransactionError::into_persistence)?
                    .ok_or_else(|| denied("claim Device current is absent"))?;
                if cut.admission().error_code().is_some() || cut.authority.realm_id != self.realm {
                    return Err(denied("claim Device is no longer admitted"));
                }
                let authorization = cut
                    .authority
                    .authorization
                    .ok_or_else(|| denied("claim Device authorization is absent"))?;
                if authorization.event_id != original.event_id
                    || authorization.source_commit_id != original.commit_id
                {
                    return Err(denied("claim Device authorization instance changed"));
                }
                let inactive=sql_query("SELECT EXISTS(SELECT 1 FROM account_lifecycle l JOIN accounts a ON a.pk=l.account_pk WHERE a.principal_id=$1 AND a.station_id=$2 AND l.state<>'active') AS present")
                    .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str()).get_result::<ExistsRow>(&mut *conn).await.map_err(PersistenceError::database)?;
                if inactive.present {
                    return Err(denied("claim Account is inactive"));
                }
            }
            Endpoint::Agent {
                agent,
                method,
                original,
            } => {
                // Fail rather than form a wait cycle with a concurrent Agent
                // producer. The actual current checker reacquires this same
                // transaction-local lock without opening another connection.
                let locked = sql_query(
                    "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0)) AS present",
                )
                .bind::<Text, _>(format!("agent-producer-current:{}:{}", self.realm, agent))
                .get_result::<ExistsRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
                if !locked.present {
                    return Err(PersistenceError::Conflict(
                        "temporarily_unavailable: claim Agent current is busy".into(),
                    ));
                }
                crate::boxed_future(|| {
                    crate::authority_commit::check_agent_endpoint_current_in_connection(
                        conn,
                        &self.realm,
                        agent,
                        original,
                        method,
                        at,
                    )
                })
                .await?;
            }
        }
        if !self.window.permits_at(Utc::now()) {
            return Err(denied("claim endpoint expired during current verification"));
        }
        Ok(())
    }
}

async fn original(
    conn: &mut AsyncPgConnection,
    event: &EventId,
) -> PersistenceResult<arkret_wire::CommittedEventFullView> {
    crate::committed_disclosure::accepted_full_event_in_connection(conn, event)
        .await?
        .ok_or_else(|| denied("claim endpoint original is not accepted"))
}

/// A local source Station must verify its participant at the held cut rather
/// than treating its own transport signature as a remote source attestation.
pub(crate) async fn require_local_requester_signature(
    conn: &mut AsyncPgConnection,
    request: &KeyPackagesClaimRequestBody,
) -> PersistenceResult<()> {
    let (method, signature, key) = match &request.requester_authorization {
        PeerKeyPackageRequesterAuthorization::Device {
            verification_method,
            requester_device_id,
            device_authorize_event_id,
            signature,
            ..
        } => {
            let account = request
                .requester_account_id
                .as_ref()
                .ok_or_else(|| denied("Device requester Account is absent"))?;
            let full = original(conn, device_authorize_event_id).await?;
            let payload: DeviceAuthorizePayload =
                serde_json::from_value(serde_json::to_value(&full.event.payload).map_err(denied)?)
                    .map_err(denied)?;
            payload.validate_wire_constraints().map_err(denied)?;
            let (controller, fragment) = verification_method
                .as_str()
                .rsplit_once('#')
                .ok_or_else(|| denied("Device method has no fragment"))?;
            let principal = arkret_wire::Did::new(controller)
                .and_then(|did| arkret_wire::project_did_to_core_id(&did))
                .map_err(denied)?;
            if full.event.kind != EventKind::DeviceAuthorize
                || full.event.actor_id != ActorId::account(account.clone())
                || payload.device_id != *requester_device_id
                || fragment != requester_device_id.as_str()
                || principal != account.principal_id
                || account.station_id != request.service_binding.source_id
            {
                return Err(denied(
                    "Device requester differs from its accepted authorization",
                ));
            }
            let multibase = payload
                .device_public_key_did
                .as_str()
                .strip_prefix("did:key:")
                .ok_or_else(|| denied("Device key is not did:key"))?;
            let key = arkret_canonical::decode_ed25519_multibase(multibase).map_err(denied)?;
            (verification_method, signature, key)
        }
        PeerKeyPackageRequesterAuthorization::Agent {
            verification_method,
            requester_agent_id,
            agent_key_authorize_event_id,
            signature,
            ..
        } => {
            let full = original(conn, agent_key_authorize_event_id).await?;
            let payload: AgentKeyAuthorizePayload =
                serde_json::from_value(serde_json::to_value(&full.event.payload).map_err(denied)?)
                    .map_err(denied)?;
            if full.event.kind != EventKind::AgentKeyAuthorize
                || payload.agent_id != *requester_agent_id
                || payload.verification_method != *verification_method
                || payload.public_key.algorithm.as_str() != "Ed25519"
            {
                return Err(denied(
                    "Agent requester differs from its accepted authorization",
                ));
            }
            let key: [u8; 32] = arkret_canonical::base64url_decode(payload.public_key.key.as_str())
                .map_err(denied)?
                .try_into()
                .map_err(|_| denied("Agent key is not Ed25519"))?;
            (verification_method, signature, key)
        }
        PeerKeyPackageRequesterAuthorization::RealmDevice {
            verification_method,
            requester_device_id,
            device_authorize_event_id,
            signature,
            ..
        } => {
            let actor = request
                .requester_actor_id
                .as_ref()
                .ok_or_else(|| denied("Realm requester Actor is absent"))?;
            let authority = crate::realm_actor_device_authority::current_in_connection(
                conn,
                actor,
                requester_device_id,
                Utc::now(),
            )
            .await
            .map_err(crate::PgTransactionError::into_persistence)?
            .ok_or_else(|| denied("Realm requester Device is unavailable"))?;
            if authority.authorization_ref.event_id != *device_authorize_event_id
                || authority.governance_service_id != request.service_binding.source_id
                || verification_method.as_str()
                    != format!("{}#{}", authority.native_did, authority.device_id)
            {
                return Err(denied("Realm requester differs from its accepted Device"));
            }
            (verification_method, signature, authority.public_key)
        }
    };
    let input = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )
    .map_err(denied)?;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &key,
        method.as_str(),
        &input,
        signature,
    )
    .map_err(denied)
}
fn reference(full: &arkret_wire::CommittedEventFullView) -> CommittedEventRef {
    CommittedEventRef {
        event_id: full.event.event_id.clone(),
        commit_id: full.commit.commit_id.clone(),
        stream_ref: full.commit.stream_ref.clone(),
        stream_position: full.commit.stream_position,
    }
}
async fn device(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    id: &DeviceId,
    event: &EventId,
) -> PersistenceResult<ClaimEndpoint> {
    let full = original(conn, event).await?;
    let payload: DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&full.event.payload).map_err(denied)?)
            .map_err(denied)?;
    payload.validate_wire_constraints().map_err(denied)?;
    if full.event.kind != EventKind::DeviceAuthorize
        || full.event.actor_id != ActorId::account(account.clone())
        || payload.device_id != *id
    {
        return Err(denied(
            "claim Device original differs from its exact Account and Device",
        ));
    }
    Ok(ClaimEndpoint {
        realm: full.event.realm_id.clone(),
        endpoint: Endpoint::Device {
            account: account.clone(),
            device: id.clone(),
            original: reference(&full),
        },
        window: EndpointWindow {
            not_before: Some(payload.not_before),
            expires_at: payload.expires_at.flatten(),
        },
    })
}
async fn realm_device(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    id: &DeviceId,
    event: &EventId,
    station: &DidCoreId,
    scope: &arkret_wire::ScopeRef,
) -> PersistenceResult<ClaimEndpoint> {
    let authority =
        crate::realm_actor_device_authority::current_in_connection(conn, actor, id, Utc::now())
            .await
            .map_err(crate::PgTransactionError::into_persistence)?
            .ok_or_else(|| denied("Realm claim Device authority is unavailable"))?;
    if authority.authorization_ref.event_id != *event
        || authority.governance_service_id != *station
        || !authority.scopes.contains_scope(scope)
        || &authority.realm_id != scope.realm_id()
    {
        return Err(denied(
            "Realm claim Device scope, governor or original changed",
        ));
    }
    Ok(ClaimEndpoint {
        realm: authority.realm_id.clone(),
        window: EndpointWindow {
            not_before: Some(authority.not_before),
            expires_at: Some(authority.expires_at),
        },
        endpoint: Endpoint::RealmDevice {
            authority: Box::new(authority),
        },
    })
}

async fn group_scope(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    group: &arkret_wire::MlsGroupId,
) -> PersistenceResult<arkret_wire::ScopeRef> {
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }
    let row = sql_query("SELECT value FROM mls_group_current_states WHERE realm_id=$1 AND mls_group_id=$2 FOR SHARE")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(group.as_str())
        .get_result::<Row>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| denied("accepted MLS group scope unavailable"))?;
    let current: arkret_wire::MlsGroupValue = serde_json::from_value(row.value).map_err(denied)?;
    let scope = current.effective_scope;
    if scope.realm_id() != realm
        || !matches!(
            scope,
            arkret_wire::ScopeRef::Realm { .. } | arkret_wire::ScopeRef::Circle { .. }
        )
        || scope.canonical_mls_group_id().map_err(denied)? != *group
    {
        return Err(denied("accepted MLS group scope differs from claim"));
    }
    Ok(scope)
}

async fn agent(
    conn: &mut AsyncPgConnection,
    id: &DidCoreId,
    method: &DidUrl,
    event: &EventId,
) -> PersistenceResult<ClaimEndpoint> {
    let full = original(conn, event).await?;
    let payload: AgentKeyAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&full.event.payload).map_err(denied)?)
            .map_err(denied)?;
    if full.event.kind != EventKind::AgentKeyAuthorize
        || payload.agent_id != *id
        || payload.verification_method != *method
    {
        return Err(denied(
            "claim Agent original differs from its exact current method",
        ));
    }
    Ok(ClaimEndpoint {
        realm: full.event.realm_id.clone(),
        endpoint: Endpoint::Agent {
            agent: id.clone(),
            method: method.clone(),
            original: reference(&full),
        },
        window: EndpointWindow {
            not_before: Some(payload.issued_at),
            expires_at: payload.expires_at,
        },
    })
}

/// Remote participant authority belongs to its authenticated origin Station.
/// Every local source and target is instead re-read under the real local PCR.
pub(crate) async fn prepare(
    conn: &mut AsyncPgConnection,
    outcome: &KeyPackagesClaimResponseBody,
    command: Option<&KeyPackagesClaimRequestBody>,
    station: &DidCoreId,
    remote_devices: &[coland_storage::MlsClaimRemoteDeviceEvidence],
) -> PersistenceResult<Vec<ClaimEndpoint>> {
    outcome.validate_shape().map_err(denied)?;
    let mut result = Vec::new();
    if let Some(command) = command {
        if arkret_canonical::canonical_sha256(command).map_err(denied)?
            != outcome.claim_receipt.request_digest.as_str()
        {
            return Err(denied(
                "delivery command differs from original receipt digest",
            ));
        }
        if &command.service_binding.source_id == station {
            match &command.requester_authorization {
                PeerKeyPackageRequesterAuthorization::Device {
                    requester_device_id,
                    device_authorize_event_id,
                    ..
                } => {
                    let account = command
                        .requester_account_id
                        .as_ref()
                        .filter(|account| &account.station_id == station)
                        .ok_or_else(|| denied("local Device requester route differs"))?;
                    result.push(
                        device(
                            conn,
                            account,
                            requester_device_id,
                            device_authorize_event_id,
                        )
                        .await?,
                    );
                }
                PeerKeyPackageRequesterAuthorization::RealmDevice {
                    requester_device_id,
                    device_authorize_event_id,
                    ..
                } => {
                    let scope =
                        group_scope(conn, &command.intended_realm_id, &command.mls_group_id)
                            .await?;
                    result.push(
                        realm_device(
                            conn,
                            command
                                .requester_actor_id
                                .as_ref()
                                .ok_or_else(|| denied("Realm requester Actor absent"))?,
                            requester_device_id,
                            device_authorize_event_id,
                            station,
                            &scope,
                        )
                        .await?,
                    );
                }
                PeerKeyPackageRequesterAuthorization::Agent {
                    requester_agent_id,
                    verification_method,
                    agent_key_authorize_event_id,
                    ..
                } => result.push(
                    agent(
                        conn,
                        requester_agent_id,
                        verification_method,
                        agent_key_authorize_event_id,
                    )
                    .await?,
                ),
            }
        }
    }
    for claim in &outcome.claims {
        if claim.actor_id.as_realm_actor_id().is_some() {
            let request = &outcome.claim_receipt.request;
            let scope =
                group_scope(conn, &request.intended_realm_id, &request.mls_group_id).await?;
            result.push(
                realm_device(
                    conn,
                    &claim.actor_id,
                    claim
                        .device_id
                        .as_ref()
                        .ok_or_else(|| denied("Realm claim Device absent"))?,
                    claim
                        .device_authorize_event_id
                        .as_ref()
                        .ok_or_else(|| denied("Realm claim authorization absent"))?,
                    station,
                    &scope,
                )
                .await?,
            );
            continue;
        }
        if claim.actor_id.fixed_route_service_id() != Some(station) {
            let request = &outcome.claim_receipt.request;
            if request
                .requester_actor_id
                .as_ref()
                .and_then(ActorId::as_realm_actor_id)
                .is_none_or(|actor| actor.realm_id != request.intended_realm_id)
                || command.is_none()
            {
                return Err(denied(
                    "remote target requires its original Realm source command",
                ));
            }
            let window = remote_device_window(claim, remote_devices)?;
            result.push(ClaimEndpoint {
                realm: request.intended_realm_id.clone(),
                endpoint: Endpoint::RemoteDevice,
                window,
            });
            continue;
        }
        match (
            &claim.device_id,
            &claim.device_authorize_event_id,
            &claim.agent_id,
            &claim.agent_verification_method,
            &claim.agent_key_authorize_event_id,
        ) {
            (Some(id), Some(event), None, None, None) => {
                let account = claim
                    .actor_id
                    .as_account_id()
                    .ok_or_else(|| denied("claim Device omits full Account"))?;
                result.push(device(conn, account, id, event).await?);
            }
            (None, None, Some(id), Some(method), Some(event)) => {
                result.push(agent(conn, id, method, event).await?)
            }
            _ => return Err(denied("claim target endpoint branch is incomplete")),
        }
    }
    Ok(result)
}

pub(crate) fn remote_device_window(
    claim: &arkret_models_crypto::KeyPackageClaimRecord,
    evidence: &[coland_storage::MlsClaimRemoteDeviceEvidence],
) -> PersistenceResult<EndpointWindow> {
    let account = claim
        .actor_id
        .as_account_id()
        .ok_or_else(|| denied("remote claim must target an ordinary Account Device"))?;
    let device = claim
        .device_id
        .as_ref()
        .ok_or_else(|| denied("remote claim Device is absent"))?;
    let mut matches = evidence
        .iter()
        .filter(|e| &e.account_id == account && &e.device_id == device);
    let evidence = matches
        .next()
        .ok_or_else(|| denied("remote claim evidence absent"))?;
    if matches.next().is_some() {
        return Err(denied("remote claim evidence is ambiguous"));
    }
    evidence
        .record
        .validate_attestation_binding(account, device)
        .map_err(denied)?;
    let attestation = &evidence.record.device_projection_attestation;
    let core = &attestation.attestation;
    if &evidence.generation.account_id != account
        || evidence
            .generation
            .generation_state
            .current_device_generation_ref
            != core.authorized_generation_ref
        || claim.device_authorize_event_id.as_ref() != Some(&core.device_authorize_event_id)
        || evidence.issuer_resolution.service_kind != "station"
    {
        return Err(denied(
            "remote claim generation or exact authorization differs",
        ));
    }
    let document = arkret_identity::authenticated_service_document_at(
        &evidence.issuer_resolution,
        &account.station_id,
        core.attested_at,
    )
    .map_err(denied)?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        &attestation.proof.verification_method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(denied)?;
    let key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        &document,
        attestation.proof.verification_method.as_str(),
    )
    .map_err(denied)?;
    arkret_signatures::device_projection::verify_device_projection_attestation(
        attestation,
        &key,
        Utc::now(),
    )
    .map_err(denied)?;
    let device_key = arkret_canonical::decode_ed25519_multibase(
        core.device_signing_key_did
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| denied("remote Device key is not did:key"))?,
    )
    .map_err(denied)?;
    let bytes = arkret_canonical::base64url_decode(&claim.keypackage).map_err(denied)?;
    let leaf = arkret_mls::author_leaf_from_key_package_bytes(&bytes, 0).map_err(denied)?;
    let credential =
        arkret_models_crypto::mls_basic_credential_identity(&claim.actor_id).map_err(denied)?;
    if !matches!(leaf.credential, arkret_mls::AuthorLeafCredential::Basic { identity } if identity == credential)
        || leaf.signature_key.as_slice() != device_key.as_slice()
        || arkret_canonical::sha256_digest(&bytes) != claim.keypackage_ref
    {
        return Err(denied(
            "remote claim leaf differs from original device evidence",
        ));
    }
    arkret_mls::validate_keypackage_capability_binding(&bytes, &claim.capabilities)
        .map_err(denied)?;
    let window = EndpointWindow {
        not_before: Some(core.authorization_window.not_before.max(core.attested_at)),
        expires_at: Some(
            core.expires_at.min(
                core.authorization_window
                    .expires_at
                    .unwrap_or(core.expires_at),
            ),
        ),
    };
    if !window.permits_at(Utc::now()) {
        return Err(denied("remote claim device window ended"));
    }
    Ok(window)
}
