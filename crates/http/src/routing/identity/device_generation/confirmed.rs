//! Device authorization derived from the accepted PCR RealmCommit stream.
//!
//! This read model never promotes a queued Event or a local device mirror into
//! authority. It reconstructs a contiguous committed stream through a fixed
//! head and rejects a concurrent head change before caching the result.

use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceReanchorPayload,
    DeviceRevokePayload,
};
use arkret_wire::{
    AccountId, ActorId, CommitStreamHead, CommitStreamRef, CommittedEventView, DeviceId, EventId,
    EventKind, Hash, RealmCommit, RealmId, StreamScanRequest,
};

use crate::state::AppState;

#[derive(Clone, Debug)]
pub(crate) struct ConfirmedDeviceAuthorization {
    device_id: DeviceId,
    generation: u64,
    event_id: EventId,
}

impl ConfirmedDeviceAuthorization {
    pub(crate) fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub(crate) fn authorized_generation_ref(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ConfirmedDeviceHistory {
    realm_id: RealmId,
    head: CommitStreamHead,
    current_generation: u64,
    managed_applet: Option<arkret_wire::AppletId>,
    authorizations: BTreeMap<EventId, ConfirmedDeviceAuthorization>,
    current_by_device: BTreeMap<DeviceId, EventId>,
}

impl ConfirmedDeviceHistory {
    pub(crate) fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }

    pub(crate) fn confirmed_head(&self) -> &CommitStreamHead {
        &self.head
    }

    pub(crate) fn current_authorization(
        &self,
        device_id: &DeviceId,
    ) -> Option<&ConfirmedDeviceAuthorization> {
        self.current_by_device
            .get(device_id)
            .and_then(|id| self.authorizations.get(id))
            .filter(|authorization| self.is_currently_active(authorization))
    }

    pub(crate) fn is_currently_active(&self, authorization: &ConfirmedDeviceAuthorization) -> bool {
        authorization.generation == self.current_generation
            && self.current_by_device.get(&authorization.device_id) == Some(&authorization.event_id)
    }
}

fn invalid(message: impl std::fmt::Display) -> String {
    format!("invalid accepted PCR device history: {message}")
}

fn unavailable(message: impl std::fmt::Display) -> String {
    format!("accepted PCR device history unavailable: {message}")
}

/// Reverify the original creation against its durable Service root. Current
/// installation liveness and current Service keys are not historical evidence.
async fn verify_managed_genesis(
    state: &AppState,
    account: &AccountId,
    genesis: &arkret_wire::Event,
) -> Result<arkret_wire::AppletId, String> {
    use arkret_models_integration::AppletManagedActorCommittedRequest;

    let context = state
        .persistence()
        .managed_pcr_creation_context(&genesis.event_id)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("managed PCR creation closure is missing"))?;
    context.validate().map_err(invalid)?;
    let (request, bundle) = match &context.committed_request {
        AppletManagedActorCommittedRequest::Bot(body) => {
            (&body.authoring_request, &body.managed_actor_bundle)
        }
        AppletManagedActorCommittedRequest::Ghost(body) => (
            &body.authoring_request,
            body.managed_actor_bundle
                .as_ref()
                .ok_or_else(|| invalid("managed genesis cannot be Ghost reuse"))?,
        ),
    };
    bundle.validate_bindings(request).map_err(invalid)?;
    let service = request.basis.service_id();
    let root = &context
        .applet_service_signer_evidence
        .authenticated_signer_evidence;
    if bundle.pcr_genesis_event != *genesis
        || request.basis.target_station_id() != &account.station_id
        || genesis.executed_by.as_ref() != Some(&ActorId::service(service.clone()))
        || root.subject_id != *service
        || context
            .managed_actor_signer_evidence
            .authenticated_signer_evidence
            .subject_id
            != account.principal_id
    {
        return Err(invalid(
            "managed PCR creation closure names another identity",
        ));
    }
    let key = arkret_signatures::PublicKeyMaterial::Jwk {
        value: serde_json::to_value(&root.public_key_jwk).map_err(invalid)?,
    };
    key.ed25519_bytes().map_err(invalid)?;
    if bundle.proof.verification_method != root.verification_method {
        return Err(invalid("managed creation bundle changed Service method"));
    }
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &bundle.proof.jws,
            &bundle.proof_binding_bytes().map_err(invalid)?,
            &key,
        )
        .map_err(invalid)?;
    for event in [
        &bundle.managed_actor_provision_event,
        &bundle.pcr_genesis_event,
        &bundle.accountability_grant_event,
        &bundle.profile_event,
    ] {
        let suite = event.event_id.digest_suite_code().digest_suite();
        let accepted = state
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("managed creation original is missing"))?;
        if accepted.event != *event {
            return Err(invalid(
                "managed creation original differs from retained closure",
            ));
        }
        event
            .verify_event_id_matches_content_with_digest_suite(suite)
            .map_err(invalid)?;
        let proof = event
            .producer_proof
            .as_ref()
            .ok_or_else(|| invalid("managed creation original omits proof"))?;
        if proof.verification_method != root.verification_method
            || event.actual_signer() != &ActorId::service(service.clone())
        {
            return Err(invalid(
                "managed creation original changed Service producer",
            ));
        }
        arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            proof,
            &arkret_signatures::EventProofBuilder::new()
                .envelope_bytes(event)
                .map_err(invalid)?,
            &event.actor_id,
            &key,
            suite,
        )
        .map_err(invalid)?;
    }
    Ok(match &request.basis {
        arkret_models_integration::AppletManagedActorAuthoringBasis::ProvisionBot(basis) => {
            basis.applet_id.clone()
        }
        arkret_models_integration::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) => {
            basis.applet_id.clone()
        }
    })
}

async fn verify_registered_genesis(
    state: &AppState,
    account: &AccountId,
    genesis: &arkret_wire::Event,
    create: &arkret_models_collaboration::events_payloads::RealmCreatePayload,
) -> Result<(), String> {
    let initial = create
        .object
        .initial_resolution
        .as_ref()
        .ok_or_else(|| unavailable("registered PCR inception resolution is missing"))?;
    let entries = state
        .dids()
        .log_events(initial.did.as_str())
        .await
        .map_err(unavailable)?;
    let mut inception_entries = entries.iter().filter(|entry| entry.seq == 1);
    let entry = inception_entries
        .next()
        .ok_or_else(|| unavailable("registered PCR DID inception is missing"))?;
    if inception_entries.next().is_some() || entry.did != initial.did.as_str() {
        return Err(invalid("PCR DID inception storage is ambiguous"));
    }
    let operation: BTreeMap<String, serde_json::Value> =
        serde_json::from_value(entry.operation.clone()).map_err(invalid)?;
    let normalized_did_document = operation
        .get("state")
        .cloned()
        .ok_or_else(|| invalid("registered DID inception has no state"))
        .and_then(|state| serde_json::from_value(state).map_err(invalid))?;
    let anchor = arkret_models_identity::PrincipalRegistrationAnchor::WebvhRegistration {
        registration_did_operation: Box::new(
            arkret_models_identity::DidOperationSubmitRequestBody {
                did: initial.did.clone(),
                did_method: arkret_models_identity::DidMethodName::Webvh,
                seq: Some(entry.seq),
                prev_event_digest: None,
                operation: operation.clone(),
            },
        ),
        log_entries: vec![operation],
        witness_records: Vec::new(),
        normalized_did_document,
    };
    let root = arkret_identity::validate_principal_registration_anchor(&anchor).map_err(invalid)?;
    if root.principal_id != account.principal_id {
        return Err(invalid(
            "PCR DID inception root differs from Account principal",
        ));
    }
    let proof = genesis
        .producer_proof
        .as_ref()
        .ok_or_else(|| invalid("PCR genesis omits inception-root proof"))?;
    proof.validate_production().map_err(invalid)?;
    if proof.verification_method != root.root_verification_method
        || proof.created_at != genesis.created_at
    {
        return Err(invalid(
            "PCR genesis proof differs from authenticated DID root",
        ));
    }
    let suite = state
        .projections()
        .realm_digest_suite(genesis.realm_id.as_str());
    genesis
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(invalid)?;
    let root_key = arkret_canonical::decode_ed25519_multibase(&root.root_public_key_multibase)
        .map_err(invalid)?;
    let bytes = arkret_signatures::proof::EventProofBuilder::new()
        .envelope_bytes(genesis)
        .map_err(invalid)?;
    arkret_signatures::proof::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &genesis.actor_id,
        &arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
            bytes: root_key.to_vec(),
        },
        suite,
    )
    .map_err(invalid)?;
    Ok(())
}

fn apply_device_event(
    history: &mut ConfirmedDeviceHistory,
    account: &AccountId,
    event: &arkret_wire::Event,
) -> Result<(), String> {
    match event.kind {
        EventKind::DeviceAuthorize => {
            if event.actor_id != ActorId::account(account.clone()) {
                return Err(invalid(
                    "device authorization actor differs from PCR Account",
                ));
            }
            let payload: DeviceAuthorizePayload = event
                .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
                .map_err(invalid)?;
            if let Some(applet) = &history.managed_applet
                && (payload.authorization_binding_kind
                    != DeviceAuthorizationBindingKind::AppletManagedDelegation
                    || payload.applet_id.as_ref() != Some(applet))
            {
                return Err(invalid(
                    "managed PCR device authorization changed its delegation branch",
                ));
            }
            if history.current_generation == 0 {
                if payload.authorization_binding_kind
                    != DeviceAuthorizationBindingKind::RegistrationAnchor
                    || payload.authorized_generation_ref != 1
                {
                    return Err(invalid(
                        "founding device authorization has invalid generation or binding",
                    ));
                }
                history.current_generation = 1;
            } else if payload.authorization_binding_kind
                == DeviceAuthorizationBindingKind::RegistrationAnchor
                || payload.authorized_generation_ref != history.current_generation
            {
                return Err(invalid(
                    "successor device authorization is outside current generation",
                ));
            }
            let authorization = ConfirmedDeviceAuthorization {
                device_id: payload.device_id.clone(),
                generation: payload.authorized_generation_ref,
                event_id: event.event_id.clone(),
            };
            if history
                .authorizations
                .insert(event.event_id.clone(), authorization)
                .is_some()
            {
                return Err(invalid("duplicate committed device authorization Event"));
            }
            history
                .current_by_device
                .insert(payload.device_id, event.event_id.clone());
        }
        EventKind::DeviceReanchor => {
            if history.managed_applet.is_some() {
                return Err(invalid("managed PCR cannot use human device recovery"));
            }
            if event.actor_id != ActorId::account(account.clone()) {
                return Err(invalid("device reanchor actor differs from PCR Account"));
            }
            let payload: DeviceReanchorPayload = event
                .typed_payload::<arkret_wire::event_spec::DeviceReanchor>()
                .map_err(invalid)?;
            if payload.account_id != *account
                || payload.previous_device_generation != history.current_generation
                || Some(payload.new_device_generation) != history.current_generation.checked_add(1)
            {
                return Err(invalid(
                    "device reanchor does not advance the exact current generation",
                ));
            }
            history.current_generation = payload.new_device_generation;
            history.current_by_device.clear();
        }
        EventKind::DeviceRevoke => {
            if event.actor_id != ActorId::account(account.clone()) {
                return Err(invalid("device revoke actor differs from PCR Account"));
            }
            let payload: DeviceRevokePayload = event
                .typed_payload::<arkret_wire::event_spec::DeviceRevoke>()
                .map_err(invalid)?;
            // A committed revoke Event is only the immutable proposal of a
            // SecurityRotation (decision 0102): whether the device is pending,
            // revoked or active again after a rejected result is the PCR
            // device status fold, which every consumer of this history reads
            // at its own cut. The authorization instance stays named here.
            if !history.current_by_device.contains_key(&payload.device_id) {
                return Err(invalid(
                    "committed device revoke has no current authorization",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) async fn load_confirmed_device_history(
    state: &AppState,
    account: &AccountId,
) -> Result<Option<Arc<ConfirmedDeviceHistory>>, String> {
    if account.station_id != state.service_core_id() {
        return Err(invalid(
            "device inventory belongs to a different Station Account",
        ));
    }
    let Some(binding) = state
        .persistence()
        .principal_resolution_by_account_id(account)
        .await
        .map_err(unavailable)?
    else {
        return Ok(None);
    };
    let genesis = &binding.genesis_event;
    if binding.account_id != *account
        || genesis.realm_id != binding.pcr_realm_id
        || genesis.actor_id != ActorId::account(account.clone())
        || genesis.kind != EventKind::RealmCreate
    {
        return Err(invalid(
            "registered PCR genesis does not bind local Account",
        ));
    }
    let create = genesis
        .typed_payload::<arkret_wire::event_spec::RealmCreate>()
        .map_err(invalid)?;
    let managed_applet = match create.object.purpose {
        arkret_models_collaboration::events_payloads::RealmPurpose::PrincipalControl
            if genesis.executed_by.is_none() =>
        {
            verify_registered_genesis(state, account, genesis, &create).await?;
            None
        }
        arkret_models_collaboration::events_payloads::RealmPurpose::AppletManagedControl
            if create.object.founding_device_descriptor.is_none() =>
        {
            Some(verify_managed_genesis(state, account, genesis).await?)
        }
        _ => {
            return Err(invalid(
                "registered PCR genesis has a different Realm purpose",
            ));
        }
    };
    let realm_id = binding.pcr_realm_id.clone();
    let stream_ref = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let Some(head) = state
        .authority_commits()
        .stream_head(&stream_ref)
        .await
        .map_err(unavailable)?
    else {
        return Ok(None);
    };
    if let Some(cached) = state.device_history_cache.lock().await.get(account)
        && cached.confirmed_head() == &head
    {
        return Ok(Some(cached.clone()));
    }
    let mut history = ConfirmedDeviceHistory {
        realm_id: realm_id.clone(),
        head: head.clone(),
        current_generation: if managed_applet.is_some() { 1 } else { 0 },
        managed_applet,
        authorizations: BTreeMap::new(),
        current_by_device: BTreeMap::new(),
    };
    let mut previous: Option<RealmCommit> = None;
    let mut pending_reanchor_digest: Option<Hash> = None;
    loop {
        let page = state
            .authority_commits()
            .scan_stream(&StreamScanRequest {
                realm_id: realm_id.clone(),
                stream_ref: stream_ref.clone(),
                direction: arkret_wire::StreamScanDirection::After(
                    previous.as_ref().map(|commit| commit.stream_position),
                ),
                limit: 1000,
            })
            .await
            .map_err(unavailable)?;
        if page.committed_events.is_empty() {
            return Err(unavailable(
                "committed PCR stream ends before its advertised head",
            ));
        }
        for item in page.committed_events {
            let CommittedEventView::Full(full) = item else {
                return Err(unavailable("PCR device history contains a withheld Event"));
            };
            full.validate_shape().map_err(invalid)?;
            let commit = &full.commit;
            if commit.realm_id != realm_id || commit.stream_ref != stream_ref {
                return Err(invalid("committed PCR item crossed its Realm stream"));
            }
            if let Some(previous) = &previous {
                commit.validate_successor_of(previous).map_err(invalid)?;
            } else if commit.stream_position != 0
                || commit.previous_commit_ref.is_some()
                || full.event.event_id != genesis.event_id
                || full.event != *genesis
            {
                return Err(invalid("PCR stream does not begin with registered genesis"));
            }
            if history.managed_applet.is_none()
                && commit.stream_position == 1
                && full.event.kind != EventKind::DeviceAuthorize
            {
                return Err(invalid("PCR founding unit omits device authorization"));
            }
            full.event
                .verify_event_id_matches_content_with_digest_suite(
                    state
                        .projections()
                        .realm_digest_suite(genesis.realm_id.as_str()),
                )
                .map_err(invalid)?;
            if commit.stream_position > head.stream_position {
                break;
            }
            if history.managed_applet.is_none() && commit.stream_position == 1 {
                let descriptor = create
                    .object
                    .founding_device_descriptor
                    .as_ref()
                    .ok_or_else(|| invalid("PCR founding device descriptor is missing"))?;
                let digest = arkret_models_collaboration::events_payloads::device_identity::device_authorize_payload_digest(
                    &serde_json::to_value(&full.event.payload).map_err(invalid)?,
                    state.projections().realm_digest_suite(realm_id.as_str()),
                ).map_err(invalid)?;
                if digest != descriptor.founding_authorize_payload_digest {
                    return Err(invalid(
                        "founding device payload differs from genesis commitment",
                    ));
                }
            }
            if commit.stream_position > 1
                && pending_reanchor_digest.is_none()
                && full.event.kind == EventKind::DeviceAuthorize
            {
                let payload: DeviceAuthorizePayload = full
                    .event
                    .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
                    .map_err(invalid)?;
                if payload.authorization_binding_kind == DeviceAuthorizationBindingKind::PcrRecovery
                {
                    return Err(invalid(
                        "recovery device authorization has no immediately preceding reanchor",
                    ));
                }
            }
            if let Some(expected_digest) = pending_reanchor_digest.take() {
                if full.event.kind != EventKind::DeviceAuthorize {
                    return Err(invalid(
                        "device reanchor is not followed by replacement authorization",
                    ));
                }
                let payload: DeviceAuthorizePayload = full
                    .event
                    .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
                    .map_err(invalid)?;
                let digest = arkret_models_collaboration::events_payloads::device_identity::device_authorize_payload_digest(
                    &serde_json::to_value(&full.event.payload).map_err(invalid)?,
                    state.projections().realm_digest_suite(realm_id.as_str()),
                ).map_err(invalid)?;
                if payload.authorization_binding_kind != DeviceAuthorizationBindingKind::PcrRecovery
                    || digest != expected_digest
                {
                    return Err(invalid(
                        "replacement authorization differs from reanchor commitment",
                    ));
                }
            }
            if full.event.kind == EventKind::DeviceReanchor {
                let payload: DeviceReanchorPayload = full
                    .event
                    .typed_payload::<arkret_wire::event_spec::DeviceReanchor>()
                    .map_err(invalid)?;
                pending_reanchor_digest = Some(payload.replacement_authorize_payload_digest);
            }
            apply_device_event(&mut history, account, &full.event)?;
            previous = Some(commit.clone());
            if commit.stream_position == head.stream_position {
                break;
            }
        }
        if previous
            .as_ref()
            .is_some_and(|commit| commit.stream_position == head.stream_position)
        {
            break;
        }
        if !page.truncated {
            return Err(unavailable(
                "PCR stream scan truncated before the advertised head",
            ));
        }
    }
    if previous.as_ref().map(|commit| &commit.commit_id) != Some(&head.commit_id)
        || history.current_generation == 0
        || pending_reanchor_digest.is_some()
    {
        return Err(invalid(
            "PCR stream head or founding authorization is invalid",
        ));
    }
    if state
        .authority_commits()
        .stream_head(&stream_ref)
        .await
        .map_err(unavailable)?
        .as_ref()
        != Some(&head)
    {
        return Err(unavailable(
            "PCR stream advanced during device history reconstruction",
        ));
    }
    let history = Arc::new(history);
    state
        .device_history_cache
        .lock()
        .await
        .insert(account.clone(), history.clone());
    Ok(Some(history))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A committed revoke proposal neither ends nor restores an
    /// authorization in this history: the lifecycle comes from the PCR
    /// status fold (pending, revoked, or active after a rejected result).
    #[test]
    fn committed_revoke_proposal_keeps_the_authorization_instance() {
        let account = AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            crate::test_event::station_id(),
        );
        let realm_id =
            RealmId::new("ak:realm:ATdMSXE70ijF1u9M9PvT4WFuWRgKpqVf-tiHDAD-_stf".to_owned())
                .unwrap();
        let device_id = DeviceId::new("ak:device:01970000-0000-7000-8000-000000000001").unwrap();
        let authorization_id =
            EventId::new("ak:event:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-".to_owned())
                .unwrap();
        let authorization = ConfirmedDeviceAuthorization {
            device_id: device_id.clone(),
            generation: 1,
            event_id: authorization_id.clone(),
        };
        let mut history = ConfirmedDeviceHistory {
            realm_id: realm_id.clone(),
            head: CommitStreamHead {
                stream_ref: CommitStreamRef::Realm {
                    realm_id: realm_id.clone(),
                },
                stream_position: 2,
                commit_id: arkret_wire::RealmCommitId::new(
                    "ak:realm_commit:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-".to_owned(),
                )
                .unwrap(),
            },
            current_generation: 1,
            managed_applet: None,
            authorizations: BTreeMap::from([(authorization_id.clone(), authorization.clone())]),
            current_by_device: BTreeMap::from([(device_id.clone(), authorization_id)]),
        };
        let revoke = |device: &DeviceId| {
            arkret_wire::test_support::raw_event(
                EventKind::DeviceRevoke.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                account.principal_id.clone(),
                account.station_id.clone(),
                serde_json::json!({
                    "device_id": device,
                    "revoked_by": "ak:device:01970000-0000-7000-8000-000000000002",
                    "revoked_at": "2026-09-24T00:00:00.000Z",
                    "reason": "security_rotation"
                }),
            )
            .unwrap()
        };
        apply_device_event(&mut history, &account, &revoke(&device_id)).unwrap();
        assert!(history.is_currently_active(&authorization));
        // A second proposal (after a rejected result) is equally a proposal.
        apply_device_event(&mut history, &account, &revoke(&device_id)).unwrap();
        assert!(history.is_currently_active(&authorization));
        // A proposal for a device this history never authorized is invalid.
        let unknown = DeviceId::new("ak:device:01970000-0000-7000-8000-000000000009").unwrap();
        assert!(apply_device_event(&mut history, &account, &revoke(&unknown)).is_err());
    }

    #[test]
    fn only_exact_latest_authorization_in_current_generation_is_active() {
        let realm_id =
            RealmId::new("ak:realm:ATdMSXE70ijF1u9M9PvT4WFuWRgKpqVf-tiHDAD-_stf".to_owned())
                .unwrap();
        let device_id = DeviceId::new("ak:device:01970000-0000-7000-8000-000000000001").unwrap();
        let first_id =
            EventId::new("ak:event:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-".to_owned())
                .unwrap();
        let successor_id =
            EventId::new("ak:event:AQYqC06461HNyfIIzUY8eXmafXvmC9i29nNObXCIbj0-".to_owned())
                .unwrap();
        let first = ConfirmedDeviceAuthorization {
            device_id: device_id.clone(),
            generation: 1,
            event_id: first_id.clone(),
        };
        let successor = ConfirmedDeviceAuthorization {
            device_id: device_id.clone(),
            generation: 1,
            event_id: successor_id.clone(),
        };
        let mut history = ConfirmedDeviceHistory {
            realm_id: realm_id.clone(),
            head: CommitStreamHead {
                stream_ref: CommitStreamRef::Realm { realm_id },
                stream_position: 2,
                commit_id: arkret_wire::RealmCommitId::new(
                    "ak:realm_commit:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-".to_owned(),
                )
                .unwrap(),
            },
            current_generation: 1,
            managed_applet: None,
            authorizations: BTreeMap::from([
                (first_id.clone(), first.clone()),
                (successor_id.clone(), successor.clone()),
            ]),
            current_by_device: BTreeMap::from([(device_id.clone(), successor_id)]),
        };
        assert!(!history.is_currently_active(&first));
        assert!(history.is_currently_active(&successor));
        history.current_generation = 2;
        assert!(!history.is_currently_active(&successor));
        history.current_generation = 1;
        history.current_by_device.remove(&device_id);
        assert!(!history.is_currently_active(&successor));
    }
}
