//! Signed claim and Add history for the Sidecar readiness storage fixture.

pub(super) fn attestor_resolution() -> arkret_models_identity::AuthenticatedServiceResolution {
    use arkret_identity::{DidKeyResolver, DidResolver};
    use arkret_models_identity::{
        AuthenticatedServiceResolution, DidDocument, ResolutionDidBindingEvidenceKind,
        ResolutionDidBindingEvidenceReceipt, ResolutionMethodEvidenceBoundary,
        ResolutionMethodHistoryEvidence,
    };
    let signer = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(signer.verifying_key().as_bytes());
    let did = arkret_wire::Did::new(format!("did:key:{multibase}")).unwrap();
    let station = arkret_wire::project_did_to_core_id(&did).unwrap();
    let document: DidDocument = DidKeyResolver::new().resolve_did(&did).unwrap().document;
    let digest = arkret_models_identity::normalized_did_document_digest(&document).unwrap();
    let head = arkret_canonical::sha256_digest(did.as_str().as_bytes());
    let version = format!(
        "synthetic-did-sha256:{}",
        head.trim_start_matches("sha256:")
    );
    AuthenticatedServiceResolution {
        service_id: station,
        service_kind: "station".to_owned(),
        normalized_did_document: document,
        method_history_evidence: ResolutionMethodHistoryEvidence::DidKeyExpansion {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: head.clone(),
                to_method_history_head: head,
                from_version_id: version.clone(),
                to_version_id: version,
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "key".to_owned(),
                document_digest: digest,
                method_proofs: vec![],
            },
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn claim_outcome(
    station_did: &arkret_wire::Did,
    package: &arkret_models_crypto::MlsKeyPackageRecord,
    claim_id: &arkret_wire::KeypackageClaimId,
    request_id: &arkret_wire::Base64UrlString,
    controller: &arkret_wire::AccountId,
    agent: &arkret_wire::AccountId,
    method: &arkret_wire::DidUrl,
    authorization: &arkret_wire::EventId,
    scope: &arkret_wire::ScopeRef,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_models_crypto::PeerKeyPackagesClaimOutcome {
    use arkret_models_crypto::{
        KeyPackageClaimRecord, PeerKeyPackageClaimReceipt, PeerKeyPackagesClaimOutcome,
        PeerKeyPackagesClaimUnsignedRequest,
    };
    let expires_at = at + chrono::TimeDelta::milliseconds(3_000_000);
    let record = KeyPackageClaimRecord {
        claim_id: claim_id.to_string(),
        keypackage_ref: package.keypackage_ref.to_string(),
        actor_id: arkret_wire::ActorId::account(agent.clone()),
        principal_id: agent.principal_id.clone(),
        device_id: None,
        agent_id: Some(agent.principal_id.clone()),
        agent_verification_method: Some(method.clone()),
        keypackage: package.keypackage.clone(),
        capabilities: package.capabilities.clone(),
        device_authorize_event_id: None,
        agent_key_authorize_event_id: Some(authorization.clone()),
        expires_at,
        revocation_status: None,
        last_resort: None,
    };
    record.validate_shape().unwrap();
    let request:PeerKeyPackagesClaimUnsignedRequest=serde_json::from_value(serde_json::json!({
        "claim_request_id":request_id,"requester_account_id":controller,"intended_realm_id":scope.realm_id(),
        "mls_group_id":scope.canonical_mls_group_id().unwrap(),"claim_purpose":"realm_membership",
        "required_capabilities":package.capabilities,"expires_at":arkret_canonical::format_timestamp_canonical(expires_at),
        "target_agent_id":agent.principal_id,"target_agent_verification_method":method,"target_agent_key_authorize_event_id":authorization,
    })).unwrap();
    let kid = format!("{station_did}#authority");
    let mut receipt = PeerKeyPackageClaimReceipt {
        claim_request_id: request_id.clone(),
        request_digest: arkret_wire::Hash::new(format!("sha256:{}", "6".repeat(64))).unwrap(),
        claims_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&[&record]).unwrap(),
        )
        .unwrap(),
        source_id: controller.station_id.clone(),
        destination_id: agent.station_id.clone(),
        request,
        claimed_at: at,
        expires_at,
        signature: arkret_models_crypto::KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(kid.clone()).unwrap(),
            signature_algorithm: Some(arkret_wire::NonEmptyString::new("Ed25519").unwrap()),
            sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
        },
    };
    receipt.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[83; 32],
        &kid,
        &arkret_models_crypto::peer_keypackage_claim_receipt_signing_bytes(&receipt).unwrap(),
    )
    .unwrap();
    let outcome = PeerKeyPackagesClaimOutcome {
        claim_request_id: request_id.clone(),
        claims: vec![record],
        claim_receipt: receipt,
    };
    outcome.validate_shape().unwrap();
    outcome
}

pub(super) fn add_witness(
    outcome: arkret_models_crypto::PeerKeyPackagesClaimOutcome,
    delivery: &arkret_wire::MlsWelcomeDelivery,
    base: &arkret_wire::MlsGroupCurrent,
    position: u64,
    leaf_key: arkret_wire::Base64UrlString,
    resolution: arkret_models_identity::AuthenticatedServiceResolution,
) -> coland_storage::VerifiedMlsRecipientRosterWitness {
    use arkret_models_collaboration::mls_roster_authority::{
        MlsAddAuthorityAttestation, MlsAttestAddRequestBody,
    };
    let mut attestation = MlsAddAuthorityAttestation {
        attestor_station_id: delivery.recipient_actor_id.route_service_id().clone(),
        realm_id: delivery.realm_id.clone(),
        effective_scope: delivery.effective_scope.clone(),
        mls_group_id: base.effective_scope.canonical_mls_group_id().unwrap(),
        genesis_event_ref: base.genesis_event_ref.clone(),
        commit_event_ref: delivery.commit_event_ref.clone(),
        commit_stream_position: position,
        epoch: base.epoch + 1,
        welcome_id: delivery.welcome_id.clone(),
        claim_id: delivery.keypackage_claim_ref.clone(),
        actor_id: delivery.recipient_actor_id.clone(),
        endpoint: delivery.recipient_endpoint.clone(),
        authorization_event_ref: outcome.claims[0]
            .agent_key_authorize_event_id
            .clone()
            .unwrap(),
        leaf_signature_key_b64u: leaf_key,
        claim_record_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&outcome.claims[0]).unwrap(),
        )
        .unwrap(),
        claim_receipt: outcome.claim_receipt.clone(),
        attested_at: outcome.claim_receipt.claimed_at,
        signature: outcome.claim_receipt.signature.clone(),
    };
    attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[83; 32],
        attestation.signature.kid.as_str(),
        &attestation.signing_bytes().unwrap(),
    )
    .unwrap();
    let request = MlsAttestAddRequestBody {
        attestation,
        claim_outcome: outcome,
    };
    request.validate_claim_binding().unwrap();
    coland_storage::VerifiedMlsRecipientRosterWitness {
        accepted_genesis_event_ref: base.genesis_event_ref.clone(),
        signed_attest_add_request_canonical_json: arkret_canonical::canonical_json_bytes(&request)
            .unwrap(),
        local_attestor_resolution: Some(resolution),
    }
}
