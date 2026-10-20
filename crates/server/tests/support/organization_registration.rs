use arkret_identifiers::{Did, DidCoreId, Hash, project_did_to_core_id};
use arkret_models_identity::{
    OrganizationControlProof, OrganizationControlProofKind, OrganizationRegistrationChallenge,
};
use arkret_signatures::{Ed25519DetachedJwsSigner, EventSigner};
use arkret_wire::{PayloadProof, ProofContextId};
use chrono::Duration;
use coland_services::identity::{PinnedDidDocumentState, PinnedDidVersionStatus};
use coland_services::organization_registration::OrganizationDidResolutionPort;
use parking_lot::RwLock;

pub struct StaticOrganizationResolver {
    pub state: RwLock<PinnedDidDocumentState>,
}

#[async_trait::async_trait]
impl OrganizationDidResolutionPort for StaticOrganizationResolver {
    async fn resolve_current_webvh_state(
        &self,
        did: &Did,
    ) -> Result<PinnedDidDocumentState, String> {
        let state = self.state.read().clone();
        (state.did == *did)
            .then_some(state)
            .ok_or_else(|| "DID not found".to_owned())
    }

    async fn resolve_pinned_webvh_state(
        &self,
        did: &Did,
        version_id: &str,
        log_head_digest: &Hash,
    ) -> Result<PinnedDidDocumentState, String> {
        let state = self.state.read().clone();
        (state.did == *did
            && state.version_id == version_id
            && state.log_head_digest == *log_head_digest)
            .then_some(state)
            .ok_or_else(|| "pinned DID state not found".to_owned())
    }
}

pub fn organization_fixture() -> (
    DidCoreId,
    Did,
    DidCoreId,
    PinnedDidDocumentState,
    Ed25519DetachedJwsSigner,
) {
    let did = Did::new("did:webvh:z6mkfixture:http-org.example".to_owned()).unwrap();
    let organization_id = project_did_to_core_id(&did).unwrap();
    let admin_did = Did::new("did:web:alice.example".to_owned()).unwrap();
    let admin_id = project_did_to_core_id(&admin_did).unwrap();
    let verification_method = format!("{did}#org-control-key-1");
    let signer = Ed25519DetachedJwsSigner::from_seed([51; 32], verification_method.clone());
    let public_key =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(signer.verifying_key().as_bytes());
    let document = serde_json::json!({
        "id": did,
        "verificationMethod": [{
            "id": verification_method,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key,
        }],
        "authentication": [verification_method],
        "assertionMethod": [verification_method],
    });
    let pinned = PinnedDidDocumentState {
        did: did.clone(),
        version_id: "3-zHttpFixtureVersion".to_owned(),
        log_head_digest: Hash::new(format!("sha256:{}", "5".repeat(64))).unwrap(),
        document,
        update_keys: Vec::new(),
        current_version_id: "3-zHttpFixtureVersion".to_owned(),
        status: PinnedDidVersionStatus::Current,
    };
    (organization_id, did, admin_id, pinned, signer)
}

pub fn signed_control_proof(
    challenge: &OrganizationRegistrationChallenge,
    pinned: &PinnedDidDocumentState,
    signer: &Ed25519DetachedJwsSigner,
) -> OrganizationControlProof {
    let created_at = challenge.created_at + Duration::seconds(1);
    let mut proof = PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new(signer.verification_method().to_owned())
            .unwrap(),
        payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "pending".to_owned(),
    };
    let transcript = serde_json::json!({
        "context": ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1,
        "challenge_id": challenge.challenge_id,
        "organization_id": challenge.organization_id,
        "organization_did": challenge.organization_did,
        "local_admin_subject_id": challenge.local_admin_subject_id,
        "version_id": pinned.version_id,
        "log_head_digest": pinned.log_head_digest,
        "verification_method": proof.verification_method,
        "created_at": proof.created_at,
    });
    let bytes = arkret_canonical::canonical_json_bytes(&transcript).unwrap();
    proof.payload_digest = Hash::new(arkret_canonical::sha256_digest(&bytes)).unwrap();
    proof.jws = signer.sign_detached_jws(&bytes);
    OrganizationControlProof {
        proof_kind: OrganizationControlProofKind::ResolvedVerificationMethod,
        quorum_threshold: None,
        proofs: vec![proof],
    }
}
