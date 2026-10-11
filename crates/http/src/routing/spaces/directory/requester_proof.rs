//! Per-object-family requester_id proof verification for the five Directory
//! resolve surfaces (`discovery-directory.md` §9.0.1).
//!
//! `directory-operations.schema.json` is a DTO container, not an object family,
//! so there is no file-wide directory operation context. Each request family
//! owns one registered context, and the binding bytes are always produced by
//! that family's own `proof_binding_bytes()` in `arkret-rust-sdk`. This module
//! therefore never spells a context string: passing the wrong body type is the
//! only way to get the wrong context, and the SDK bakes the context into the
//! signed bytes so a signature valid under one family can never verify under
//! another.
//!
//! The SDK helper already enforces the wire-shape half of §9.0.1 — production
//! proof material, `payload_digest` equality against the proofs-stripped
//! canonical request, required typed `audience_id`, and no generic `domain` or
//! `proof_purpose` members. This module adds the receiver-side half: the
//! audience_id must name *this* service, the proof must be fresh, and
//! the JWS must verify under the family's originator.

use super::*;

/// §9.0.1: a Directory MUST reject any proof whose `created_at` deviates from
/// the receiving instant by more than 300 seconds. Callers needing a longer
/// window MUST re-issue; deployments MUST NOT relax this constant.
const DIRECTORY_REQUESTER_PROOF_WINDOW_SECONDS: i64 = 300;

/// Verify every requester_id proof carried by one Directory resolve request.
///
/// `issuer` is the family's originator wire field projected to its DID core id
/// (`requester_id` for `resolve_target` / `resolve_handle` /
/// historical selector and handle enumeration surfaces).
/// `resolve_organization` has no originator wire field, so it passes `None` and
/// the signer identity is borne only by `verification_method`.
///
/// `binding_for` MUST be the request body's own `proof_binding_bytes`; that is
/// what selects the per-family context.
///
/// Returns `false` for every failure without distinguishing the cause, so that
/// callers can collapse it into the §9.2 uniform "indistinguishable from
/// not-found" rejection. Proofs are optional on the wire: an empty slice is
/// accepted here and the surface's own visibility rules still apply.
pub(super) async fn directory_requester_proofs_verified(
    state: &AppState,
    proofs: &[DirectoryRequestProof],
    issuer: Option<&str>,
    binding_for: impl Fn(&DirectoryRequestProof) -> Option<Vec<u8>>,
) -> bool {
    for proof in proofs {
        if !directory_requester_proof_verified(state, proof, issuer, &binding_for).await {
            return false;
        }
    }
    true
}

async fn directory_requester_proof_verified(
    state: &AppState,
    proof: &DirectoryRequestProof,
    issuer: Option<&str>,
    binding_for: impl Fn(&DirectoryRequestProof) -> Option<Vec<u8>>,
) -> bool {
    if proof.kind != DirectoryRequestProofKind::DetachedJws {
        return false;
    }
    // §9.0.1: `audience_id` MUST be the target Directory `service_id` published
    // by `ak.find.directory.read.describe.v1`. The SDK rejects any other shape;
    // the receiver decides whether the typed value actually names it.
    // `state.service_id()` is this deployment's
    // projected core id, which is exactly the value describe publishes.
    if proof.audience_id.as_str() != state.service_id() {
        return false;
    }
    let age_seconds = Utc::now()
        .signed_duration_since(proof.created_at)
        .num_seconds()
        .abs();
    if age_seconds > DIRECTORY_REQUESTER_PROOF_WINDOW_SECONDS {
        return false;
    }
    // The family's own binding bytes. A proof signed under a sibling family's
    // context produces different bytes here and fails JWS verification below,
    // which is exactly the §9.0.1 cross-family rejection.
    let Some(binding) = binding_for(proof) else {
        return false;
    };
    // Without an originator wire field the signer is whoever controls the
    // verification method, so the method's own controller is the issuer.
    let controller = match issuer {
        Some(issuer) => issuer.to_owned(),
        None => {
            let method = proof.verification_method.as_str();
            match arkret_identity::verification_method_did(method) {
                Ok(did) => did.to_string(),
                Err(_) => return false,
            }
        }
    };
    crate::jws_verify::verify_did_controlled_jws_async(
        &binding,
        &proof.jws,
        &proof.verification_method,
        &controller,
        state,
    )
    .await
    .is_ok()
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{Did, project_did_to_core_id};
    use arkret_models_discovery::DirectoryResolveHandleRequestBody;
    use arkret_wire::{DomainSeparationId, Hash};

    use super::*;

    fn state() -> AppState {
        let mut config = crate::config::AppConfig::test_default();
        config.development_mode = true;
        AppState::new(config, coland_storage_postgres::Db { pool: None })
    }

    fn requester_id() -> DidCoreId {
        let did = Did::new("did:web:directory-proof-test.invalid".to_owned()).unwrap();
        project_did_to_core_id(&did).unwrap()
    }

    fn proof(
        audience: &str,
        created_at: DateTime<Utc>,
        payload_digest: Hash,
    ) -> DirectoryRequestProof {
        DirectoryRequestProof {
            kind: DirectoryRequestProofKind::DetachedJws,
            verification_method: arkret_wire::DidUrl::new(
                "did:web:directory-proof-test.invalid#ak:key:directory-requester_id".to_owned(),
            )
            .unwrap(),
            payload_digest,
            created_at,
            audience_id: DidCoreId::new(audience).unwrap(),
            jws: "eyJhbGciOiJFZERTQSJ9..c2lnbmF0dXJl".to_owned(),
        }
    }

    fn target_body(proofs: Vec<DirectoryRequestProof>) -> DirectoryResolveTargetRequestBody {
        DirectoryResolveTargetRequestBody {
            address: "ak://realm/release".to_owned(),
            requester_id: Some(requester_id()),
            proof_challenge: None,
            claim_presentations: Vec::new(),
            proofs,
            token: None,
        }
    }

    fn handle_body(proofs: Vec<DirectoryRequestProof>) -> DirectoryResolveHandleRequestBody {
        DirectoryResolveHandleRequestBody {
            handle: "@alice:directory-proof-test.invalid".to_owned(),
            expected_account_id: None,
            proof_challenge: None,
            claim_presentations: Vec::new(),
            intent: None,
            requester_id: Some(requester_id()),
            audience: None,
            realm_id: None,
            proofs,
        }
    }

    fn binding_context(bytes: &[u8]) -> String {
        serde_json::from_slice::<serde_json::Value>(bytes).unwrap()["context"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// §9.0.1: every family owns one registered context and the Directory MUST
    /// reject a proof whose context does not belong to the handled family. The
    /// context is inside the signed bytes, so a signature that is valid under
    /// one family cannot produce the sibling family's transcript at all.
    #[test]
    fn each_family_binds_its_own_registered_context() {
        let now = Utc::now();
        let target = target_body(Vec::new());
        let handle = handle_body(Vec::new());

        let target_proof = proof(
            "ak:did_core:web:svc.invalid",
            now,
            target.payload_digest().unwrap(),
        );
        let handle_proof = proof(
            "ak:did_core:web:svc.invalid",
            now,
            handle.payload_digest().unwrap(),
        );

        let target_bytes = target.proof_binding_bytes(&target_proof).unwrap();
        let handle_bytes = handle.proof_binding_bytes(&handle_proof).unwrap();

        assert_eq!(
            binding_context(&target_bytes),
            DomainSeparationId::DIRECTORY_RESOLVE_TARGET_REQUEST_PROOF_V1
        );
        assert_eq!(
            binding_context(&handle_bytes),
            DomainSeparationId::DIRECTORY_RESOLVE_HANDLE_REQUEST_PROOF_V1
        );
        assert_ne!(target_bytes, handle_bytes);
    }

    /// A proof correctly issued for `resolve_handle` and replayed into a
    /// `resolve_target` request MUST NOT reproduce the transcript it signed:
    /// even after forcing the digest to match the target body, the context and
    /// the bound target member differ, so the signature can never verify.
    #[test]
    fn a_sibling_family_proof_never_reproduces_the_handled_family_transcript() {
        let now = Utc::now();
        let handle = handle_body(Vec::new());
        let handle_proof = proof(
            "ak:did_core:web:svc.invalid",
            now,
            handle.payload_digest().unwrap(),
        );
        let signed_bytes = handle.proof_binding_bytes(&handle_proof).unwrap();

        // Replay the same proof into resolve_target, re-stamping only the
        // digest so the SDK's digest gate is not what rejects it.
        let target = target_body(Vec::new());
        let mut replayed = handle_proof.clone();
        replayed.payload_digest = target.payload_digest().unwrap();
        let replay_bytes = target.proof_binding_bytes(&replayed).unwrap();

        assert_ne!(signed_bytes, replay_bytes);
        assert_ne!(
            binding_context(&signed_bytes),
            binding_context(&replay_bytes)
        );
    }

    /// A digest lifted from a sibling family is rejected outright, so a
    /// cross-family replay cannot even reach JWS verification.
    #[test]
    fn a_sibling_family_digest_is_rejected_by_the_binding() {
        let now = Utc::now();
        let handle = handle_body(Vec::new());
        let target = target_body(Vec::new());
        let borrowed = proof(
            "ak:did_core:web:svc.invalid",
            now,
            handle.payload_digest().unwrap(),
        );
        assert!(target.proof_binding_bytes(&borrowed).is_err());
    }

    /// §9.0.1 uses a closed leaf, so generic proof members are not aliases.
    #[test]
    fn generic_proof_members_are_refused_on_the_read_surface() {
        let now = Utc::now();
        let target = target_body(Vec::new());
        let digest = target.payload_digest().unwrap();
        let canonical =
            serde_json::to_value(proof("ak:did_core:web:svc.invalid", now, digest)).unwrap();
        for field in ["domain", "proof_purpose", "audience"] {
            let mut generic = canonical.clone();
            generic
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), serde_json::json!("unstructured"));
            assert!(serde_json::from_value::<DirectoryRequestProof>(generic).is_err());
        }
    }

    /// §9.0.1: `audience_id` MUST be the target Directory `service_id` in
    /// `did_core_id` form. A well-formed core id naming a different directory
    /// is still rejected.
    #[tokio::test]
    async fn an_audience_naming_another_service_is_rejected() {
        let state = state();
        let now = Utc::now();
        let body = target_body(Vec::new());
        let wrong = proof(
            "ak:did_core:web:some-other-directory.invalid",
            now,
            body.payload_digest().unwrap(),
        );
        let body = target_body(vec![wrong]);
        assert!(
            !directory_requester_proofs_verified(
                &state,
                &body.proofs,
                body.requester_id.as_ref().map(DidCoreId::as_str),
                |proof| body.proof_binding_bytes(proof).ok(),
            )
            .await
        );
    }

    /// §9.0.1: a proof older than 300 seconds MUST be rejected and deployments
    /// MUST NOT relax the constant.
    #[tokio::test]
    async fn a_proof_outside_the_three_hundred_second_window_is_rejected() {
        let state = state();
        let service_id = state.service_id().clone();
        let stale_at =
            Utc::now() - chrono::Duration::seconds(DIRECTORY_REQUESTER_PROOF_WINDOW_SECONDS + 1);
        let body = target_body(Vec::new());
        let stale = proof(&service_id, stale_at, body.payload_digest().unwrap());
        let body = target_body(vec![stale]);
        assert!(
            !directory_requester_proofs_verified(
                &state,
                &body.proofs,
                body.requester_id.as_ref().map(DidCoreId::as_str),
                |proof| body.proof_binding_bytes(proof).ok(),
            )
            .await
        );
    }

    /// Proofs are optional on the wire; an absent `proofs` member leaves the
    /// surface's own visibility rules as the only gate.
    #[tokio::test]
    async fn an_absent_proofs_member_is_accepted() {
        let state = state();
        let body = target_body(Vec::new());
        assert!(
            directory_requester_proofs_verified(
                &state,
                &body.proofs,
                body.requester_id.as_ref().map(DidCoreId::as_str),
                |proof| body.proof_binding_bytes(proof).ok(),
            )
            .await
        );
    }
}
