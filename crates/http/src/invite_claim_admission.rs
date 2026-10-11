//! Historical external claim authority prepared before the accepting transaction.

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::governance::membership_invite::{
    InviteClaimPayload, InviteThirdPartyCreatePayload,
};
use coland_services::{ServiceError, ServiceResult};
use coland_storage::InviteClaimProofCommit;

use crate::state::AppState;

fn invalid(detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!("claim_invalid: {detail}"))
}

pub(crate) async fn prepare_invite_claim_proof(
    state: &AppState,
    event: &arkret_wire::Event,
    at: chrono::DateTime<chrono::Utc>,
) -> ServiceResult<Option<InviteClaimProofCommit>> {
    if event.kind != arkret_wire::EventKind::InviteClaim {
        return Ok(None);
    }
    let claim: InviteClaimPayload = event
        .typed_payload::<arkret_wire::event_spec::InviteClaim>()
        .map_err(invalid)?
        .clone();
    claim.validate().map_err(invalid)?;
    let create = state
        .authority_commits()
        .committed_event(&claim.invite_id.event_id())
        .await?
        .ok_or_else(|| invalid("accepted third-party create is unavailable"))?;
    if create.event.kind != arkret_wire::EventKind::InviteThirdParty
        || create.event.realm_id != event.realm_id
    {
        return Err(invalid(
            "claim does not name an accepted third-party create",
        ));
    }
    let material: InviteThirdPartyCreatePayload =
        serde_json::from_value(serde_json::to_value(&create.event.payload).map_err(invalid)?)
            .map_err(invalid)?;
    let binding = &claim.binding_proof;
    let subject_method = claim.subject_proof.verification_method.as_str();
    let subject_did = arkret_identity::verification_method_did(subject_method).map_err(invalid)?;
    let fragment = subject_method
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .ok_or_else(|| invalid("subject method has no fragment"))?;
    if arkret_wire::DeviceId::new(fragment.to_owned()).is_ok() {
        return Err(invalid(
            "subject proof must be a directly declared historical DID method",
        ));
    }
    // ak.verifier.invite.claim_subject_at_commit.v1: accepted_at_history;
    // immutable did:key or authenticated method-native webvh history only.
    let (subject_public_key, subject_native_control, subject_control_history) =
        if subject_did.method() == "key"
            && claim
                .subject_account_id
                .principal_id
                .as_str()
                .starts_with("ak:did_core:webvh:")
        {
            // The producer method supplies a locator only. Its device key is never
            // an identity-control authority; native SCID/history is independent.
            let locator = event
                .producer_proof
                .as_ref()
                .ok_or_else(|| invalid("principal locator is unavailable"))?
                .verification_method
                .as_str();
            let principal_did =
                arkret_identity::verification_method_did(locator).map_err(invalid)?;
            let (key,selected)=crate::principal_control::resolve_native_identity_control(
            state,&principal_did,&claim.subject_account_id.principal_id,
            &claim.subject_proof.verification_method,at,
            arkret_identity::principal_control::DirectIdentityControlPurpose::InviteClaimSubject,
        ).await.map_err(invalid)?;
            let history = serde_json::json!({"did":selected.did,"version_id":selected.version_id,
            "log_head_digest":selected.log_head_digest,"update_keys":selected.update_keys,
            "verified_at":arkret_canonical::format_timestamp_canonical(at)});
            (*key.public_key(), Some(key), Some(history))
        } else {
            if arkret_wire::project_did_to_core_id(&subject_did).map_err(invalid)?
                != claim.subject_account_id.principal_id
            {
                return Err(invalid(
                    "subject historical method belongs to another principal",
                ));
            }
            let key = crate::jws_verify::resolve_ed25519_pubkey_at(state, subject_method, at)
                .await
                .map_err(invalid)?
                .to_bytes();
            (key, None, None)
        };
    let binding_did =
        arkret_identity::verification_method_did(binding.verification_method.as_str())
            .map_err(invalid)?;
    if arkret_wire::project_did_to_core_id(&binding_did).map_err(invalid)?
        != binding.verification_id
    {
        return Err(invalid("binding method controller differs from verifier"));
    }
    let expected_key = &material.third_party_invite.verification_public_key;
    let binding_public_key = if expected_key.starts_with("did:") {
        if binding.verification_method.as_str() != expected_key {
            return Err(invalid("binding method differs from accepted create"));
        }
        crate::jws_verify::resolve_ed25519_pubkey_at(state, expected_key, at)
            .await
            .map_err(invalid)?
            .to_bytes()
    } else {
        arkret_canonical::decode_ed25519_multibase(expected_key).map_err(invalid)?
    };
    Ok(Some(InviteClaimProofCommit {
        event_id: event.event_id.clone(),
        event_digest: event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .map_err(invalid)?,
        create_ref: arkret_wire::CommittedEventRef {
            event_id: create.event.event_id,
            commit_id: create.commit.commit_id,
            stream_ref: create.commit.stream_ref,
            stream_position: create.commit.stream_position,
        },
        committed_at: at,
        subject_public_key,
        subject_native_control,
        subject_control_history,
        binding_public_key,
    }))
}
