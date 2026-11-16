//! Agent signer evidence from an accepted key authorization Event and its
//! RealmCommit. Current key eligibility is checked against the PCR snapshot.

use arkret_models_collaboration::agent_operations::KeyStateCurrentSignerEvidence;
use arkret_models_collaboration::governance::agent_artifacts::PublicKey;
use arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey;
use arkret_models_identity::authenticated_signer_resolution_evidence::build_agent_signer_evidence;
use arkret_models_identity::{
    AuthenticatedServiceResolution, AuthenticatedSignerKind, AuthenticatedSignerResolutionEvidence,
};
use arkret_wire::{ActorId, DidUrl, EventId, NonEmptyJsonObject, SignerEvidenceRef};

use super::*;

/// Fetch the method-native service history used by a historical service
/// signature. The compact signer-key evidence does not carry this history.
pub(crate) async fn fetch_service_resolution(
    state: &AppState,
    service_id: &arkret_wire::DidCoreId,
    base_url: Option<&str>,
) -> Result<AuthenticatedServiceResolution, AgentEvidenceAcquisitionFailure> {
    if service_id == &state.service_core_id() {
        return crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|_| missing());
    }
    let resolved_base;
    let base_url = match base_url.filter(|value| !value.trim().is_empty()) {
        Some(value) => value,
        None => {
            resolved_base = crate::routing::federation::resolved_peer_base_url(
                state,
                service_id.as_str(),
                arkret_wire::ServiceKind::Station.as_str(),
                false,
            )
            .await
            .map_err(|_| missing())?;
            &resolved_base
        }
    };
    let path = arkret_models_identity::canonical_service_resolution_path(service_id);
    let target = format!("{}{}", base_url.trim_end_matches('/'), path);
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "historical service resolution",
        state.config().development_mode,
        std::time::Duration::from_secs(10),
    )
    .map_err(|_| missing())?;
    let response = client
        .get(url)
        .header(
            "arkret-operation",
            arkret_wire::ServiceOperationId::OPEN_SERVICE_READ_RESOLUTION_V1,
        )
        .send()
        .await
        .map_err(|_| missing())?;
    if !response.status().is_success() {
        return Err(missing());
    }
    let body = response.bytes().await.map_err(|_| missing())?;
    if body.len() > 1024 * 1024 {
        return Err(missing());
    }
    serde_json::from_slice(&body).map_err(|_| missing())
}

#[derive(Clone, Debug)]
pub(crate) enum AgentSignerEvidenceQuerySelector {
    CurrentAdmission {
        actor: ActorId,
        verification_method: DidUrl,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AgentEvidenceAcquisitionFailure {
    AgentSignerEvidenceMissing,
    AgentAuthorizationInactive,
}

fn missing() -> AgentEvidenceAcquisitionFailure {
    AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing
}

/// Rebuild the one compact signer evidence from the accepted authorization.
/// This does not itself authorize future use of the key; the active PCR rows
/// are read and checked on every current query.
pub(crate) async fn current_authenticated_agent_signer_evidence_for_record(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
    frozen_agent: Option<&AgentPrincipalRecord>,
) -> Result<
    (
        AuthenticatedSignerResolutionEvidence,
        Vec<AuthenticatedSignerResolutionEvidence>,
    ),
    AgentEvidenceAcquisitionFailure,
> {
    let AgentSignerEvidenceQuerySelector::CurrentAdmission {
        actor,
        verification_method,
    } = selector;
    let agent_id = &actor.as_account_id().ok_or_else(missing)?.principal_id;
    let owned;
    let agent = match frozen_agent {
        Some(record) => record,
        None => {
            owned = state
                .agent_pairings()
                .agent(agent_id.as_str())
                .await
                .map_err(|_| missing())?
                .ok_or_else(missing)?;
            &owned
        }
    };
    if agent.id != agent_id.as_str()
        || agent.state != AgentLifecycleState::Active
        || agent.authorized_verification_method.as_deref() != Some(verification_method.as_str())
    {
        return Err(AgentEvidenceAcquisitionFailure::AgentAuthorizationInactive);
    }
    let authorized_event_id = EventId::new(agent.authorized_event_ref.clone().ok_or_else(missing)?)
        .map_err(|_| missing())?;
    let frozen_event = agent.authorized_key_event.as_ref().ok_or_else(missing)?;
    let committed = state
        .authority_commits()
        .committed_event(&authorized_event_id)
        .await
        .map_err(|_| missing())?
        .ok_or_else(missing)?;
    let realm_id = arkret_wire::RealmId::new(agent.principal_control_realm_id.clone())
        .map_err(|_| missing())?;
    if frozen_event.event_id != authorized_event_id
        || committed.event != *frozen_event
        || committed.event.realm_id != realm_id
        || committed.commit.event_ref != authorized_event_id
        || committed.commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            })
    {
        return Err(missing());
    }
    let key = AgentAuthorizedSigningKey::from_event(&committed.event).map_err(|_| missing())?;
    if key.agent_id != *agent_id
        || key.verification_method != *verification_method
        || key
            .expires_at
            .is_some_and(|expiry| expiry <= chrono::Utc::now())
        || agent.authorized_public_key_digest.as_deref() != Some(key.public_key_digest.as_str())
    {
        return Err(AgentEvidenceAcquisitionFailure::AgentAuthorizationInactive);
    }
    let (active, heads, status) =
        super::pairing::accepted_agent_key_authorization_snapshot(state, agent)
            .await
            .map_err(|_| missing())?;
    if status != Some(AgentLifecycleState::Active)
        || active.len() != 1
        || !active.contains(&(
            key.agent_key_id.to_string(),
            authorized_event_id.to_string(),
        ))
        || !heads.iter().any(|head| {
            head.stream_ref == committed.commit.stream_ref
                && head.stream_position >= committed.commit.stream_position
        })
    {
        return Err(AgentEvidenceAcquisitionFailure::AgentAuthorizationInactive);
    }
    let public_key: PublicKey = serde_json::from_value(
        committed
            .event
            .payload
            .get("public_key")
            .cloned()
            .ok_or_else(missing)?,
    )
    .map_err(|_| missing())?;
    let public_key_jwk = agent_runtime_public_key_jwk(&public_key, verification_method)?;
    let evidence = build_agent_signer_evidence(
        agent_id.clone(),
        verification_method.clone(),
        public_key_jwk,
        committed.commit.commit_id,
        committed.commit.committed_at,
    )
    .map_err(|_| missing())?;
    Ok((evidence, Vec::new()))
}

fn agent_runtime_public_key_jwk(
    public_key: &PublicKey,
    verification_method: &DidUrl,
) -> Result<NonEmptyJsonObject, AgentEvidenceAcquisitionFailure> {
    if public_key.kty.as_str() != "OKP"
        || public_key.algorithm.as_str() != "Ed25519"
        || public_key.kid.as_str() != verification_method.as_str()
    {
        return Err(missing());
    }
    let jwk = arkret_signatures::jwk::JsonWebKey::ed25519(public_key.key.clone());
    serde_json::from_value(serde_json::to_value(jwk).map_err(|_| missing())?).map_err(|_| missing())
}

/// Return the frozen evidence and its canonical content ref for the durable
/// activation row. The public key-state wrapper is validated before storing.
pub(crate) fn current_agent_evidence_delivery(
    actor: ActorId,
    verification_method: DidUrl,
    root: &AuthenticatedSignerResolutionEvidence,
    dependencies: Vec<AuthenticatedSignerResolutionEvidence>,
) -> Result<(SignerEvidenceRef, AuthenticatedSignerResolutionEvidence), AppError> {
    if !dependencies.is_empty()
        || root.signer_kind != AuthenticatedSignerKind::Agent
        || actor.signing_principal_id() != &root.subject_id
        || verification_method != root.verification_method
    {
        return Err(AppError::internal(
            "Agent signer evidence does not match its current key",
        ));
    }
    let reference = root
        .signer_evidence_ref()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let delivery = KeyStateCurrentSignerEvidence {
        signer_resolution_evidence_ref: reference.clone(),
        authenticated_signer_evidence: root.clone(),
    };
    delivery
        .validate_against(&reference)
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok((reference, root.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_key_evidence_uses_public_jwk_shape() {
        let method = DidUrl::new("did:web:agent.example#runtime").unwrap();
        let public_key: PublicKey = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "kid": method.as_str(),
            "algorithm": "Ed25519",
            "key": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
        }))
        .unwrap();

        let jwk = agent_runtime_public_key_jwk(&public_key, &method).unwrap();
        let value = serde_json::to_value(jwk).unwrap();
        assert_eq!(value["kty"], "OKP");
        assert_eq!(value["crv"], "Ed25519");
        assert_eq!(value["x"], public_key.key.as_str());
        assert!(value.get("algorithm").is_none());
        assert!(value.get("key").is_none());
    }
}
