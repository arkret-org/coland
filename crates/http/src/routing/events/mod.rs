use coland_services::identity::SessionIdentityState as SessionRecord;
use salvo::prelude::*;

mod account_authority_private;
pub(crate) mod event_log;
pub(crate) mod peer;
mod peer_device_revocations;
// Strand + projection helpers are `pub(crate)` so the MIMI interop
// facade can reuse the canonical space→strand mapping + projection-event
// JSON shape when ingesting MIMI traffic into the Arkret timeline.
pub(crate) mod notify;
pub(crate) mod operations;
pub(crate) mod projection;
pub(super) mod projection_query;
#[cfg(test)]
pub(crate) use projection_query::structural_navigation_available;
pub(crate) mod strand;
pub(crate) mod sync;

use strand::{
    discussion_track_for_projection_event, message_id_from_event_id, strand_id_for_projection_event,
};

#[cfg(test)]
use super::realm_allows_plaintext_service_for_data_class;
#[cfg(test)]
use super::validate_space_id;
use super::{
    authenticated_session, is_realm_deleted, now, query_param, realm_discoverability,
    realm_event_visible_to_session, realm_id_accessible, realm_state_snapshot_manifest_for_realm,
    render_error, sha256_hex, validate_did,
};

pub fn router() -> Router {
    Router::new()
        .push(sync::protocol_router())
        .push(event_log::router())
        .push(projection_query::protocol_router())
}

pub(crate) fn require_agent_session_scope(
    session: &SessionRecord,
    required_scope: &str,
) -> Result<(), coland_http::error::AppError> {
    let Some(agent_session) = session.agent_session() else {
        return Ok(());
    };
    if agent_session
        .granted_scope
        .iter()
        .any(|scope| scope == required_scope)
    {
        return Ok(());
    }
    Err(coland_http::error::AppError::capability_denied(format!(
        "agent session scope {required_scope} is required"
    )))
}

/// Product-private (`/_coland/self/*`) projection read surface: single-Strand
/// object read with materialized `fields`, and the relation edge list. These
/// stay off the canonical `/_arkret/*` protocol root per
/// `service-http-binding.md` §2.1.3 (relation / object direct reads beyond the
/// declared Realm-scoped read binding belong to the implementation private
/// surface).
pub fn local_router() -> Router {
    projection_query::local_router()
}

/// Deployment-private Account Authority → Station admission boundary.
///
/// These routes deliberately live outside `/_arkret`, carry no
/// `Arkret-Operation`, and are excluded from protocol OpenAPI/Describe.
pub fn account_authority_private_router() -> Router {
    Router::with_path("account-authority")
        .push(
            Router::with_path("agent-session-authority/read")
                .post(account_authority_private::read_agent_session_authority),
        )
        .push(
            Router::with_path("agent-participation/read")
                .post(account_authority_private::read_agent_participation),
        )
        .push(Router::with_path("events/admit").post(account_authority_private::admit_event))
        .push(
            Router::with_path("current-device/check")
                .post(peer_device_revocations::check_private_current_device),
        )
        .push(
            Router::with_path("principal-genesis/admit")
                .post(peer::admit_private_principal_genesis),
        )
}

pub fn peer_router() -> Router {
    peer::router()
}

#[cfg(test)]
mod tests {
    use arkret_wire::FreshnessState;
    use chrono::Utc;
    use coland_services::identity::AgentSessionState as AgentSessionRecord;

    use super::*;

    fn session_with_agent_scopes(scopes: &[&str]) -> SessionRecord {
        SessionRecord {
            account_pk: None,
            token_hash: "grant".to_owned(),
            actor: "did:web:agent.example".to_owned(),
            audience: "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:coland.local:webvh:service".to_owned(),
            session_public_key: Some("{}".to_owned()),
            endpoint: coland_services::identity::SessionEndpointState::AgentRuntime { state: AgentSessionRecord {
                granted_scope: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                scope_details: serde_json::json!({
                    "controller_principal_id": "ak:did_core:web:alice.example",
                    "resources": {
                        "realm_refs": [],
                        "strand_refs": [],
                    },
                    "constraints": {},
                    "capability_grant_refs": [],
                    "policy_refs": [],
                }),
                freshness_state: FreshnessState::Fresh,
            } },
            session_grant: None,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            created_at: Utc::now(),
            revoked_at: None,
        }
    }

    fn human_session() -> SessionRecord {
        SessionRecord {
            account_pk: None,
            token_hash: "human".to_owned(),
            actor: "did:web:alice.example".to_owned(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice { device_id: "ak:device:0196419b-0000-7000-8000-000000000001".to_owned() },
            audience: "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:coland.local:webvh:service".to_owned(),
            session_public_key: None,
            session_grant: None,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            created_at: Utc::now(),
            revoked_at: None,
        }
    }

    #[test]
    fn human_sessions_are_not_limited_by_agent_service_scopes() {
        assert!(
            require_agent_session_scope(
                &human_session(),
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1
            )
            .is_ok()
        );
    }

    #[test]
    fn agent_session_requires_stream_subscribe_scope() {
        assert!(
            require_agent_session_scope(
                &session_with_agent_scopes(&[
                    arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1
                ]),
                arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1,
            )
            .is_err()
        );
        assert!(
            require_agent_session_scope(
                &session_with_agent_scopes(&[
                    arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1
                ]),
                arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1,
            )
            .is_ok()
        );
    }

    #[test]
    fn agent_session_requires_query_scan_scope() {
        assert!(
            require_agent_session_scope(
                &session_with_agent_scopes(&[
                    arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1
                ]),
                arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
            )
            .is_err()
        );
        assert!(
            require_agent_session_scope(
                &session_with_agent_scopes(&[
                    arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1
                ]),
                arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
            )
            .is_ok()
        );
    }

    #[test]
    fn agent_session_requires_command_submit_scope() {
        assert!(
            require_agent_session_scope(
                &session_with_agent_scopes(&[
                    arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1
                ]),
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            )
            .is_err()
        );
        assert!(
            require_agent_session_scope(
                &session_with_agent_scopes(&[
                    arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1
                ]),
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            )
            .is_ok()
        );
    }
}
