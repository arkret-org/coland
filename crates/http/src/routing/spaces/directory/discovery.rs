use serde_json::Value;
use coland_services::identity::SessionIdentityState as SessionRecord;

use crate::state::AppState;

pub async fn has_accepted_contact(state: &AppState, left: &str, right: &str) -> bool {
    let (Ok(left_principal), Ok(right_principal)) = (
        arkret_wire::DidCoreId::new(left.to_owned()),
        arkret_wire::DidCoreId::new(right.to_owned()),
    ) else {
        return false;
    };
    let left = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        left_principal,
        state.service_core_id().clone(),
    ));
    let right = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        right_principal,
        state.service_core_id().clone(),
    ));
    state
        .contacts()
        .contacts_for_actor(&left)
        .await
        .unwrap_or_default()
        .iter()
        .any(|contact| {
            contact.status == "accepted"
                && ((contact.requester_id == left && contact.target_id == right)
                    || (contact.requester_id == right && contact.target_id == left))
        })
}

pub async fn actor_visible_to(
    state: &AppState,
    actor: &Value,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(actor_id) = actor["actor_id"].as_str() else {
        return false;
    };
    if actor_id == "ak:did_core:web:alice.example" {
        return true;
    }
    match session {
        Some(session) => {
            session.actor == actor_id || has_accepted_contact(state, &session.actor, actor_id).await
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::{now, query_matches};
    use super::*;

    #[tokio::test]
    async fn accepted_contact_visibility_does_not_turn_a_mismatched_query_into_a_hit() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let alice = "ak:did_core:web:alice.example";
        let bob = "ak:did_core:web:bob.example";
        let observed_at = now();
        state
            .contacts()
            .save_contact(coland_services::identity::ContactRecord {
                requester_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    arkret_wire::DidCoreId::new(alice.to_owned()).unwrap(),
                    state.service_core_id().clone(),
                )),
                target_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    arkret_wire::DidCoreId::new(bob.to_owned()).unwrap(),
                    state.service_core_id().clone(),
                )),
                contact_round_id: Some(
                    arkret_wire::Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
                ),
                granted_to_target_scopes: vec!["direct_message".to_owned()],
                granted_to_requester_scopes: vec!["direct_message".to_owned()],
                status: "accepted".to_owned(),
                pending_incoming_admitted: true,
                request_event_ref: None,
                request_slot_states: Vec::new(),
                request_receipts: Vec::new(),
                request_mirror_receipts: Vec::new(),
                contact_round_evidence: None,
                contact_round_evidence_history: Vec::new(),
                control_outcomes: Vec::new(),
                response_event_ref: None,
                tombstone_event_ref: None,
                message: None,
                peer_host_id: None,
                peer_service_resolution: None,
                created_at: observed_at,
                updated_at: observed_at,
            })
            .await
            .unwrap();
        let session = SessionRecord {
            account_pk: None,
            token_hash: "directory-test-token".to_owned(),
            actor: alice.to_owned(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: "ak:device:019a0000-0000-7000-8000-000000000001".to_owned(),
            },
            audience: state.service_id().clone(),
            session_public_key: None,
            session_grant: None,
            expires_at: observed_at + chrono::Duration::hours(1),
            created_at: observed_at,
            revoked_at: None,
        };
        let candidate = json!({
            "actor_id": bob,
            "handle": "@collab-bob",
            "display_name": "collab-bob"
        });

        assert!(actor_visible_to(&state, &candidate, Some(&session)).await);
        assert!(query_matches(&candidate, Some("collab-bob")));
        assert!(!query_matches(&candidate, Some("cotest-collab-bob")));
    }
}
