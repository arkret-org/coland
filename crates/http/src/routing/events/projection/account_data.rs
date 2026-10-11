use arkret_event_draft::ProjectedEventOperation as Operation;
use coland_services::identity::AccountDataState;
use serde_json::Value;

use crate::routing::identity::device_messages::{
    ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate, ActorPrivateDeviceUpdate,
    DeviceMessageSender, fanout_actor_private_update,
};
use crate::state::AppState;

pub(super) async fn project_account_data_set(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
) {
    let Some(account_data_key) = operation
        .payload
        .get("key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    let Some(account_id) = operation.context.sender.as_account_id() else {
        return;
    };
    // This projection and its device fanout belong to the local Account. A
    // foreign accepted Event cannot borrow a same-principal local directory.
    if account_id.station_id != state.service_core_id() {
        return;
    }
    let owner = operation.context.sender.to_string();
    let Some(expected_revision) = operation
        .payload
        .get("expected_server_revision")
        .and_then(Value::as_u64)
    else {
        tracing::warn!(
            owner,
            account_data_key,
            "account_data Event missing expected_server_revision"
        );
        return;
    };
    let Some(revision) = expected_revision.checked_add(1) else {
        tracing::warn!(owner, account_data_key, "account_data revision exhausted");
        return;
    };
    let tombstone = operation
        .payload
        .get("tombstone")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let content = if tombstone {
        Value::Null
    } else {
        let Some(content) = operation
            .payload
            .get("body")
            .or_else(|| operation.payload.get("encrypted_payload"))
            .cloned()
        else {
            return;
        };
        content
    };
    let record = AccountDataState {
        actor_id: owner.to_owned(),
        account_data_key: account_data_key.to_owned(),
        revision,
        payload: content,
        tombstone,
        updated_at: operation.created_at,
    };
    // The Event commit already applied CAS and published its exact current
    // source. This asynchronous projection only fans out that committed value.
    let applied = match state.account_data().entry(&owner, account_data_key).await {
        Ok(Some(applied))
            if applied.revision == revision
                && applied.payload == record.payload
                && applied.tombstone == tombstone =>
        {
            applied
        }
        Ok(_) => return,
        Err(error) => {
            tracing::warn!(%error, "committed account data unavailable for fanout");
            return;
        }
    };
    if !source_device_id.is_empty() && origin == account_id.principal_id.as_str() {
        let Ok(sender_device_id) = arkret_identifiers::DeviceId::new(source_device_id.to_owned())
        else {
            tracing::warn!(
                owner,
                source_device_id,
                "actor-private account-data fanout source is not a DeviceId"
            );
            return;
        };
        let sender = DeviceMessageSender::Account {
            sender_account_id: account_id.clone(),
            sender_device_id,
        };
        let content = ActorPrivateAccountDataUpdate {
            operation: if tombstone {
                ActorPrivateAccountDataOperation::Delete
            } else {
                ActorPrivateAccountDataOperation::Put
            },
            account_data_key: account_data_key.to_owned(),
            revision: applied.revision,
            content: (!tombstone).then_some(applied.payload.clone()),
            updated_at: applied.updated_at,
        };
        let update = ActorPrivateDeviceUpdate::AccountData {
            sender,
            content,
            created_at: applied.updated_at,
        };
        fanout_actor_private_update(state, account_id.principal_id.as_str(), update).await;
    }
}

mod tests {
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn asynchronous_account_data_projection_cannot_accept_or_replace_cas() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:holder.example").unwrap(),
            state.service_core_id(),
        ));
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_wire::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000002")
                .unwrap(),
            arkret_wire::RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")
                .unwrap(),
            arkret_wire::EventKind::AccountDataSet.as_str(),
            json!({"key":"ak.dnd_schedule","expected_server_revision":0,"body":{"value":"uncommitted"}}),
        );
        operation.context.sender = actor.clone();
        project_account_data_set(
            &state,
            actor.signing_principal_id().as_str(),
            "",
            &operation,
        )
        .await;
        assert!(
            state
                .account_data()
                .entry(&actor.to_string(), "ak.dnd_schedule")
                .await
                .unwrap()
                .is_none()
        );
    }
}
