//! Exact Account-private copies, removed before the final global MVCC purge.
use arkret_wire::{AccountId, ActorId};
use coland_storage::{DeviceRevocationGateSelector, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension as _, RunQueryDsl as _};

use crate::AsyncPgConnection;

#[derive(QueryableByName)]
struct SelectorRow {
    #[diesel(sql_type = Jsonb)]
    selector: serde_json::Value,
    #[diesel(sql_type = Text)]
    recipient: String,
    #[diesel(sql_type = Text)]
    device_id: String,
}

#[derive(QueryableByName)]
struct MirrorOwnerRow {
    #[diesel(sql_type = Text)]
    target_holder_principal_id: String,
    #[diesel(sql_type = Text)]
    request_event_id: String,
    #[diesel(sql_type = Jsonb)]
    source_receipt: serde_json::Value,
}

#[derive(QueryableByName)]
struct AgentPrivateRow {
    #[diesel(sql_type = Text)]
    id: String,
}

#[derive(QueryableByName)]
struct ForwardPrivateRow {
    #[diesel(sql_type = BigInt)]
    event_pk: i64,
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
}

#[derive(QueryableByName)]
struct AccountPkRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}

fn unproved(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: Account erasure {detail}"))
}

/// These rows were admitted through the ordinary queue's verified original
/// Device selector gate. The receiver's accepted terminal record authorizes
/// deletion; it need not import the foreign PCR a second time. Unknown or
/// internally inconsistent selectors remain a completion failure.
async fn check_queue_ownership(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
) -> PersistenceResult<()> {
    let rows=sql_query(
        "SELECT recipient_device_authorization AS selector,recipient,device_id FROM device_messages WHERE recipient=$1 \
         UNION ALL SELECT recipient_device_authorization,recipient,device_id FROM device_message_ack_tokens WHERE recipient=$1 AND effective_scope IS NULL \
         UNION ALL SELECT recipient_device_authorization,recipient,recipient_device_id FROM mls_welcome_deliveries WHERE recipient=$1 AND recipient_endpoint_kind='device' AND state='queued'"
    ).bind::<Text,_>(account.principal_id.as_str()).load::<SelectorRow>(&mut *conn)
        .await.map_err(PersistenceError::database)?;
    for row in rows {
        let selector: DeviceRevocationGateSelector = serde_json::from_value(row.selector.clone())
            .map_err(|_| {
            unproved("has a recipient without an exact original Device selector")
        })?;
        if serde_json::to_value(&selector).map_err(PersistenceError::database)? != row.selector
            || selector.principal_id.as_str() != row.recipient
            || selector.device_id != row.device_id
        {
            return Err(unproved("recipient and original Device selector disagree"));
        }
    }
    Ok(())
}

/// The owning transaction verified the accepted terminal intent and holds Account UPDATE.
/// Human queue and cursor producers acquire Account SHARE before private rows.
/// No ACK, Welcome delivery transition or prekey consume occurs here.
pub(super) async fn purge(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
) -> PersistenceResult<()> {
    let holder = serde_json::to_value(account).map_err(PersistenceError::database)?;
    let actor = ActorId::account(account.clone()).to_string();
    let actor_json = serde_json::to_value(ActorId::account(account.clone()))
        .map_err(PersistenceError::database)?;
    let pk = sql_query("SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2")
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .get_result::<AccountPkRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .pk;
    for statement in [
        "DELETE FROM consent_private_effect_jobs WHERE holder_account_id=$1",
        "DELETE FROM consent_private_effect_fences WHERE holder_account_id=$1",
        "DELETE FROM consent_private_proxy_fences WHERE holder_account_id=$1",
        "DELETE FROM consent_private_effect_cuts WHERE holder_account_id=$1",
        "DELETE FROM consent_private_proxy_cuts WHERE holder_account_id=$1",
    ] {
        sql_query(statement)
            .bind::<Jsonb, _>(&holder)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    }
    sql_query("DELETE FROM mimi_consent_decision_attempts WHERE consent_id IN(SELECT consent_id FROM mimi_consent_correlations WHERE holder_account_id::jsonb=$1 OR requester_actor_id::jsonb=$2)")
        .bind::<Jsonb,_>(&holder).bind::<Jsonb,_>(&actor_json).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    sql_query("DELETE FROM mimi_consent_correlations WHERE holder_account_id::jsonb=$1 OR requester_actor_id::jsonb=$2")
        .bind::<Jsonb,_>(&holder).bind::<Jsonb,_>(&actor_json).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    sql_query("DELETE FROM invite_locators WHERE subject_id=$1 AND recipient_id=$2")
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    sql_query("DELETE FROM invite_receive_policies WHERE account_pk=$1")
        .bind::<BigInt, _>(pk)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    sql_query("DELETE FROM notifications WHERE recipient_actor_id=$1 OR controller_account_pk=$2")
        .bind::<Text, _>(&actor)
        .bind::<BigInt, _>(pk)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    for statement in [
        "DELETE FROM account_summary_current WHERE actor_key=$1",
        "DELETE FROM account_summary_versions WHERE actor_key=$1",
    ] {
        sql_query(statement)
            .bind::<Text, _>(&actor)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    }
    // Hosting intent/outcome mirrors are private copies, not governing
    // authority or installed MLS state. The immutable original Event gives
    // the actual producer through the one SDK executed-by/actor rule.
    let forwards = sql_query("SELECT a.event_pk,e.envelope FROM authority_forward_attempts a JOIN canonical_events e ON e.pk=a.event_pk WHERE e.envelope->'actor_id'=$1 OR e.envelope->'executed_by'=$1")
        .bind::<Jsonb,_>(&actor_json).load::<ForwardPrivateRow>(&mut *conn)
        .await.map_err(PersistenceError::database)?;
    let own_actor = ActorId::account(account.clone());
    for forward in forwards {
        let event: arkret_wire::Event =
            serde_json::from_value(forward.envelope).map_err(PersistenceError::database)?;
        if crate::organization_hosting::handle_private_forward_erasure(conn, &event, account)
            .await?
        {
            continue;
        }
        if event.actual_signer() == &own_actor {
            sql_query("DELETE FROM authority_forward_attempts WHERE event_pk=$1")
                .bind::<BigInt, _>(forward.event_pk)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
        }
    }
    // Independent Agent public authorization remains. Only the controller's
    // private pairing/approval/saga adjuncts are cleared, after proving the
    // complete controller Account from the accepted provision original.
    let agents = sql_query("SELECT id FROM agent_principals WHERE controller_principal_id=$1 OR controller_account_pk=$2")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<BigInt,_>(pk)
        .load::<AgentPrivateRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for agent in agents {
        let owner = crate::agents::private_controller_account(conn, &agent.id)
            .await?
            .ok_or_else(|| unproved("Agent private projection disappeared"))?;
        if &owner == account {
            // The only private presentation body belongs to this same PG
            // boundary. Keep the minimal accepted nonce/authorization receipt.
            sql_query(
                "UPDATE agent_pairing_receipts SET encrypted_scope_custody=NULL WHERE agent_id=$1",
            )
            .bind::<Text, _>(&agent.id)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            sql_query("UPDATE agent_principals SET requested_scope=NULL,pairing_request_id=NULL,paired_pairing_request_id=NULL,paired_request_digest=NULL,pending_pairing_commit_intent=NULL,pairing_code=NULL,pairing_expires_at=NULL,approval_request_id=NULL,recipient_id=NULL,runtime_key_binding_digest=NULL,approval_notification_id=NULL,runtime_key_material=NULL,approval_requested_at=NULL,provision_event_refs=NULL WHERE id=$1")
                .bind::<Text,_>(&agent.id).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        }
    }
    // Generic diagnostic audits never retain inner private bodies: the unique
    // sink and the initial schema enforce this at every legal insertion.
    // Shared Contact rows retain their exact signed originals and continuity.
    sql_query("UPDATE contacts SET message=NULL,peer_service_resolution=NULL WHERE requester_id=$1 OR target_id=$1")
        .bind::<Text,_>(&actor).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let mirrors = sql_query("SELECT target_holder_principal_id,request_event_id,source_receipt FROM contact_verified_mirrors WHERE target_holder_principal_id=$1")
        .bind::<Text,_>(account.principal_id.as_str()).load::<MirrorOwnerRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for mirror in mirrors {
        let receipt: arkret_models_collaboration::contact_operations::RequestAcceptanceReceipt =
            serde_json::from_value(mirror.source_receipt).map_err(PersistenceError::database)?;
        let peer = receipt.core.peer.contact_actor_id();
        let owner = peer
            .as_account_id()
            .ok_or_else(|| unproved("Contact mirror has no exact Account peer"))?;
        if owner.principal_id.as_str() != mirror.target_holder_principal_id {
            return Err(unproved(
                "Contact mirror key differs from its exact source peer",
            ));
        }
        if owner == account {
            sql_query("DELETE FROM contact_verified_mirrors WHERE target_holder_principal_id=$1 AND request_event_id=$2")
                .bind::<Text,_>(&mirror.target_holder_principal_id).bind::<Text,_>(&mirror.request_event_id)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        }
    }
    // Per-handle retention children cascade; global revision clocks stay intact.
    sql_query("DELETE FROM sync_cursor_handles h WHERE h.binding_subject=$1 OR h.session_id IN(SELECT id FROM sessions WHERE account_pk=$2 AND actor_id=$3)")
        .bind::<Text,_>(account.to_string()).bind::<BigInt,_>(pk).bind::<Text,_>(account.principal_id.as_str())
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    sql_query("DELETE FROM recovery_sessions WHERE principal_id=$1 AND station_id=$2")
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    // Episode-local inventory and census copies are private discovery state.
    // The signed Recovery R/C and accepted PCR originals remain intact.
    sql_query("DELETE FROM content_recovery_census_sources c USING content_recovery_episodes e WHERE c.authorization_event_ref=e.authorization_event_ref AND e.actor_id=$1")
        .bind::<Jsonb,_>(&actor_json).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    sql_query("WITH erased AS (DELETE FROM content_recovery_episodes WHERE actor_id=$1 RETURNING inventory_blob_ref)
        DELETE FROM blobs WHERE id IN (SELECT inventory_blob_ref FROM erased) AND storage_backend='recovery_inventory'")
        .bind::<Jsonb, _>(&actor_json)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    // A SecurityRotation plan and step response contain full backup ciphertext.
    // Keep identity and accepted proof fields, but no retrievable private plan.
    // Recovery R/C originals remain intact for the native recovery source.
    sql_query("DELETE FROM security_transaction_step_attempts a USING security_transactions t WHERE a.transaction_id=t.id AND t.kind='security_rotation' AND t.principal_id=$1 AND t.station_id=$2")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    sql_query("UPDATE security_transaction_step_outcomes o SET canonical_request=NULL,response=NULL FROM security_transactions t WHERE o.transaction_id=t.id AND t.kind='security_rotation' AND t.principal_id=$1 AND t.station_id=$2")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    sql_query("UPDATE security_transactions SET canonical_request=NULL,prepared_plan=NULL WHERE kind='security_rotation' AND principal_id=$1 AND station_id=$2")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    // External Gateway receipts must already be durably verified. An active
    // registration or unfinished revoke is an infrastructure-pending execution.
    let push = sql_query("SELECT pk FROM accounts WHERE pk=$1 AND (EXISTS(SELECT 1 FROM push_devices WHERE payload->'account_id'=$2) OR EXISTS(SELECT 1 FROM push_registration_handoff_intents WHERE local_account_id=$2 AND (desired_state<>'revoked' OR status<>'receipt_verified')))")
        .bind::<BigInt,_>(pk).bind::<Jsonb,_>(&holder)
        .get_result::<AccountPkRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if push.is_some() {
        return Err(unproved(
            "Push Gateway revocation has not durably completed",
        ));
    }
    check_queue_ownership(conn, account).await?;
    for statement in [
        "DELETE FROM device_message_ack_tokens WHERE recipient=$1 AND recipient_device_authorization->>'principal_id'=$1 AND recipient_device_authorization->>'station_id'=$2 AND effective_scope IS NULL",
        "DELETE FROM device_messages WHERE recipient=$1 AND recipient_device_authorization->>'principal_id'=$1 AND recipient_device_authorization->>'station_id'=$2",
        "DELETE FROM mls_welcome_deliveries WHERE recipient=$1 AND recipient_endpoint_kind='device' AND recipient_device_authorization->>'principal_id'=$1 AND recipient_device_authorization->>'station_id'=$2 AND state='queued'",
    ] {
        sql_query(statement)
            .bind::<Text, _>(account.principal_id.as_str())
            .bind::<Text, _>(account.station_id.as_str())
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    }

    sql_query("DELETE FROM signal_relay_watermark WHERE actor_id=$1")
        .bind::<Text, _>(&actor)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    // The opaque grant cache is private. Keep only its public Device binding
    // and durable denial coordinates, without changing any original expiry.
    sql_query("UPDATE sessions SET revoked_at=COALESCE(revoked_at,NOW()),session_public_key=NULL,payload=CASE WHEN payload ? 'device_authorization' THEN jsonb_build_object('device_authorization',payload->'device_authorization') ELSE '{}'::jsonb END,updated_at=NOW() WHERE account_pk=$1 AND actor_id=$2")
        .bind::<BigInt,_>(pk).bind::<Text,_>(account.principal_id.as_str()).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    // Presentation/activity metadata is optional. The remaining authorization
    // and public-key fields are separately retained signed provenance.
    sql_query("UPDATE devices SET payload=payload-'display_name'-'last_seen_at'-'last_key_upload_at',revoked_at=COALESCE(revoked_at,NOW()),updated_at=NOW() WHERE actor_id=$1 AND station_id=$2")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str()).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(())
}

#[cfg(test)]
mod owner_projection_tests {
    use super::*;

    #[derive(QueryableByName)]
    struct Owner {
        #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
        owner: Option<serde_json::Value>,
    }

    #[tokio::test]
    async fn original_private_owner_is_the_controller_not_the_agent_signer() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let holder = serde_json::json!({"principal_id":"ak:did_core:web:holder.example","station_id":"ak:did_core:web:home.example"});
        let other = serde_json::json!({"principal_id":"ak:did_core:web:holder.example","station_id":"ak:did_core:web:foreign.example"});
        let agent = serde_json::json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:agent.example","station_id":"ak:did_core:web:home.example"}});
        for (kind, payload, actor) in [
            (
                "ak.agent.action_request",
                serde_json::json!({"controller_account_id":holder}),
                agent.clone(),
            ),
            (
                "ak.agent.draft.propose",
                serde_json::json!({"controller_account_id":holder}),
                agent.clone(),
            ),
            (
                "ak.device.push_route",
                serde_json::json!({"account_id":holder}),
                agent.clone(),
            ),
            (
                "ak.read_cursor.advance",
                serde_json::json!({"actor_id":{"kind":"account","account_id":holder}}),
                agent.clone(),
            ),
            (
                "ak.agent.action_reject",
                serde_json::json!({}),
                serde_json::json!({"kind":"account","account_id":holder}),
            ),
            (
                "ak.account_data.set",
                serde_json::json!({}),
                serde_json::json!({"kind":"account","account_id":holder}),
            ),
        ] {
            // Minimal scalar inputs exercise only a DB ownership projection;
            // they are not inserted or accepted as signed protocol Events.
            let envelope = serde_json::json!({"kind":kind,"actor_id":actor,"payload":payload});
            let selected = sql_query("SELECT actor_private_event_owner($1) AS owner")
                .bind::<Jsonb, _>(envelope)
                .get_result::<Owner>(&mut *conn)
                .await
                .unwrap()
                .owner
                .unwrap();
            assert_eq!(selected, holder);
            assert_ne!(selected, other);
        }
        let selected=sql_query("SELECT actor_private_event_owner($1) AS owner")
            .bind::<Jsonb,_>(serde_json::json!({"kind":"ak.message.create","actor_id":agent,"payload":{"controller_account_id":holder}}))
            .get_result::<Owner>(&mut *conn).await.unwrap().owner;
        assert!(selected.is_none());
    }
}
