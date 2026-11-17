//! Component cache locks are real PG locks; no signed erasure is fabricated.
use arkret_wire::{AccountId, DidCoreId, EventAdmissionSubmission, EventKind};
use chrono::Utc;
use diesel_async::AsyncConnection;

use super::*;

fn foreign(owner: &AccountId) -> AccountId {
    AccountId::new(
        owner.principal_id.clone(),
        DidCoreId::new("ak:did_core:web:mimi-foreign.example").unwrap(),
    )
}

fn correlation(
    holder: &AccountId,
    requester: &AccountId,
    label: &str,
) -> MimiConsentCorrelationRecord {
    MimiConsentCorrelationRecord {
        consent_id: format!("ak:consent:{}", uuid::Uuid::now_v7()),
        requester_actor_id: arkret_canonical::canonical_json_string(&ActorId::account(
            requester.clone(),
        ))
        .unwrap(),
        holder_account_id: arkret_canonical::canonical_json_string(holder).unwrap(),
        purpose: "voice_call".into(),
        strand_id: None,
        source_id: Some(label.into()),
        source_class: coland_storage::MimiConsentSourceClass::Service,
        created_at: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
        expires_at: None,
    }
}

#[derive(QueryableByName)]
struct Backend {
    #[diesel(sql_type=diesel::sql_types::Integer)]
    pid: i32,
}
#[derive(QueryableByName)]
struct Waiting {
    #[diesel(sql_type=diesel::sql_types::Bool)]
    waiting: bool,
}

#[tokio::test]
async fn real_erasure_lock_waiter_cannot_recreate_deleted_mimi_decision_or_correlation() {
    let fixture = Box::pin(coland_test_support::agent_origin::OriginFixture::new()).await;
    let owner = fixture.controller.history.account.clone();
    let other = foreign(&owner);
    let mut observer = fixture.pool.get().await.unwrap();
    sql_query("INSERT INTO accounts(principal_id,station_id,payload) VALUES($1,$2,'{}'::jsonb)")
        .bind::<Text, _>(other.principal_id.as_str())
        .bind::<Text, _>(other.station_id.as_str())
        .execute(&mut *observer)
        .await
        .unwrap();
    let store = PgMimiConsentCorrelationStore {
        pool: fixture.pool.clone(),
    };
    let original = correlation(&owner, &other, "original-service");
    store.put(&original).await.unwrap();
    let event=fixture.controller.history.event(EventKind::ConsentReplace,serde_json::json!({
        "expected_current":{"state":"never_written"},"peer":{"kind":"actor","actor_id":ActorId::account(other.clone())},"permissions":[{"consent_scope":"voice_call"}]
    }));
    let submission = EventAdmissionSubmission::new(event);
    let mut eraser = fixture.pool.get().await.unwrap();
    let pid = sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Backend>(&mut *eraser)
        .await
        .unwrap()
        .pid;
    let writer_pool = fixture.pool.clone();
    let consent_id = original.consent_id.clone();
    let writer=eraser.transaction::<_,crate::PgTransactionError,_>(async |conn| {
        sql_query("SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2 FOR UPDATE")
            .bind::<Text,_>(owner.principal_id.as_str()).bind::<Text,_>(owner.station_id.as_str()).execute(&mut *conn).await?;
        sql_query("INSERT INTO account_lifecycle(account_pk,state,changed_at) SELECT pk,'erasure_pending',NOW() FROM accounts WHERE principal_id=$1 AND station_id=$2")
            .bind::<Text,_>(owner.principal_id.as_str()).bind::<Text,_>(owner.station_id.as_str()).execute(&mut *conn).await?;
        let writer=tokio::spawn(async move {
            PgMimiConsentCorrelationStore { pool:writer_pool }.bind_decision(&consent_id,"accept",&submission,true).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5),async {
            loop {
                let waiting=sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%lock_active_account_private_state%') AS waiting")
                    .bind::<diesel::sql_types::Integer,_>(pid).get_result::<Waiting>(&mut *observer).await.unwrap().waiting;
                if waiting { break; }
                tokio::task::yield_now().await;
            }
        }).await.expect("the actual private writer must wait on this eraser's Account row");
        sql_query("DELETE FROM mimi_consent_decision_attempts WHERE consent_id=$1").bind::<Text,_>(&original.consent_id).execute(&mut *conn).await?;
        sql_query("DELETE FROM mimi_consent_correlations WHERE consent_id=$1").bind::<Text,_>(&original.consent_id).execute(&mut *conn).await?;
        Ok(writer)
    }).await.map_err(crate::PgTransactionError::into_persistence).unwrap();
    assert_eq!(
        writer.await.unwrap().unwrap_err().conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
    assert!(store.get(&original.consent_id).await.unwrap().is_none());
    assert_eq!(
        store.put(&original).await.unwrap_err().conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
    // Same principal at another Station remains a distinct writable Account.
    let independent = correlation(&other, &other, "foreign-service");
    store.put(&independent).await.unwrap();
    assert_eq!(
        store.get(&independent.consent_id).await.unwrap(),
        Some(independent)
    );
}
