//! Real PostgreSQL private-cache behavior; these rows prove no protocol authority.
use super::*;

#[derive(QueryableByName)]
struct Number {
    #[diesel(sql_type = BigInt)]
    value: i64,
}

fn profile(station: &str, localpart: &str) -> AccountRecord {
    AccountRecord {
        pk: AccountPk(0),
        principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:profile-holder.example")
            .unwrap(),
        station_id: arkret_wire::DidCoreId::new(station).unwrap(),
        localpart: localpart.into(),
        display_name: Some("private profile".into()),
        biography: Some("private biography".into()),
        avatar_blob_ref: None,
        created_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    }
}

#[tokio::test]
async fn late_profile_or_alias_write_cannot_recreate_terminal_account_private_key() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let profiles = PgAccountStore { pool: pool.clone() };
    let aliases = PgAccountLocalpartStore { pool: pool.clone() };
    let lifecycle = PgAccountLifecycleStore { pool: pool.clone() };
    let mut home = profile("ak:did_core:web:profile-home.example", "profile-home");
    let foreign = profile("ak:did_core:web:profile-foreign.example", "profile-foreign");
    let home_id = arkret_wire::AccountId::new(home.principal_id.clone(), home.station_id.clone());
    let foreign_id =
        arkret_wire::AccountId::new(foreign.principal_id.clone(), foreign.station_id.clone());
    let home_pk = profiles.put(&home).await.unwrap();
    let foreign_pk = profiles.put(&foreign).await.unwrap();
    assert_ne!(home_pk, foreign_pk);
    lifecycle
        .put(
            home_pk,
            &AccountLifecycleRecord {
                state: "erasure_pending".into(),
                reason: None,
                changed_by: None,
                changed_at: home.created_at,
            },
        )
        .await
        .unwrap();
    let mut conn = pool.get().await.unwrap();
    // The physical owner removes these exact private cache rows. No signed
    // status record, execution or erasure receipt is fabricated by this test.
    sql_query("DELETE FROM invite_new_source_hmac_keys WHERE account_pk=$1")
        .bind::<BigInt, _>(home_pk.get())
        .execute(&mut *conn)
        .await
        .unwrap();
    sql_query("DELETE FROM account_localparts WHERE account_pk=$1")
        .bind::<BigInt, _>(home_pk.get())
        .execute(&mut *conn)
        .await
        .unwrap();
    sql_query("UPDATE accounts SET display_name=NULL,payload='{}'::jsonb WHERE pk=$1")
        .bind::<BigInt, _>(home_pk.get())
        .execute(&mut *conn)
        .await
        .unwrap();
    let original = profiles.get(&home_id).await.unwrap().unwrap();
    // Old projection callbacks cannot remove or overwrite the absorbing
    // terminal cache after its actual Account writer has committed.
    for state in ["active", "locked", "suspended", "deactivated"] {
        lifecycle
            .put(
                home_pk,
                &AccountLifecycleRecord {
                    state: state.into(),
                    reason: Some("late callback".into()),
                    changed_by: None,
                    changed_at: home.created_at + chrono::Duration::seconds(1),
                },
            )
            .await
            .unwrap();
    }
    lifecycle.delete(home_pk).await.unwrap();
    let original_terminal = lifecycle
        .snapshot_all()
        .await
        .unwrap()
        .into_iter()
        .find(|(account, _)| account == &home_id)
        .unwrap()
        .1;
    assert_eq!(original_terminal.state, "erasure_pending");
    assert_eq!(original_terminal.reason, None);
    assert_eq!(original_terminal.changed_by, None);
    assert_eq!(original_terminal.changed_at, home.created_at);

    home.localpart = "late-handle".into();
    home.display_name = Some("late private profile".into());
    assert_eq!(
        profiles.put(&home).await.unwrap_err().conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
    assert_eq!(
        aliases
            .add(home_pk, "late-alias", true)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
    let after = profiles.get(&home_id).await.unwrap().unwrap();
    assert_eq!(after.display_name, original.display_name);
    assert_eq!(after.biography, original.biography);
    assert_eq!(after.localpart, original.localpart);
    assert_eq!(
        sql_query(
            "SELECT COUNT(*)::bigint AS value FROM invite_new_source_hmac_keys WHERE account_pk=$1"
        )
        .bind::<BigInt, _>(home_pk.get())
        .get_result::<Number>(&mut *conn)
        .await
        .unwrap()
        .value,
        0
    );
    assert_eq!(
        sql_query("SELECT COUNT(*)::bigint AS value FROM account_localparts WHERE account_pk=$1")
            .bind::<BigInt, _>(home_pk.get())
            .get_result::<Number>(&mut *conn)
            .await
            .unwrap()
            .value,
        0
    );
    assert_eq!(
        profiles
            .get(&foreign_id)
            .await
            .unwrap()
            .unwrap()
            .display_name,
        foreign.display_name
    );
    assert!(
        aliases
            .add(foreign_pk, "foreign-alias", false)
            .await
            .is_ok()
    );
    // A new, distinct full Account remains an ordinary lawful first create.
    let fresh = profile("ak:did_core:web:profile-fresh.example", "profile-fresh");
    assert!(profiles.put(&fresh).await.is_ok());
}
