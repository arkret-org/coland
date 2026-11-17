use super::*;

#[tokio::test]
async fn diagnostic_audit_never_persists_a_private_business_body() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuditStore { pool: pool.clone() };
    let audit_id = crate::ids::generate("audit");
    let actor = "ak:did_core:web:private-audit.example";
    let entry = serde_json::json!({
        "audit_id": audit_id,
        "actor": actor,
        "action": "account_data.set",
        "outcome": "accepted",
        "payload": {"account_data_key":"ak.private.contact.did:secret.example", "secret":"private body"},
        "created_at":"2026-11-16T00:00:00Z",
    });
    store.append(entry.clone()).await.unwrap();
    // A delayed callback uses the same sink and cannot regenerate a private
    // body even without an authentication or Account-lifecycle dependency.
    let late_id = crate::ids::generate("audit");
    let mut late = entry.clone();
    late["audit_id"] = serde_json::json!(late_id);
    store.append(late).await.unwrap();
    let mut conn = pool.get().await.unwrap();
    let bypass=sql_query("INSERT INTO audit_logs(id,actor_id,action,outcome,payload) VALUES($1,$2,'account_data.set','accepted',$3)")
        .bind::<sql_types::Uuid,_>(uuid::Uuid::now_v7()).bind::<Text,_>(actor)
        .bind::<Jsonb,_>(&entry).execute(&mut *conn).await;
    assert!(
        bypass.is_err(),
        "the initial schema must reject a generic private-body bypass"
    );
    drop(conn);
    let rows = store.list_for_actor(actor).await.unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row["action"], "account_data.set");
        assert_eq!(row["outcome"], "accepted");
        assert!(row.get("payload").is_none());
        assert!(row["audit_id"] == audit_id || row["audit_id"] == late_id);
    }
}
