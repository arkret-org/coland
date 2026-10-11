//! Check the decoder's 64-ref budget after prospective typed-current writes,
//! before the enclosing accepted authority transaction can commit.

use super::{
    AsyncPgConnection, Jsonb, PersistenceError, PersistenceResult, QueryableByName, RunQueryDsl,
    Text, sql_query,
};

#[derive(QueryableByName)]
struct Affected {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    sidecar_id: String,
    #[diesel(sql_type = Jsonb)]
    controller_account_id: serde_json::Value,
}

pub(crate) async fn after_current_writes_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> PersistenceResult<()> {
    let affected = sql_query("SELECT DISTINCT s.realm_id,s.sidecar_id,s.controller_account_id FROM sidecar_current_results s \
        LEFT JOIN pcr_genesis_units g ON g.principal_id=s.controller_account_id->>'principal_id' \
          AND g.station_id=s.controller_account_id->>'station_id' \
        LEFT JOIN agent_provisioning_current_results p ON p.realm_id=g.realm_id \
          AND p.value->>'controller_principal_id'=g.principal_id \
        WHERE s.value->>'state'='active' AND (s.realm_id=$1 OR g.realm_id=$1 OR p.value->>'principal_control_realm_id'=$1) \
        ORDER BY s.realm_id,s.sidecar_id")
        .bind::<Text,_>(event.realm_id.as_str()).load::<Affected>(&mut *conn).await.map_err(PersistenceError::database)?;
    for sidecar in affected {
        let realm =
            arkret_wire::RealmId::new(sidecar.realm_id).map_err(PersistenceError::database)?;
        let id =
            arkret_wire::SidecarId::new(sidecar.sidecar_id).map_err(PersistenceError::database)?;
        let controller = serde_json::from_value(sidecar.controller_account_id)
            .map_err(PersistenceError::database)?;
        let cut =
            crate::sidecar_authority_cut::locked_in_connection(conn, &realm, &id, &controller)
                .await;
        if let Err(PersistenceError::SchemaViolation(message)) = &cut
            && message == "Sidecar participant authority cut exceeds 64 accepted refs"
        {
            return Err(PersistenceError::Conflict(format!(
                "{}: Sidecar participant authority cut exceeds 64 accepted refs",
                coland_storage::ConflictCode::FailedPrecondition
            )));
        }
        // A missing parent membership means this Sidecar has no live desired
        // cut. An unheld or corrupt authority source remains a hard refusal.
        cut?;
    }
    Ok(())
}
