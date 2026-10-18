//! Registry-backed governance approval configuration, never an authority grant.
use arkret_models_collaboration::events_payloads::PolicyActionDocument;
use arkret_wire::CapabilityActionId;
use coland_storage::{PersistenceError, PersistenceResult};

pub(crate) fn require_registered_carrier(action: CapabilityActionId) -> PersistenceResult<()> {
    let descriptor = arkret_schema::capability_action_descriptor(action);
    if descriptor.approval_evidence_carrier_id.is_none()
        || descriptor.approval_requirement_eligibility
            == arkret_schema::ApprovalRequirementEligibility::IneligibleNoRegisteredCarrier
    {
        return Err(PersistenceError::SchemaViolation(
            "approval_carrier_unregistered: action has no registered approval evidence carrier"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Caller has resolved exact current scopes and effective Policy references at
/// its frozen cut. OR/max is independent of namespace and row ordering.
pub(crate) fn effective_quorum<'a>(
    action: CapabilityActionId,
    matching: impl IntoIterator<Item = &'a PolicyActionDocument>,
) -> PersistenceResult<Option<u64>> {
    let mut quorum = None;
    for document in matching {
        document
            .validate()
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        if document.action.as_str() != action.as_str() {
            continue;
        }
        if document.approval_required {
            require_registered_carrier(action)?;
            quorum = Some(quorum.unwrap_or(0u64).max(document.approval_quorum));
        }
    }
    Ok(quorum)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(quorum: u64, required: bool) -> PolicyActionDocument {
        serde_json::from_value(serde_json::json!({"action":"ak.strand.move","approval_required":required,
            "approval_quorum":quorum,"policy_scope":"ak:realm:AKZtk00-QonOuPLHdYdyGYATwu66wDI-jFH83rByulha"})).unwrap()
    }
    #[test]
    fn governance_or_max_preserves_both_namespaces_and_false_is_layer_local() {
        let docs = [config(2, true), config(99, false), config(3, true)];
        assert_eq!(
            effective_quorum(CapabilityActionId::StrandMove, docs.iter()).unwrap(),
            Some(3)
        );
        assert_eq!(
            effective_quorum(CapabilityActionId::StrandMove, docs.iter().rev()).unwrap(),
            Some(3)
        );
        assert_eq!(
            effective_quorum(CapabilityActionId::StrandMove, std::iter::empty()).unwrap(),
            None
        );
    }
}

#[derive(diesel::QueryableByName)]
struct ConfigRow {
    #[diesel(sql_type=diesel::sql_types::Text)]
    subject_kind: String,
    #[diesel(sql_type=diesel::sql_types::Text)]
    subject_id: String,
    #[diesel(sql_type=diesel::sql_types::Jsonb)]
    value: serde_json::Value,
}
#[derive(diesel::QueryableByName)]
struct DocumentRow {
    #[diesel(sql_type=diesel::sql_types::Jsonb)]
    value: serde_json::Value,
}

/// Current rows only. Resolve references inside the accepting transaction and
/// keep private subjects out of every caller-visible refusal.
pub(crate) async fn current_quorum(
    conn: &mut diesel_async::AsyncPgConnection,
    event: &arkret_wire::Event,
    action: CapabilityActionId,
    target: &arkret_wire::WireResourceSelector,
    facts: &coland_storage::OperationFacts,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<u64>> {
    current_operation_quorum(conn, &event.realm_id, action, target, facts, at).await
}

/// Governance approval for a real non-Event operation at its locked Realm cut.
pub(crate) async fn current_operation_quorum(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    action: CapabilityActionId,
    target: &arkret_wire::WireResourceSelector,
    facts: &coland_storage::OperationFacts,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<u64>> {
    use diesel::OptionalExtension;
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;
    let rows=diesel::sql_query("SELECT subject_kind,subject_id,value FROM policy_action_current_results WHERE realm_id=$1 ORDER BY subject_kind,subject_id,action_key")
        .bind::<Text,_>(realm.as_str()).load::<ConfigRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut matched = Vec::new();
    for row in rows {
        let config: PolicyActionDocument = serde_json::from_value(row.value).map_err(|_| {
            PersistenceError::Conflict(
                "failed_precondition: current governance approval configuration is invalid"
                    .to_owned(),
            )
        })?;
        config.validate().map_err(|_| {
            PersistenceError::Conflict(
                "failed_precondition: current governance approval configuration is invalid"
                    .to_owned(),
            )
        })?;
        if config.action.as_str() != action.as_str() {
            continue;
        }
        let scope =
            crate::policy_current_results::resolve_scope(conn, realm, &config.policy_scope).await?;
        if !scope_contains(conn, realm, &scope, target, facts).await? {
            continue;
        }
        if row.subject_kind == "policy_ref" {
            let Some(policy) = diesel::sql_query(
                "SELECT value FROM policy_current_results WHERE realm_id=$1 AND policy_id=$2",
            )
            .bind::<Text, _>(realm.as_str())
            .bind::<Text, _>(&row.subject_id)
            .get_result::<DocumentRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            else {
                // An unresolved reference is not a matching Policy. The caller
                // must still establish a complete current authorization cut.
                continue;
            };
            let policy: arkret_models_collaboration::governance::operation_wire::PolicySetValue =
                serde_json::from_value(policy.value).map_err(|_| {
                    PersistenceError::Conflict(
                        "failed_precondition: applicable governance Policy is invalid".to_owned(),
                    )
                })?;
            policy.validate().map_err(|_| {
                PersistenceError::Conflict(
                    "failed_precondition: applicable governance Policy is invalid".to_owned(),
                )
            })?;
            let arkret_models_collaboration::governance::operation_wire::PolicySetValue::Governance(
                policy,
            ) = policy
            else {
                return Err(PersistenceError::Conflict(
                    "failed_precondition: approval configuration names a non-governance Policy"
                        .to_owned(),
                ));
            };
            if policy
                .realm_id
                .as_ref()
                .is_some_and(|configured_realm| configured_realm != realm)
                || policy.id.as_str() != row.subject_id
            {
                return Err(PersistenceError::Conflict(
                    "failed_precondition: governance Policy does not bind the current selector"
                        .to_owned(),
                ));
            }
            if policy.not_before.is_some_and(|start| at < start)
                || policy.expires_at.is_some_and(|end| at >= end)
            {
                continue;
            }
        } else if row.subject_kind != "realm_action" {
            return Err(PersistenceError::Conflict(
                "failed_precondition: approval selector namespace is invalid".to_owned(),
            ));
        }
        matched.push(config);
    }
    effective_quorum(action, matched.iter())
}

async fn scope_contains(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    scope: &arkret_wire::WireResourceSelector,
    target: &arkret_wire::WireResourceSelector,
    facts: &coland_storage::OperationFacts,
) -> PersistenceResult<bool> {
    use arkret_wire::ResourceSelectorKind;
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;
    if target.realm_id.as_ref().is_some_and(|id| id != realm) {
        return Ok(false);
    }
    if scope.kind == ResourceSelectorKind::Realm {
        return Ok(scope.realm_id.as_ref() == Some(realm));
    }
    if scope.kind == ResourceSelectorKind::Actor {
        return Ok(scope.actor_id == target.actor_id && target.kind == ResourceSelectorKind::Actor);
    }
    if coland_storage::resource_selector_covers(scope, target) {
        return Ok(true);
    }
    let Some(space) = &scope.space_id else {
        return Ok(false);
    };
    let mut starts = Vec::<String>::new();
    if let Some(id) = target.space_id.as_ref() {
        starts.push(id.to_string());
    }
    if let Some(id) = facts.space_id.as_ref() {
        starts.push(id.clone());
    }
    if let Some(id) = facts.to_container_id.as_ref() {
        starts.push(id.clone());
    }
    if let Some(strand) = target.strand_id.as_ref() {
        #[derive(diesel::QueryableByName)]
        struct Placement {
            #[diesel(sql_type=Text)]
            board: String,
            #[diesel(sql_type=Text)]
            list: String,
        }
        let placements=diesel::sql_query("SELECT board_space_id AS board,value->>'list_space_id' AS list FROM strand_position_current_results WHERE realm_id=$1 AND strand_id=$2 AND value<>'null'::jsonb")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(strand.as_str()).load::<Placement>(&mut *conn).await.map_err(PersistenceError::database)?;
        for placement in placements {
            starts.extend([placement.board, placement.list]);
        }
    }
    for start in starts {
        if start == space.as_str() {
            return Ok(true);
        }
        #[derive(diesel::QueryableByName)]
        struct Ancestor {
            #[diesel(sql_type=diesel::sql_types::Bool)]
            contains: bool,
            #[diesel(sql_type=diesel::sql_types::Bool)]
            cyclic: bool,
        }
        let ancestry=diesel::sql_query("WITH RECURSIVE ancestors(id,path,cycle) AS (SELECT $2::text,ARRAY[$2::text],false UNION ALL SELECT p.value->>'parent_space_id',a.path||(p.value->>'parent_space_id'),(p.value->>'parent_space_id')=ANY(a.path) FROM ancestors a JOIN space_parent_current_results p ON p.realm_id=$1 AND p.space_id=a.id WHERE p.value->>'parent_space_id' IS NOT NULL AND NOT a.cycle) SELECT COALESCE(bool_or(id=$3),false) AS contains,COALESCE(bool_or(cycle),false) AS cyclic FROM ancestors")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(&start).bind::<Text,_>(space.as_str())
            .get_result::<Ancestor>(&mut *conn).await.map_err(PersistenceError::database)?;
        if ancestry.cyclic {
            return Err(PersistenceError::Conflict(
                "failed_precondition: Policy scope ancestry is invalid".to_owned(),
            ));
        }
        if ancestry.contains {
            return Ok(true);
        }
    }
    Ok(false)
}
