//! Private Service-authored creation, without member replication or Account projections.
use arkret_wire::{AuthorityCommitStatus, AuthoritySubmitOutcome, Event, RealmCommit};
use coland_storage::{
    AppletEventProducerGuard, AuthorityCommitTransaction, EventApprovalCommit, PersistenceError,
};
use diesel_async::AsyncPgConnection;
use serde_json::json;

use crate::PgTransactionError;

fn invalid(detail: impl std::fmt::Display) -> PgTransactionError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}")).into()
}

/// The caller has independently authenticated the exact Service on this request.
/// Historical replay does not require today's business permission to remain active.
pub(crate) async fn replay(
    conn: &mut AsyncPgConnection,
    event: &Event,
    digest: &arkret_wire::Hash,
    governor: &arkret_wire::DidCoreId,
) -> Result<Option<RealmCommit>, PgTransactionError> {
    event.validate_for_submit_structural().map_err(invalid)?;
    let candidate = crate::realm_actor_control::creation(event)?
        .ok_or_else(|| invalid("Service creation replay requires its original candidate"))?;
    crate::realm_actor_control::require_current_governor(conn, &event.realm_id, governor).await?;
    let Some(original) =
        crate::committed_disclosure::accepted_full_event_in_connection(conn, &event.event_id)
            .await?
    else {
        return Ok(None);
    };
    if original.event != *event {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: creation original differs".to_owned(),
        )
        .into());
    }
    if crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
        conn,
        event,
        &original.commit,
    )
    .await?
    .is_none()
    {
        return Err(invalid("creation signing original is unavailable"));
    }
    let outcome = AuthoritySubmitOutcome::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: original.commit.clone(),
    };
    crate::realm_actor_material::retain_outcome(
        conn,
        event,
        &candidate.actor_id,
        digest,
        &outcome,
        original.commit.committed_at,
    )
    .await?;
    Ok(Some(original.commit))
}

pub(crate) async fn admit(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    producer: &AppletEventProducerGuard,
    prepared: Option<&EventApprovalCommit>,
    digest: &arkret_wire::Hash,
) -> Result<AuthoritySubmitOutcome, PgTransactionError> {
    let event = &transaction.event;
    let commit = &transaction.commit;
    let candidate = crate::realm_actor_control::creation(event)?
        .ok_or_else(|| invalid("creation unit requires its exact Event kind"))?;
    crate::agent_management_review::lock_candidate_current_realms_in_connection(
        conn,
        event,
        prepared,
        None,
        &[],
    )
    .await?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    if let Some(commit) = replay(
        conn,
        event,
        digest,
        &transaction.expected_authority.service_id,
    )
    .await?
    {
        return Ok(AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Duplicate,
            commit,
        });
    }
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &event.realm_id,
        &event.actor_id,
    )
    .await?;
    cut.require_open_lifecycle(event)?;
    crate::applet_configuration::require_candidate(conn, event, prepared).await?;
    crate::realm_actor_control::admit_creation(conn, event, commit).await?;
    let (fact, approvals) = crate::managed_message_actor::require_applet_producer_in_connection(
        conn, event, producer, commit, prepared,
    )
    .await?;
    crate::agent_producer_signer_keys::validate_producer_fact_binding(event, commit, Some(&fact))?;
    let review = crate::agent_management_review::prepare_admission_in_connection(
        conn,
        event,
        prepared,
        commit.committed_at,
        None,
    )
    .await?;
    crate::approval_admission::validate_candidate(event, commit, prepared)?;
    crate::authority_commit::queue_event_in_connection(conn, event, commit.committed_at).await?;
    let result = crate::authority_commit::commit_realm_actor_creation_in_connection(
        conn,
        transaction,
        prepared,
    )
    .await?;
    if !matches!(
        result,
        coland_storage::AuthorityCommitWriteOutcome::Committed
    ) {
        return Err(invalid("creation control head or governance changed"));
    }
    crate::agent_producer_signer_keys::retain_prepared_applet_in_connection(
        conn, event, commit, &fact,
    )
    .await?;
    if let Some(review) = review {
        crate::agent_management_review::consume_in_connection(
            conn,
            event,
            commit,
            review.methods(),
        )
        .await?;
    }
    crate::approval_admission::consume_and_audit(
        conn,
        event,
        commit,
        &approvals,
        &json!({"realm_actor_creation":candidate.actor_id}),
    )
    .await?;
    let outcome = AuthoritySubmitOutcome::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: commit.clone(),
    };
    crate::realm_actor_material::retain_outcome(
        conn,
        event,
        &candidate.actor_id,
        digest,
        &outcome,
        commit.committed_at,
    )
    .await?;
    crate::applet_configuration::accepted(conn, event).await?;
    crate::applet_completion::retain(
        conn,
        event,
        commit,
        digest,
        &transaction.expected_authority.service_id,
    )
    .await?;
    Ok(outcome)
}

/// Reconstruct accepted originals, optionally restricted to their current managing Service.
pub(crate) async fn inventory(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    applet: &arkret_wire::AppletId,
    service: Option<&arkret_wire::DidCoreId>,
) -> Result<Vec<arkret_wire::CommittedEventFullView>, PgTransactionError> {
    use diesel::sql_types::{Jsonb, Text};
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type=Jsonb)]
        value: serde_json::Value,
    }
    // Inventory shares a stable authority cut with other reads. Governance and
    // control writers still take the exclusive lock before changing this cut.
    sql_query("SELECT to_jsonb(a) AS value FROM realm_authorities a WHERE realm_id=$1 FOR SHARE")
        .bind::<Text, _>(realm.as_str())
        .get_result::<Row>(&mut *conn)
        .await?;
    let rows = sql_query("SELECT jsonb_build_object('event',e.envelope,'commit',c.commit_json) AS value FROM realm_actor_creations r JOIN realm_commits c ON c.commit_id=r.commit_id AND c.realm_id=r.realm_id JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE r.realm_id=$1 AND r.applet_id=$2 ORDER BY c.stream_position")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(applet.as_str()).load::<Row>(&mut *conn).await?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let full: arkret_wire::CommittedEventFullView =
            serde_json::from_value(row.value).map_err(invalid)?;
        full.validate_shape().map_err(invalid)?;
        let candidate = crate::realm_actor_control::creation(&full.event)?
            .ok_or_else(|| invalid("inventory writer is not creation"))?;
        if &full.event.realm_id != realm
            || &candidate.applet_id != applet
            || crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
                conn,
                &full.event,
                &full.commit,
            )
            .await?
            .is_none()
        {
            return Err(invalid(
                "creation inventory is not backed by its original authority",
            ));
        }
        if let Some(service) = service {
            let (manager, _) = crate::realm_actor_control::current_source(
                conn,
                &candidate.actor_id,
                serde_json::json!({"kind":"realm_actor_manager", "actor_id":candidate.actor_id}),
            )
            .await?;
            if manager
                .get("service_id")
                .and_then(serde_json::Value::as_str)
                != Some(service.as_str())
            {
                continue;
            }
        }
        result.push(full);
    }
    Ok(result)
}
