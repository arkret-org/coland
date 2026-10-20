//! Caller-bound Realm projections and response-lifetime authorization cuts.
use arkret_models_collaboration::governance::realm_governance::RealmLifecycleView;
use arkret_wire::{ActorId, CommittedEventFullView, CommittedEventView, DidCoreId, RealmId};
use coland_storage::{
    AccountContentDeliveryGuard, AccountContentDeliveryInput, PersistenceError, PersistenceResult,
};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("revision_unavailable: {detail}"))
}

#[derive(diesel::QueryableByName)]
struct LifecycleRow {
    #[diesel(sql_type = Text)]
    result_family: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    commit_json: Option<serde_json::Value>,
}

pub(crate) async fn lifecycle_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    actor: &ActorId,
) -> PersistenceResult<Option<RealmLifecycleView>> {
    if !crate::authority_commit::accepted_realm_reader_in_connection(conn, realm, actor).await? {
        return Ok(None);
    }
    crate::realm_authorization_cut::RealmAuthorizationCut::read_accepted(conn, realm, actor)
        .await?
        .require_realm_projection_read(chrono::Utc::now())?;
    let roster = crate::authority_commit::accepted_realm_roster_in_connection(conn, realm)
        .await?
        .ok_or_else(|| unavailable("Realm roster has no accepted root"))?;
    let mut view = RealmLifecycleView {
        realm_id: realm.clone(),
        owner_id: roster.controller_actor_id.signing_principal_id().clone(),
        member_ids: roster.joined_members,
        deleted: false,
        archived: false,
        frozen: false,
        terminal_state: None,
        successor_realm_id: None,
    };
    let rows = sql_query("SELECT r.result_family,r.current_commit_id,r.current_stream_position,r.value,c.commit_json FROM realm_bootstrap_current_results r LEFT JOIN realm_commits c ON c.realm_id=r.realm_id AND c.commit_id=r.current_commit_id AND c.stream_position=r.current_stream_position AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',r.realm_id) WHERE r.realm_id=$1 AND r.result_family IN ('realm_archive','realm_freeze','realm_tombstone','realm_destroy')")
        .bind::<Text,_>(realm.as_str()).load::<LifecycleRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in rows {
        let Some(commit_json) = row.commit_json else {
            // A member snapshot may prove a current value below the retained
            // history floor. Require its exact durable anchor, never a cache.
            let selector = match row.result_family.as_str() {
                "realm_archive" => arkret_wire::CurrentSelector::RealmArchive,
                "realm_freeze" => arkret_wire::CurrentSelector::RealmFreeze,
                "realm_tombstone" => arkret_wire::CurrentSelector::RealmTombstone,
                _ => return Err(unavailable("Realm lifecycle anchor family is unregistered")),
            };
            let stream = arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            };
            let (_, entries) = Box::pin(crate::replica_authorization::exact_current_evidence(
                conn,
                &stream,
                &[selector],
            ))
            .await?
            .ok_or_else(|| unavailable("Realm lifecycle anchor is unavailable"))?;
            let proved = entries.iter().any(|entry| {
                let arkret_wire::TypedCurrentRow::Value {
                    selector,
                    revision,
                    value,
                    ..
                } = entry;
                let family = match selector {
                    arkret_wire::CurrentSelector::RealmArchive => "realm_archive",
                    arkret_wire::CurrentSelector::RealmFreeze => "realm_freeze",
                    arkret_wire::CurrentSelector::RealmTombstone => "realm_tombstone",
                    _ => "",
                };
                family == row.result_family
                    && revision.commit_id.as_str() == row.current_commit_id
                    && i64::try_from(revision.stream_position).ok()
                        == Some(row.current_stream_position)
                    && value == &row.value
            });
            if !proved {
                return Err(unavailable("Realm lifecycle has no exact accepted anchor"));
            }
            match row.result_family.as_str() {
                "realm_archive" | "realm_freeze" => {
                    let key = if row.result_family == "realm_archive" {
                        "archived"
                    } else {
                        "frozen"
                    };
                    let value = row
                        .value
                        .get(key)
                        .and_then(serde_json::Value::as_bool)
                        .ok_or_else(|| unavailable("Realm lifecycle anchor value is invalid"))?;
                    if row.value != serde_json::json!({key:value}) {
                        return Err(unavailable("Realm lifecycle anchor shape differs"));
                    }
                    if key == "archived" {
                        view.archived = value;
                    } else {
                        view.frozen = value;
                    }
                }
                "realm_tombstone" => {
                    let payload: arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload = serde_json::from_value(row.value).map_err(unavailable)?;
                    view.deleted = true;
                    view.terminal_state = Some("tombstoned".into());
                    view.successor_realm_id = Some(payload.successor_realm_id);
                }
                _ => return Err(unavailable("Realm lifecycle anchor family is unregistered")),
            }
            continue;
        };
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(commit_json).map_err(unavailable)?;
        let full =
            crate::committed_disclosure::accepted_full_event_in_connection(conn, &commit.event_ref)
                .await?
                .ok_or_else(|| unavailable("Realm lifecycle has no accepted original"))?;
        if full.commit != commit
            || commit.realm_id != *realm
            || commit.commit_id.as_str() != row.current_commit_id
            || i64::try_from(commit.stream_position).map_err(unavailable)?
                != row.current_stream_position
        {
            return Err(unavailable("Realm lifecycle source differs"));
        }
        full.event
            .verify_event_id_matches_content_with_digest_suite(
                full.event.event_id.digest_suite_code().digest_suite(),
            )
            .map_err(unavailable)?;
        commit
            .verify_commit_id_matches_content()
            .map_err(unavailable)?;
        use arkret_wire::EventKind;
        let expected = match (row.result_family.as_str(), full.event.kind) {
            ("realm_archive", EventKind::RealmArchive) => {
                view.archived = true;
                serde_json::json!({"archived":true})
            }
            ("realm_archive", EventKind::RealmRestore) => serde_json::json!({"archived":false}),
            ("realm_freeze", EventKind::RealmFreeze) => {
                view.frozen = true;
                serde_json::json!({"frozen":true})
            }
            ("realm_freeze", EventKind::RealmUnfreeze) => serde_json::json!({"frozen":false}),
            ("realm_tombstone", EventKind::RealmTombstone) => {
                let payload: arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload = serde_json::from_value(serde_json::json!(full.event.payload)).map_err(unavailable)?;
                view.deleted = true;
                view.terminal_state = Some("tombstoned".into());
                view.successor_realm_id = Some(payload.successor_realm_id);
                serde_json::json!(full.event.payload)
            }
            _ => return Err(unavailable("Realm lifecycle has an unregistered source")),
        };
        if row.value != expected {
            return Err(unavailable(
                "Realm lifecycle value differs from its original",
            ));
        }
    }
    Ok(Some(view))
}

/// Rebuild whole outputs on the held cut, including empty lists and withheld slots.
pub(crate) async fn revalidate_in_connection(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    station: &DidCoreId,
    input: &AccountContentDeliveryInput,
) -> PersistenceResult<Vec<CommittedEventFullView>> {
    let mut sources = Vec::new();
    for view in &input.realm_lifecycle_reads {
        let fresh = lifecycle_in_connection(conn, &view.realm_id, actor)
            .await?
            .ok_or_else(|| unavailable("Realm lifecycle reader changed"))?;
        if view != &fresh {
            return Err(unavailable("Realm lifecycle output changed"));
        }
    }
    for (list, allow) in &input.realm_link_reads {
        let (fresh, originals) = crate::object_projection_reads::realm_link_list_in_connection(
            conn,
            &list.realm_id,
            actor,
            station,
            list.direction,
            allow.as_deref(),
        )
        .await?
        .ok_or_else(|| unavailable("Realm link reader changed"))?;
        if arkret_canonical::canonical_json_bytes(list).map_err(unavailable)?
            != arkret_canonical::canonical_json_bytes(&fresh).map_err(unavailable)?
        {
            return Err(unavailable("Realm link output changed"));
        }
        sources.extend(originals);
    }
    for export in &input.realm_exports {
        let (fresh, originals) =
            Box::pin(crate::account_content_delivery::realm_export_in_connection(
                conn,
                &export.realm_id,
                actor,
                station,
                export.generated_at,
            ))
            .await?
            .ok_or_else(|| unavailable("Realm export reader changed"))?;
        if export != &fresh {
            return Err(unavailable("Realm export output changed"));
        }
        sources.extend(originals.into_iter().filter_map(|row| match row {
            CommittedEventView::Full(full) => Some(full),
            _ => None,
        }));
    }
    Ok(sources)
}

type Connection = diesel_async::pooled_connection::deadpool::Object<AsyncPgConnection>;
struct ReadGuard {
    connection: Option<Connection>,
    runtime: tokio::runtime::Handle,
    at: chrono::DateTime<chrono::Utc>,
    expires: chrono::DateTime<chrono::Utc>,
    proofs: Vec<(
        crate::realm_authorization_cut::RealmAuthorizationCut,
        Vec<arkret_wire::Event>,
    )>,
}
#[async_trait::async_trait]
impl AccountContentDeliveryGuard for ReadGuard {
    fn permits_handoff(&self) -> bool {
        let now = chrono::Utc::now();
        now >= self.at
            && now < self.expires
            && self.proofs.iter().all(|(cut, events)| {
                cut.time_sources_unchanged(self.at, now)
                    && cut.require_realm_projection_read(now).is_ok()
                    && events.iter().all(|event| {
                        cut.require_membership_read_constraints(event, now, None)
                            .is_ok()
                    })
            })
    }
    async fn finish(mut self: Box<Self>) -> PersistenceResult<()> {
        if let Some(conn) = self.connection.as_mut() {
            sql_query("ROLLBACK")
                .execute(&mut **conn)
                .await
                .map_err(PersistenceError::database)?;
        }
        drop(self.connection.take());
        Ok(())
    }
}
impl Drop for ReadGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            let conn = Connection::take(conn);
            let cancel = conn.cancel_token();
            drop(conn);
            self.runtime.spawn(async move {
                let _ = cancel.cancel_query(tokio_postgres::NoTls).await;
            });
        }
    }
}

pub(crate) async fn ordinary_delivery_guard(
    pool: &crate::PgPool,
    account: &arkret_wire::AccountId,
    station: &DidCoreId,
    input: &AccountContentDeliveryInput,
) -> PersistenceResult<Option<Box<dyn AccountContentDeliveryGuard>>> {
    if input.realm_lifecycle_reads.is_empty()
        && input.realm_link_reads.is_empty()
        && input.realm_exports.is_empty()
    {
        return Ok(None);
    }
    if input.agent_endpoint.is_some()
        || input.agent_session_scope.is_some()
        || input.applet_endpoint.is_some()
    {
        return Err(unavailable("Realm reader requires its current managed cut"));
    }
    let mut guard = Box::new(ReadGuard {
        connection: Some(crate::pg_conn(pool).await?),
        runtime: tokio::runtime::Handle::current(),
        at: chrono::Utc::now(),
        expires: input
            .credential_expires_at
            .ok_or_else(|| unavailable("Realm reader credential expiry missing"))?,
        proofs: Vec::new(),
    });
    let conn = guard.connection.as_mut().unwrap();
    sql_query("BEGIN")
        .execute(&mut **conn)
        .await
        .map_err(PersistenceError::database)?;
    let pcr = crate::morph_projection_reads::human_realm_in_connection(conn, account).await?;
    let mut realms = input
        .realms
        .iter()
        .cloned()
        .chain(std::iter::once(pcr.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    for view in &input.realm_lifecycle_reads {
        realms.insert(view.realm_id.clone());
    }
    for export in &input.realm_exports {
        realms.insert(export.realm_id.clone());
    }
    for (list, _) in &input.realm_link_reads {
        realms.insert(list.realm_id.clone());
        realms.extend(list.links.iter().map(|link| link.realm_id.clone()));
    }
    for realm in &realms {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
    }
    crate::morph_projection_reads::require_accepted_human_identity(
        conn,
        account,
        &pcr,
        station,
        input
            .account_status_observations
            .iter()
            .find(|observation| &observation.record().account_id == account),
    )
    .await?;
    let actor = ActorId::account(account.clone());
    let sources = Box::pin(revalidate_in_connection(conn, &actor, station, input)).await?;
    // The caller's PCR was locked for identity; it is not a requested business read.
    let business = input
        .realm_lifecycle_reads
        .iter()
        .map(|view| view.realm_id.clone())
        .chain(
            input
                .realm_exports
                .iter()
                .map(|export| export.realm_id.clone()),
        )
        .chain(input.realm_link_reads.iter().flat_map(|(list, _)| {
            std::iter::once(list.realm_id.clone())
                .chain(list.links.iter().map(|link| link.realm_id.clone()))
        }))
        .collect::<std::collections::BTreeSet<_>>();
    let at = chrono::Utc::now();
    for realm in business {
        let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read_accepted(
            conn, &realm, &actor,
        )
        .await?;
        cut.require_realm_projection_read(at)?;
        let events = sources
            .iter()
            .filter(|full| full.event.realm_id == realm)
            .map(|full| full.event.clone())
            .collect::<Vec<_>>();
        for event in &events {
            cut.require_membership_read_constraints(event, at, None)?;
        }
        guard.proofs.push((cut, events));
    }
    guard.at = at;
    if !guard.permits_handoff() {
        return Err(unavailable("Realm reader expired before handoff"));
    }
    Ok(Some(guard))
}
