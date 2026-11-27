//! Endpoint-specific home checks before requesting history and handing it off.
use arkret_models_collaboration::authority_commit::OwnedAgentStreamScanRequestBody;
use arkret_models_collaboration::governance::realm_join_intake::{
    OwnedAgentContentAction, OwnedAgentContentIntent,
};
use arkret_wire::{
    CommitStreamRef, RealmStateSnapshot, StreamScanRequestBody, StreamScanResponseBody,
};
use coland_storage::HostedAgentHistoryRead;
use diesel::sql_types::{BigInt, Jsonb};

use super::*;

fn denied() -> PersistenceError {
    PersistenceError::Conflict("capability_denied: hosted Agent history is unavailable".into())
}

struct HostedRead {
    held: Box<DeliveryGuard>,
    query: OwnedAgentStreamScanRequestBody,
    generation: u64,
    accepted_floor: Option<(u64, arkret_wire::RealmCommitId, u64)>,
    checked_page: bool,
}

pub(crate) async fn prepare(
    pool: &crate::PgPool,
    account: &AccountId,
    station: &DidCoreId,
    scan: &StreamScanRequestBody,
    session: &arkret_wire::SessionGrantId,
    input: &coland_storage::AccountContentDeliveryInput,
) -> PersistenceResult<(
    OwnedAgentStreamScanRequestBody,
    Box<dyn HostedAgentHistoryRead>,
)> {
    let missing = |source: &str| {
        PersistenceError::Conflict(format!("capability_denied: project history lacks {source}"))
    };
    let realm = &scan.realm_id;
    if !matches!(
        scan.stream_ref,
        CommitStreamRef::Realm { .. }
    ) || !input.future_materials.is_empty()
    {
        return Err(denied());
    }
    let endpoint = input
        .agent_endpoint
        .as_ref()
        .ok_or_else(|| missing("an authenticated Agent endpoint"))?;
    let owner = &input
        .qualified_agent_scope_evidence
        .as_ref()
        .ok_or_else(|| missing("the credential owner binding"))?
        .accepted_binding()
        .controller_account;
    let expiry = input
        .credential_expires_at
        .ok_or_else(|| missing("the credential deadline"))?;
    if &account.station_id != station || &owner.station_id != station || account == owner {
        return Err(denied());
    }
    let mut held = DeliveryGuard::begin(pool).await?;
    crate::sync_cursor::retention::lock(held.connection(), false)
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
    lock_scope_evidence_owner(held.connection(), input).await?;
    for subject in [owner, account] {
        crate::content_recovery_fence::require_unfenced(
            held.connection(),
            &ActorId::account(subject.clone()),
        )
        .await?;
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(held.connection(), realm).await?;
    #[derive(QueryableByName)]
    struct Tenure {
        #[diesel(sql_type=BigInt)]
        generation: i64,
    }
    let tenure = sql_query("SELECT generation FROM realm_authorities a WHERE realm_id=$1 AND service_id<>$2
        AND NOT EXISTS(SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk
            WHERE c.realm_id=a.realm_id AND c.governance_generation=a.generation AND e.kind='ak.realm.governance_station.change')")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(station.as_str()).get_result::<Tenure>(held.connection())
        .await.optional().map_err(PersistenceError::database)?.ok_or_else(|| missing("the current foreign governing tenure"))?;
    let pair = crate::agent_interaction_current_states::governed_join_pair(
        held.connection(),
        realm,
        account,
        chrono::Utc::now(),
        true,
        None,
    )
    .await?
    .filter(|p| &p.controller == owner)
    .ok_or_else(|| missing("the current Agent and controller joins"))?;
    crate::agent_interaction_current_states::owned_provenance_in_connection(
        held.connection(),
        account,
        owner,
        chrono::Utc::now(),
        true,
    )
    .await?
    .ok_or_else(|| missing("active ownership provenance"))?;
    validate_private_delivery_credentials(
        &mut held,
        account,
        station,
        input,
        arkret_wire::WireResourceSelector::realm(realm.clone()),
        Default::default(),
        CapabilityActionId::EventRead,
        expiry,
    )
    .await?;
    let accountability = sql_query("SELECT value FROM identity_accountability_current_states WHERE subject_id=$1 AND issuer_id=$2 ORDER BY realm_id,scope_set_digest FOR SHARE")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(owner.principal_id.as_str())
        .load::<ValueRow>(held.connection()).await.map_err(PersistenceError::database)?;
    let values = accountability
        .into_iter()
        .map(|r| {
            serde_json::from_value::<
                arkret_models_collaboration::governance::accountability::AccountabilityProjection,
            >(r.value)
            .map_err(PersistenceError::database)
        })
        .collect::<PersistenceResult<Vec<_>>>()?
        .into_iter()
        .filter(|v| {
            v.accountability_scope
                .scopes()
                .contains(&arkret_wire::AccountabilityScopeKind::AgentOperator)
        })
        .collect();
    held.clock
        .as_mut()
        .ok_or_else(denied)?
        .accountability
        .push(values);
    if !held.permits_handoff() {
        return Err(missing(
            "an effective delivery credential and accountability scope",
        ));
    }
    let request_digest = arkret_wire::Hash::new(
        arkret_canonical::canonical_sha256(scan).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    let query = OwnedAgentStreamScanRequestBody {
        request_id: arkret_wire::RequestId::new_v7_at(
            chrono::Utc::now().timestamp_millis().max(0) as u64
        ),
        member_account_id: account.clone(),
        membership_commit_id: pair.agent_commit.commit_id.clone(),
        content_intent: OwnedAgentContentIntent {
            controller_account_id: owner.clone(),
            controller_membership_commit_id: pair.controller_commit.commit_id.clone(),
            agent_key_authorization_ref: endpoint.authorization_ref.event_id.clone(),
            action: OwnedAgentContentAction::EventRead,
            effective_scope: scan.stream_ref.scope_ref(),
            strand_id: None,
            request_digest,
        },
        session_grant_id: session.clone(),
        scan: scan.clone(),
    };
    query
        .validate_binding()
        .map_err(PersistenceError::database)?;
    // G applies the project grant and management policies at the signed history read.
    // H retains the native credential, ownership, membership generation and resource ceilings.
    Ok((
        query.clone(),
        Box::new(HostedRead {
            held,
            query,
            generation: u64::try_from(tenure.generation).map_err(PersistenceError::database)?,
            accepted_floor: None,
            checked_page: false,
        }),
    ))
}

#[async_trait::async_trait]
impl HostedAgentHistoryRead for HostedRead {
    async fn qualify_archived_history(
        &mut self,
        snapshot: &RealmStateSnapshot,
    ) -> PersistenceResult<()> {
        let account = &self.query.member_account_id;
        let conn = self.held.connection();
        let present = sql_query("SELECT EXISTS(SELECT 1 FROM realm_state_snapshots s JOIN realm_state_snapshot_issuances i USING(snapshot_id)
            WHERE s.snapshot_id=$1 AND s.realm_id=$2 AND i.account_id=$3 AND s.snapshot_json=$4) AS present")
            .bind::<Text,_>(snapshot.snapshot_id.as_str()).bind::<Text,_>(snapshot.realm_id.as_str())
            .bind::<Text,_>(account.canonical_key().map_err(PersistenceError::database)?)
            .bind::<Jsonb,_>(serde_json::json!(snapshot)).get_result::<crate::query_rows::ExistsRow>(conn).await.map_err(PersistenceError::database)?;
        if !present.present {
            return Err(denied());
        }
        let clock = self.held.clock.as_ref().ok_or_else(denied)?;
        let restricted = !clock.key_scope.constraints.is_empty()
            || !clock.provision_scope.constraints.is_empty()
            || clock.session_scope.as_ref().is_some_and(|(_, session)| {
                !session.strand_ids.is_empty()
                    || !session.resources.strand_ids.is_empty()
                    || !session.constraints.allowed_tracks.is_empty()
                    || !session.constraints.allowed_data_labels.is_empty()
                    || session.constraints.allowed_strand_ids.is_some()
            });
        if restricted {
            let realm = &snapshot.realm_id;
            let actor = ActorId::account(account.clone());
            let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read_accepted(
                self.held.connection(),
                realm,
                &actor,
            )
            .await?;
            for row in &snapshot.current_state_entries {
                let arkret_wire::CurrentState::Value {
                    source_stream_ref,
                    revision,
                    ..
                } = row;
                let event = super::current_source_in_connection(
                    self.held.connection(),
                    realm,
                    source_stream_ref,
                    revision,
                )
                .await?;
                let (target, facts) =
                    cut.content_scope_facts(&event, CapabilityActionId::EventRead)?;
                self.held
                    .clock
                    .as_mut()
                    .ok_or_else(denied)?
                    .scope_operations
                    .push((actor.clone(), target, facts, CapabilityActionId::EventRead));
            }
        }
        if !self.held.permits_handoff() {
            return Err(denied());
        }
        Ok(())
    }

    async fn discard(self: Box<Self>) -> PersistenceResult<()> {
        self.held.finish().await
    }

    async fn permits_request(&mut self) -> bool {
        self.held.probe().await.is_ok() && self.held.permits_handoff()
    }
    async fn accept_history(&mut self, snapshot: &RealmStateSnapshot) -> PersistenceResult<()> {
        let scan = &self.query.scan;
        let account = &self.query.member_account_id;
        let basis = snapshot.history_basis.as_ref().ok_or_else(denied)?;
        if self.accepted_floor.is_some()
            || basis.account_id != *account
            || basis.stream_ref != scan.stream_ref
            || snapshot.governance_generation != self.generation
            || snapshot.realm_id != scan.realm_id
            || snapshot
                .active_realm_member_revision(&ActorId::account(account.clone()))
                .is_none_or(|r| r.commit_id != self.query.membership_commit_id)
        {
            return Err(denied());
        }
        snapshot
            .validate_purpose()
            .map_err(PersistenceError::database)?;
        let head = snapshot
            .visible_stream_heads
            .iter()
            .find(|h| h.stream_ref == scan.stream_ref)
            .ok_or_else(denied)?;
        let floor = snapshot
            .retention_and_history_floor
            .stream_floors
            .iter()
            .find(|f| f.stream_ref == scan.stream_ref)
            .ok_or_else(denied)?
            .oldest_position;
        let conn = self.held.connection();
        // G attests the complete disclosure at this cut. H verifies only the
        // covered streams, its own membership, and the originals it retained.
        for covered in &snapshot.visible_stream_heads {
            let exact = sql_query("SELECT EXISTS(SELECT 1 FROM (
                SELECT commit_id,stream_position FROM realm_commits WHERE realm_id=$1 AND stream_ref=$2
                ORDER BY stream_position DESC LIMIT 1) h WHERE h.commit_id=$3 AND h.stream_position=$4) AS present")
                .bind::<Text,_>(scan.realm_id.as_str()).bind::<Jsonb,_>(serde_json::json!(covered.stream_ref))
                .bind::<Text,_>(covered.commit_id.as_str()).bind::<BigInt,_>(i64::try_from(covered.stream_position).map_err(PersistenceError::database)?)
                .get_result::<crate::query_rows::ExistsRow>(&mut *conn).await.map_err(PersistenceError::database)?;
            if !exact.present {
                return Err(PersistenceError::Conflict(
                    "project history head differs from the covered local stream".into(),
                ));
            }
        }
        let mut parent_floor = 0;
        for subject in [account, &self.query.content_intent.controller_account_id] {
            let covered = crate::account_stream_scan::hosted_project_member_floor(
                conn,
                &scan.realm_id,
                &ActorId::account(subject.clone()),
            )
            .await?
            .ok_or_else(|| {
                PersistenceError::Conflict("project member history floor is unavailable".into())
            })?;
            parent_floor = parent_floor.max(covered.oldest_position);
        }
        if !snapshot
            .retention_and_history_floor
            .stream_floors
            .iter()
            .any(|f| {
                f.stream_ref
                    == (CommitStreamRef::Realm {
                        realm_id: scan.realm_id.clone(),
                    })
                    && f.oldest_position == parent_floor
            })
        {
            return Err(denied());
        }
        let prior = crate::issued_realm_snapshots::disclosed_basis_from_snapshot(
            conn,
            account,
            snapshot,
            &scan.stream_ref,
            head,
            floor,
        )
        .await?;
        if prior.is_none() {
            return Err(denied());
        }
        #[derive(QueryableByName)]
        struct Floor {
            #[diesel(sql_type=Text)]
            id: String,
        }
        let chain = sql_query("WITH chain AS (
            SELECT commit_id,stream_position,previous_commit_ref,lag(commit_id) OVER (ORDER BY stream_position) AS prior
            FROM realm_commits WHERE realm_id=$1 AND stream_ref=$2 AND stream_position BETWEEN $3 AND $4
        ) SELECT min(commit_id) FILTER (WHERE stream_position=$3) AS id FROM chain
          HAVING count(*)=$4-$3+1 AND bool_and(stream_position=$3 OR previous_commit_ref IS NOT DISTINCT FROM prior)
            AND count(*) FILTER (WHERE stream_position=$4 AND commit_id=$5)=1")
            .bind::<Text,_>(scan.realm_id.as_str()).bind::<Jsonb,_>(serde_json::json!(scan.stream_ref))
            .bind::<BigInt,_>(i64::try_from(floor).map_err(PersistenceError::database)?)
            .bind::<BigInt,_>(i64::try_from(head.stream_position).map_err(PersistenceError::database)?)
            .bind::<Text,_>(head.commit_id.as_str()).get_result::<Floor>(&mut *conn).await.optional()
            .map_err(PersistenceError::database)?.ok_or_else(denied)?;
        let held_rows = crate::replica_authorization::snapshot_current_evidence(
            conn,
            &scan.realm_id,
            &snapshot.visible_stream_heads,
        )
        .await?;
        for signed in &snapshot.current_state_entries {
            let arkret_wire::CurrentState::Value {
                selector, revision, ..
            } = signed;
            if held_rows.iter().any(|known| {
                let arkret_wire::CurrentState::Value {
                    selector: old,
                    revision: observed,
                    ..
                } = known;
                old == selector
                    && observed.stream_position >= revision.stream_position
                    && known != signed
            }) {
                return Err(PersistenceError::Conflict(
                    "project history conflicts with an observed current revision".into(),
                ));
            }
        }
        crate::replica_authorization::guard_current_rows(
            conn,
            &scan.realm_id,
            &snapshot.current_state_entries,
        )
        .await?;
        coland_storage::enforce_inline_realm_state_snapshot_capacity(snapshot)?;
        let material = coland_storage::RealmStateSnapshotMaterial {
            realm_id: snapshot.realm_id.clone(),
            governance_generation: snapshot.governance_generation,
            purpose: snapshot.purpose,
            history_basis: snapshot.history_basis.clone(),
            visible_stream_heads: snapshot.visible_stream_heads.clone(),
            retention_and_history_floor: snapshot.retention_and_history_floor.clone(),
            current_state_entries: snapshot.current_state_entries.clone(),
        };
        crate::issued_realm_snapshots::issue_head_in_connection(
            conn,
            account,
            &material,
            snapshot.clone(),
        )
        .await?;
        self.accepted_floor = Some((
            floor,
            arkret_wire::RealmCommitId::new(chain.id).map_err(PersistenceError::database)?,
            head.stream_position,
        ));
        Ok(())
    }

    async fn accept_page(&mut self, page: &StreamScanResponseBody) -> PersistenceResult<()> {
        let (floor, id, head) = self.accepted_floor.as_ref().ok_or_else(denied)?;
        page.validate_for_request(&self.query.scan)
            .map_err(PersistenceError::database)?;
        if self.checked_page
            || page
                .readable_floor
                .as_ref()
                .is_none_or(|f| f.oldest_position != *floor || f.floor_commit_id != *id)
            || page
                .committed_events
                .iter()
                .any(|row| row.commit().stream_position > *head)
        {
            return Err(denied());
        }
        let actor = ActorId::account(self.query.member_account_id.clone());
        let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read_accepted(
            self.held.connection(),
            &self.query.scan.realm_id,
            &actor,
        )
        .await?;
        for item in &page.committed_events {
            let original = sql_query(
                "SELECT commit_json AS value FROM realm_commits WHERE realm_id=$1 AND commit_id=$2",
            )
            .bind::<Text, _>(self.query.scan.realm_id.as_str())
            .bind::<Text, _>(item.commit().commit_id.as_str())
            .get_result::<ValueRow>(self.held.connection())
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(denied)?;
            if original.value != serde_json::json!(item.commit()) {
                return Err(denied());
            }
            if let Some(event) = item.reducer_input() {
                if event.scope_ref != self.query.content_intent.effective_scope {
                    return Err(denied());
                }
                event
                    .verify_event_id_matches_content_with_digest_suite(
                        event.realm_id.digest_suite_code().digest_suite(),
                    )
                    .map_err(PersistenceError::database)?;
                let (target, facts) =
                    cut.content_scope_facts(event, CapabilityActionId::EventRead)?;
                self.held
                    .clock
                    .as_mut()
                    .ok_or_else(denied)?
                    .scope_operations
                    .push((actor.clone(), target, facts, CapabilityActionId::EventRead));
            }
        }
        if !self.held.permits_handoff() {
            return Err(denied());
        }
        self.checked_page = true;
        Ok(())
    }
}

#[async_trait::async_trait]
impl AccountContentDeliveryGuard for HostedRead {
    async fn prepare_handoff(&mut self) -> bool {
        self.checked_page && self.permits_request().await
    }
    async fn finish(self: Box<Self>) -> PersistenceResult<()> {
        if self.checked_page {
            self.held.commit().await
        } else {
            self.held.finish().await
        }
    }
}
