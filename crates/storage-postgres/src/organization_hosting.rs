//! Hosting acceptance is local operator authority, never another PCR governor.
//!
//! The existing forward row is the one intent/result owner. The accepted
//! projection retains only the original public Genesis source; G alone keeps
//! its complete private admission source and approval consumption.

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::authority_commit::{
    HistoricalProducerSignerFact, OrganizationGenesisSignerFact,
    PeerAuthorityForwardEventRequestBody, PeerAuthoritySubmitRequestBody,
    SelfAuthoritySubmitRequestBody,
};
use arkret_models_identity::{
    AuthenticatedServiceResolution, HistoricalSignerKeyQuerySender, PrincipalResolutionProjection,
    SignerKeyQuerySelector, SignerKeyResolution,
};
use arkret_wire::{
    AccountId, ActorId, AuthorityCommitStatus, AuthoritySubmitResponseBody, CommittedEventFullView,
    DidCoreId, Event, EventAdmissionSubmission, RealmAuthorityBundle, RealmCommit, RealmId,
};
use coland_storage::{CurrentRealmAuthority, PersistenceError, PersistenceResult};
use diesel::sql_types::{Bool, Jsonb, Nullable, Text, Timestamptz};
use diesel_async::AsyncConnection as _;
use horme::{OptionalExtension as _, RunQueryDsl as _};
use serde_json::Value;

use crate::{AsyncPgConnection, PgAuthorityCommitStore, PgTransactionError, pg_conn, sql_query};

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "failed_precondition: Organization hosting {detail}"
    ))
}

fn conflict(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("duplicate_conflict: Organization hosting {detail}"))
}

fn holder<'a>(
    original: &'a EventAdmissionSubmission,
    hosting: &DidCoreId,
) -> PersistenceResult<&'a AccountId> {
    original.validate().map_err(invalid)?;
    let event = &original.event;
    let account = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("full Account is absent"))?;
    let device = event.account_device_producer().map_err(invalid)?;
    if arkret_wire::GenesisGovernance::from_genesis(event).map_err(invalid)?
        != arkret_wire::GenesisGovernance::Organization
        || &account.station_id != hosting
        || !(matches!(event.actual_signer(), ActorId::Service { .. })
            || device
                .as_ref()
                .is_some_and(|producer| &producer.account_id.station_id == hosting))
        || event
            .as_realm_create()
            .map_err(invalid)?
            .object
            .governance_station_id
            == *hosting
    {
        return Err(invalid(
            "this local owner requires its exact Account, independent G and real Service or H-local Device executor",
        ));
    }
    Ok(account)
}

async fn lock_subject(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    device_owner: Option<&AccountId>,
) -> PersistenceResult<()> {
    #[derive(diesel::QueryableByName)]
    struct Local {
        #[diesel(sql_type=Nullable<Text>)]
        station: Option<String>,
    }
    let local = sql_query("SELECT current_device_inventory_station() AS station")
        .get_result::<Local>(&mut *conn)
        .await
        .map_err(crate::persistence_query_error)?;
    if local.station.as_deref() != Some(account.station_id.as_str()) {
        return Err(invalid(
            "the existing local Service identity does not own this hosting Account",
        ));
    }
    // Share the native G owner's inception-before-tuple order. Both entry
    // points can contend for this Account while erasure waits for its tuple.
    let key = format!(
        "native-account-inception:{}",
        arkret_canonical::canonical_json_string(account).map_err(invalid)?
    );
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(key)
        .execute(&mut *conn)
        .await
        .map_err(crate::persistence_query_error)?;
    // Fresh Device publication owns two distinct private subjects. Acquire
    // every tuple before any Account row or forward row, in one stable order.
    if let Some(producer) = device_owner {
        let mut owners = [account, producer]
            .into_iter()
            .map(|owner| {
                Ok((
                    arkret_canonical::canonical_json_string(owner).map_err(invalid)?,
                    owner,
                ))
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        owners.sort_by(|a, b| a.0.cmp(&b.0));
        owners.dedup_by(|a, b| a.0 == b.0);
        for (_, owner) in owners {
            crate::pcr_private_authority::lock_optional_account_private_tuple(conn, owner).await?;
        }
    }
    crate::organization_pcr_genesis::require_creatable_account_owner(conn, account).await?;
    if let Some(producer) = device_owner {
        crate::pcr_private_authority::require_active_account_owner(conn, producer).await?;
    }
    Ok(())
}

#[derive(diesel::QueryableByName)]
struct Intent {
    #[diesel(sql_type=Jsonb)]
    envelope: Value,
    #[diesel(sql_type=Jsonb)]
    original: Value,
    #[diesel(sql_type=Nullable<Jsonb>)]
    terminal: Option<Value>,
}

async fn intent(
    conn: &mut AsyncPgConnection,
    original: &EventAdmissionSubmission,
    account: &AccountId,
) -> PersistenceResult<Option<Intent>> {
    let rows = sql_query("SELECT e.envelope,f.original_submission_json AS original,f.terminal_outcome_json AS terminal FROM canonical_events e JOIN authority_forward_attempts f ON f.event_pk=e.pk WHERE e.kind='ak.realm.create' AND e.envelope->'actor_id'=$1 AND e.envelope#>>'{payload,object,purpose}'='principal_control' AND f.original_submission_json IS NOT NULL ORDER BY e.pk FOR UPDATE OF f")
        .bind::<Jsonb,_>(serde_json::to_value(ActorId::account(account.clone())).map_err(invalid)?)
        .load::<Intent>(conn).await.map_err(crate::persistence_query_error)?;
    if rows.len() > 1 {
        return Err(conflict("multiple inception intents exist"));
    }
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    if row.envelope != serde_json::to_value(&original.event).map_err(invalid)?
        || row.original
            != serde_json::to_value(SelfAuthoritySubmitRequestBody::Event(original.clone()))
                .map_err(invalid)?
    {
        return Err(conflict(
            "the Account already chose another exact inception",
        ));
    }
    Ok(Some(row))
}

/// An accepted H source must have H's earlier exact intent and the first G
/// result. A naked public bundle/fact, an editable index or a G private row
/// cannot create this lineage.
pub(crate) async fn fact_for_commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<Option<OrganizationGenesisSignerFact>> {
    #[derive(diesel::QueryableByName)]
    struct Source {
        #[diesel(sql_type=Jsonb)]
        original: Value,
        #[diesel(sql_type=Jsonb)]
        terminal: Value,
        #[diesel(sql_type=Jsonb)]
        fact: Value,
    }
    let row = sql_query("SELECT f.original_submission_json AS original,f.terminal_outcome_json AS terminal,k.producer_source_fact AS fact FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk JOIN authority_forward_attempts f ON f.event_pk=e.pk JOIN agent_producer_signer_keys k ON k.commit_id=c.commit_id WHERE e.envelope=$1 AND e.state='committed' AND c.commit_json=$2 AND current_device_inventory_station()=(e.envelope#>>'{actor_id,account_id,station_id}') AND f.original_submission_json IS NOT NULL AND f.terminal_outcome_json IS NOT NULL AND f.peer_request_json IS NULL AND k.producer_source_fact IS NOT NULL")
        .bind::<Jsonb,_>(serde_json::to_value(event).map_err(invalid)?)
        .bind::<Jsonb,_>(serde_json::to_value(commit).map_err(invalid)?)
        .get_result::<Source>(conn).await.optional().map_err(crate::persistence_query_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let SelfAuthoritySubmitRequestBody::Event(original) =
        serde_json::from_value(row.original).map_err(invalid)?
    else {
        return Err(invalid("original source is not the one-create Event"));
    };
    let AuthoritySubmitResponseBody::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: accepted,
    } = serde_json::from_value(row.terminal).map_err(invalid)?
    else {
        return Err(invalid("original source has no G acceptance"));
    };
    let HistoricalProducerSignerFact::OrganizationGenesis(fact) =
        serde_json::from_value(row.fact).map_err(invalid)?
    else {
        return Err(invalid("original fact is not Organization Genesis"));
    };
    if original.event != *event
        || accepted != *commit
        || original.approval_signatures != fact.approval_signatures
    {
        return Err(conflict(
            "original Event, approvals, fact or G result differ",
        ));
    }
    let account = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("source has no full Account"))?;
    if event
        .as_realm_create()
        .map_err(invalid)?
        .object
        .governance_station_id
        == account.station_id
        || !(matches!(event.actual_signer(), ActorId::Service { .. })
            || event
                .account_device_producer()
                .map_err(invalid)?
                .is_some_and(|producer| producer.account_id.station_id == account.station_id))
    {
        return Err(invalid(
            "a local-G or different producer cannot use the hosting-only source",
        ));
    }
    arkret_identity::organization_pcr_genesis::verify_organization_genesis_signer_fact(
        &CommittedEventFullView {
            event: event.clone(),
            commit: commit.clone(),
        },
        &fact,
    )
    .map_err(invalid)?;
    Ok(Some(fact))
}

/// Hosting-only private projections consume this accepted source. Authoritative
/// G private reads and handoff never use this adapter.
pub(crate) async fn has_accepted_source_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<bool> {
    #[derive(diesel::QueryableByName)]
    struct Original {
        #[diesel(sql_type=Jsonb)]
        event: Value,
        #[diesel(sql_type=Jsonb)]
        commit: Value,
    }
    // Once H itself is current governor it must possess G's complete private
    // source. Hosting evidence never substitutes for that import obligation.
    let original = sql_query("SELECT e.envelope AS event,c.commit_json AS commit FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk JOIN realm_authorities a ON a.realm_id=c.realm_id WHERE c.realm_id=$1 AND e.kind='ak.realm.create' AND e.state='committed' AND c.stream_position=0 AND a.service_id<>(e.envelope#>>'{actor_id,account_id,station_id}') AND current_device_inventory_station()=(e.envelope#>>'{actor_id,account_id,station_id}')")
        .bind::<Text,_>(realm.as_str()).get_result::<Original>(&mut *conn).await.optional().map_err(crate::persistence_query_error)?;
    if let Some(original) = original {
        let event = serde_json::from_value(original.event).map_err(invalid)?;
        let commit = serde_json::from_value(original.commit).map_err(invalid)?;
        return Ok(fact_for_commit_in_connection(conn, &event, &commit)
            .await?
            .is_some());
    }
    Ok(false)
}

pub(crate) async fn require_private_projection_source(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<()> {
    if has_accepted_source_in_connection(conn, realm).await? {
        return Ok(());
    }
    let native = crate::pcr_private_authority::accepted_governance(conn, realm).await?;
    if !native.is_principal_control() {
        return Err(invalid("private projection is not an accepted PCR"));
    }
    native.require_transferable().map_err(invalid)
}

/// Account erasure already owns the exclusive tuple and Account cut. Pending
/// H transport belongs to the Organization subject; the accepted minimal
/// public governance original belongs to that Organization even when C was
/// the actual executor. No Account SHARE is taken from this erasure callback.
pub(crate) async fn handle_private_forward_erasure(
    conn: &mut AsyncPgConnection,
    event: &Event,
    erased: &AccountId,
) -> PersistenceResult<bool> {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=Jsonb)]
        original: Value,
        #[diesel(sql_type=Nullable<Jsonb>)]
        peer: Option<Value>,
        #[diesel(sql_type=Nullable<Jsonb>)]
        terminal: Option<Value>,
    }
    let row = sql_query("SELECT f.original_submission_json AS original,f.peer_request_json AS peer,f.terminal_outcome_json AS terminal FROM authority_forward_attempts f JOIN canonical_events e ON e.pk=f.event_pk WHERE e.envelope=$1 AND e.kind='ak.realm.create' AND e.envelope#>>'{payload,object,purpose}'='principal_control' AND current_device_inventory_station()=(e.envelope#>>'{actor_id,account_id,station_id}') AND f.original_submission_json IS NOT NULL")
        .bind::<Jsonb,_>(serde_json::to_value(event).map_err(invalid)?)
        .get_result::<Row>(&mut *conn).await.optional().map_err(crate::persistence_query_error)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let SelfAuthoritySubmitRequestBody::Event(original) =
        serde_json::from_value(row.original).map_err(invalid)?
    else {
        return Ok(false);
    };
    if original.event != *event {
        return Err(conflict("erasure intent differs from the immutable Event"));
    }
    if let Some(outcome) = row.terminal {
        let AuthoritySubmitResponseBody::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        } = serde_json::from_value(outcome).map_err(invalid)?
        else {
            return Ok(false);
        };
        return Ok(fact_for_commit_in_connection(conn, event, &commit)
            .await?
            .is_some());
    }
    let subject = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("pending choice has no Org Account"))?;
    if arkret_wire::GenesisGovernance::from_genesis(event).map_err(invalid)?
        != arkret_wire::GenesisGovernance::Organization
    {
        return Ok(false);
    }
    if let Some(peer) = row.peer {
        let PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(peer) =
            serde_json::from_value(peer).map_err(invalid)?
        else {
            return Err(invalid("pending hosting choice has another transport"));
        };
        peer.validate().map_err(invalid)?;
        if !peer.is_organization_pcr_genesis_candidate() || peer.event_submission != original {
            return Err(conflict(
                "pending hosting transport differs from its business choice",
            ));
        }
    }
    if subject == erased {
        // E(O) permanently prevents a new H Account; its unaccepted private
        // intent may be erased without releasing an active Organization.
        sql_query("DELETE FROM authority_forward_attempts WHERE event_pk=(SELECT pk FROM canonical_events WHERE envelope=$1) AND terminal_outcome_json IS NULL")
            .bind::<Jsonb,_>(serde_json::to_value(event).map_err(invalid)?)
            .execute(conn).await.map_err(crate::persistence_query_error)?;
        return Ok(true);
    }
    if event
        .account_device_producer()
        .map_err(invalid)?
        .is_some_and(|producer| &producer.account_id == erased)
    {
        // E(C) removes its dynamic private source, never O's immutable choice
        // while a previously sent G request may still have committed. Later
        // recovery uses only O's original submission and a positive public
        // certificate; this None is not a peer request or an absence proof.
        sql_query("UPDATE authority_forward_attempts SET peer_request_json=NULL WHERE event_pk=(SELECT pk FROM canonical_events WHERE envelope=$1) AND terminal_outcome_json IS NULL")
            .bind::<Jsonb,_>(serde_json::to_value(event).map_err(invalid)?)
            .execute(conn).await.map_err(crate::persistence_query_error)?;
        return Ok(true);
    }
    Ok(false)
}

impl PgAuthorityCommitStore {
    /// A local operator may inspect only its actually accepted Org hosting
    /// lineage. This read never installs a foreign source or refreshes choice.
    pub async fn require_accepted_organization_hosting_account(
        &self,
        account: &AccountId,
        hosting: &DidCoreId,
    ) -> PersistenceResult<RealmId> {
        if &account.station_id != hosting {
            return Err(invalid("inspection belongs to another hosting Station"));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_,PgTransactionError,_>(async |conn| {
            lock_subject(conn, account, None).await?;
            crate::pcr_private_authority::require_active_account_owner(conn, account).await?;
            #[derive(diesel::QueryableByName)]
            struct Origin { #[diesel(sql_type=Jsonb)] event: Value, #[diesel(sql_type=Jsonb)] commit: Value }
            let row = sql_query("SELECT e.envelope AS event,c.commit_json AS commit FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->'actor_id'=$1 AND e.kind='ak.realm.create' AND e.state='committed' AND c.stream_position=0")
                .bind::<Jsonb,_>(serde_json::to_value(ActorId::account(account.clone())).map_err(invalid)?)
                .get_result::<Origin>(&mut *conn).await.optional()?.ok_or_else(|| invalid("accepted local Organization hosting original absent"))?;
            let event: Event = serde_json::from_value(row.event).map_err(invalid)?;
            let commit: RealmCommit = serde_json::from_value(row.commit).map_err(invalid)?;
            fact_for_commit_in_connection(conn, &event, &commit).await?.ok_or_else(|| invalid("the local immutable accepted hosting intent/source is missing"))?;
            let (current, _) = crate::principal_resolution_unit::current_in_connection(conn, Some(account), Some(&event.realm_id)).await?
                .ok_or_else(|| invalid("accepted typed Organization current is missing"))?;
            if current.genesis_event != event { return Err(conflict("typed current belongs to another inception").into()); }
            Ok(event.realm_id)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    /// Read/recover only a previously accepted local hosting intent. The exact
    /// subject's current/E gate precedes any private ledger access.
    pub async fn organization_hosting_intent(
        &self,
        original: &EventAdmissionSubmission,
        hosting: &DidCoreId,
    ) -> PersistenceResult<Option<Option<AuthoritySubmitResponseBody>>> {
        let account = holder(original, hosting)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            lock_subject(conn, account, None).await?;
            let Some(row) = intent(conn, original, account).await? else {
                return Ok(None);
            };
            if let Some(terminal) = &row.terminal {
                let outcome: AuthoritySubmitResponseBody =
                    serde_json::from_value(terminal.clone()).map_err(invalid)?;
                let AuthoritySubmitResponseBody::Accepted {
                    status: AuthorityCommitStatus::Committed,
                    commit,
                } = &outcome
                else {
                    return Err(invalid("hosting source has a non-acceptance result").into());
                };
                fact_for_commit_in_connection(conn, &original.event, commit)
                    .await?
                    .ok_or_else(|| invalid("accepted hosting original is incomplete"))?;
                return Ok(Some(Some(outcome)));
            }
            // The minimal Org choice remains readable after C's private peer
            // body was erased. Never return that private transport here.
            Ok(Some(None))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    /// Prepare only a real H-local current C source, without private writes.
    /// Both full-pair owner cuts precede C's PCR and any forward row.
    pub async fn prepare_organization_hosting_device(
        &self,
        original: &EventAdmissionSubmission,
        hosting: &DidCoreId,
    ) -> PersistenceResult<Option<coland_storage::PreparedAccountDeviceForwardSource>> {
        let account = holder(original, hosting)?;
        let event = &original.event;
        let Some(producer) = event.account_device_producer().map_err(invalid)? else {
            return Ok(None);
        };
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_,PgTransactionError,_>(async |conn| {
            lock_subject(conn, account, Some(&producer.account_id)).await?;
            crate::managed_forward_source::lock_source(conn, event).await?;
            if let Some(row) = intent(conn, original, account).await?
                && row.terminal.is_some() {
                    return Err(invalid("accepted original requires its historical result reader").into());
                }
            // This is the existing unsigned business-body builder used before
            // issuing evidence, never a transmitted missing-evidence probe.
            let draft = PeerAuthorityForwardEventRequestBody {
                branch: arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
                event_submission: original.clone(), mls_group_state_material: None,
                content_backup_sources: None, producer_device_evidence: None,
                producer_agent_evidence: None, successor_device_evidence: None,
            };
            let digest = arkret_models_collaboration::authority_commit::authority_forward_body_digest(&draft).map_err(invalid)?;
            let destination = event.as_realm_create().map_err(invalid)?.object.governance_station_id;
            let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
            let device = crate::account_device_signer_evidence::forward_source::prepare_in_connection(conn, event, &destination, &digest, at).await?
                .ok_or_else(|| invalid("real locked H Device source unavailable"))?;
            Ok(Some(coland_storage::PreparedAccountDeviceForwardSource { device }))
        }).await.map_err(PgTransactionError::into_persistence)
    }

    /// Freeze the unique full Account's first source and complete peer intent
    /// in one transaction. This creates no Account, Device or readable PCR.
    pub async fn prepare_organization_hosting(
        &self,
        request: &PeerAuthorityForwardEventRequestBody,
        hosting: &DidCoreId,
        entries: &[Value],
        witnesses: &[Value],
        producer: Option<&AuthenticatedServiceResolution>,
    ) -> PersistenceResult<PeerAuthorityForwardEventRequestBody> {
        request.validate().map_err(invalid)?;
        if !request.is_organization_pcr_genesis_candidate() {
            return Err(invalid(
                "fresh source is not the complete Organization create",
            ));
        }
        let account = holder(&request.event_submission, hosting)?;
        let event = &request.event_submission.event;
        let device = event.account_device_producer().map_err(invalid)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_,PgTransactionError,_>(async |conn| {
            lock_subject(conn, account, device.as_ref().map(|producer| &producer.account_id)).await?;
            if let Some(device) = device.as_ref() {
                crate::managed_forward_source::lock_source(conn, event).await?;
                let evidence = request.producer_device_evidence.as_ref().ok_or_else(|| invalid("fresh Device source absent"))?;
                let core = &evidence.device_projection_attestation.attestation;
                let digest = arkret_models_collaboration::authority_commit::authority_forward_body_digest(request).map_err(invalid)?;
                let destination = event.as_realm_create().map_err(invalid)?.object.governance_station_id;
                let current = crate::account_device_signer_evidence::forward_source::prepare_in_connection(conn, event, &destination, &digest, core.attested_at).await?;
                if core.account_id != device.account_id || current.as_ref() != Some(core) {
                    return Err(invalid("fresh Device source changed before the first durable transport").into());
                }
            }
            let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
            arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_source(request, hosting, entries, witnesses, producer, at).map_err(invalid)?;
            crate::organization_pcr_genesis::lock_current_native_sources(conn, entries, producer).await?;
            if let Some(row) = intent(conn, &request.event_submission, account).await? {
                if row.terminal.is_some() { return Err(invalid("accepted original requires the original-result reader").into()); }
                if device.is_some() {
                    let refreshed = sql_query("UPDATE authority_forward_attempts SET peer_request_json=$2,attempted_at=$3 WHERE event_pk=(SELECT pk FROM canonical_events WHERE envelope=$1) AND terminal_outcome_json IS NULL")
                        .bind::<Jsonb,_>(serde_json::to_value(event).map_err(invalid)?)
                        .bind::<Jsonb,_>(serde_json::to_value(PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(request.clone())).map_err(invalid)?)
                        .bind::<Timestamptz,_>(at).execute(&mut *conn).await?;
                    if refreshed != 1 { return Err(conflict("the original unknown choice changed before fresh source publication").into()); }
                } else {
                    #[derive(diesel::QueryableByName)]
                    struct Peer { #[diesel(sql_type=Nullable<Jsonb>)] peer: Option<Value> }
                    let peer = sql_query("SELECT peer_request_json AS peer FROM authority_forward_attempts WHERE event_pk=(SELECT pk FROM canonical_events WHERE envelope=$1)")
                        .bind::<Jsonb,_>(serde_json::to_value(event).map_err(invalid)?).get_result::<Peer>(&mut *conn).await?;
                    if peer.peer != Some(serde_json::to_value(PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(request.clone())).map_err(invalid)?) {
                        return Err(conflict("the original Service transport changed").into());
                    }
                }
                return Ok(request.clone());
            }
            #[derive(diesel::QueryableByName)] struct Present { #[diesel(sql_type=Bool)] present: bool }
            let bound = sql_query("SELECT EXISTS(SELECT 1 FROM accounts WHERE principal_id=$1 AND station_id=$2) OR EXISTS(SELECT 1 FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2) OR EXISTS(SELECT 1 FROM pcr_genesis_units WHERE principal_id=$1 AND station_id=$2) OR EXISTS(SELECT 1 FROM organization_pcr_genesis_sources WHERE principal_id=$1 AND station_id=$2) AS present")
                .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str()).get_result::<Present>(&mut *conn).await?;
            if bound.present { return Err(conflict("an Account or inception already exists without this original hosting intent").into()); }
            crate::authority_commit::queue_event_in_connection(conn, event, at).await?;
            let written = sql_query("INSERT INTO authority_forward_attempts(event_pk,status,attempted_at,original_submission_json,peer_request_json) SELECT pk,'forwarding',$2,$3,$4 FROM canonical_events WHERE envelope=$1 ON CONFLICT(event_pk) DO NOTHING")
                .bind::<Jsonb,_>(serde_json::to_value(event).map_err(invalid)?).bind::<Timestamptz,_>(at)
                .bind::<Jsonb,_>(serde_json::to_value(SelfAuthoritySubmitRequestBody::Event(request.event_submission.clone())).map_err(invalid)?)
                .bind::<Jsonb,_>(serde_json::to_value(PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(request.clone())).map_err(invalid)?)
                .execute(&mut *conn).await?;
            if written != 1 { return Err(conflict("the first hosting intent changed").into()); }
            Ok(request.clone())
        }).await.map_err(PgTransactionError::into_persistence)
    }

    /// Install only the verified G original against H's own earlier intent.
    /// A remote bundle alone can never manufacture a hosted Account.
    pub async fn complete_organization_hosting(
        &self,
        original: &EventAdmissionSubmission,
        hosting: &DidCoreId,
        outcome: &AuthoritySubmitResponseBody,
        bundle: &RealmAuthorityBundle,
        freshness: &arkret_identity::RealmAuthorityFreshness,
        keys: &arkret_identity::RealmAuthorityKeyMap,
    ) -> PersistenceResult<AuthoritySubmitResponseBody> {
        let account = holder(original, hosting)?;
        let event = &original.event;
        let AuthoritySubmitResponseBody::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        } = outcome
        else {
            return Err(invalid(
                "G did not return the one original Committed Organization result",
            ));
        };
        if bundle.genesis_event != *event || bundle.genesis_commit != *commit {
            return Err(conflict(
                "G original differs from the frozen Event and genesis certificate",
            ));
        }
        let fact =
            arkret_models_collaboration::authority_commit::organization_genesis_signer_fact(bundle)
                .map_err(invalid)?
                .ok_or_else(|| invalid("original public Organization source missing"))?;
        if fact.approval_signatures != original.approval_signatures {
            return Err(conflict("G original changed the finite approvals"));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_,PgTransactionError,_>(async |conn| {
            // Historical positive-certificate installation belongs to O. It
            // must not acquire C's current gate or read erased C peer material.
            lock_subject(conn, account, None).await?;
            let row = intent(conn, original, account).await?.ok_or_else(|| invalid("no earlier H hosting intent exists"))?;
            if let Some(terminal) = &row.terminal {
                let original: AuthoritySubmitResponseBody = serde_json::from_value(terminal.clone()).map_err(invalid)?;
                if original != *outcome { return Err(conflict("G outcome changed").into()); }
                fact_for_commit_in_connection(conn, event, commit).await?.ok_or_else(|| invalid("accepted source missing"))?;
                return Ok(original);
            }
            let fresh = arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), freshness.expected_nonce.clone());
            let verified = arkret_identity::verify_realm_authority_bundle(bundle, &fresh, keys).map_err(invalid)?;
            verified.verify_commit(commit, keys).map_err(invalid)?;
            let (authority_ref, last_handoff_ref) = bundle.authority_transitions.last().map_or_else(
                || (arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone()), None),
                |transition| (arkret_wire::RealmCommitAuthorityRef::Handoff(transition.handoff.handoff_id.clone()), Some(transition.handoff.handoff_id.clone())),
            );
            let authority = CurrentRealmAuthority { realm_id: event.realm_id.clone(), generation: verified.current_generation(), service_id: verified.current_service_id().clone(), authority_ref, last_handoff_ref };
            crate::authority_commit::replica::record_remote_authority_in_connection(conn, &authority, hosting).await?;
            let key = crate::authority_commit::stream_key(&commit.stream_ref)?;
            crate::authority_commit::replica::store_replica_rows(conn, event, commit, &key, chrono::Utc::now()).await?;
            let verification_method = event.producer_proof.as_ref().ok_or_else(|| invalid("producer proof absent"))?.verification_method.clone();
            let committed_event_ref = arkret_wire::CommittedEventRef { event_id: event.event_id.clone(), commit_id: commit.commit_id.clone(), stream_ref: commit.stream_ref.clone(), stream_position: commit.stream_position };
            let sender = if let Some(producer) = event.account_device_producer().map_err(invalid)? {
                HistoricalSignerKeyQuerySender::AccountDevice { actor: event.actual_signer().clone(), device_id: producer.device_id, verification_method, committed_event_ref }
            } else {
                HistoricalSignerKeyQuerySender::Service { actor: event.actual_signer().clone(), verification_method, committed_event_ref }
            };
            let selector = SignerKeyQuerySelector::HistoricalEvent { sender };
            let unavailable = SignerKeyResolution::Unavailable { selector };
            let source = HistoricalProducerSignerFact::OrganizationGenesis(fact.clone());
            sql_query("INSERT INTO agent_producer_signer_keys(commit_id,outcome,producer_source_fact) VALUES($1,$2,$3)")
                .bind::<Text,_>(commit.commit_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(unavailable).map_err(invalid)?)
                .bind::<Jsonb,_>(serde_json::to_value(source).map_err(invalid)?).execute(&mut *conn).await?;
            let resolution = event.as_realm_create().map_err(invalid)?.object.initial_resolution.clone().ok_or_else(|| invalid("initial resolution absent"))?;
            let projection = PrincipalResolutionProjection { did: resolution.did, method_history_head: resolution.method_history_head, version_id: resolution.version_id, resolution_event_ref: event.event_id.to_string(), updated_at: event.created_at };
            sql_query("WITH p AS (INSERT INTO principal_resolutions(principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) VALUES($1,$2,$3,$4,$4,$5,$6) RETURNING principal_id,station_id) INSERT INTO principal_resolution_events(principal_id,station_id,event_id,previous_event_id,method_history_head,event_json,created_at) SELECT principal_id,station_id,$4,NULL,$7,$8,$6 FROM p")
                .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str()).bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.event_id.as_str())
                .bind::<Jsonb,_>(serde_json::to_value(&projection).map_err(invalid)?).bind::<Timestamptz,_>(projection.updated_at).bind::<Text,_>(&projection.method_history_head)
                .bind::<Jsonb,_>(serde_json::to_value(event).map_err(invalid)?).execute(&mut *conn).await?;
            crate::principal_resolution_unit::initialize_in_connection(conn, account, event, commit, &projection).await?;
            crate::accounts::create_native_holder_account_in_connection(conn, account, commit.committed_at).await?;
            // Dynamic source siblings are H-private transport, not another G
            // archive. The public original Event/approvals and first G result
            // are sufficient for H's immutable accepted hosting lineage.
            let written = sql_query("UPDATE authority_forward_attempts f SET terminal_outcome_json=$2,peer_request_json=NULL WHERE event_pk=(SELECT pk FROM canonical_events WHERE envelope=$1) AND terminal_outcome_json IS NULL")
                .bind::<Jsonb,_>(serde_json::to_value(event).map_err(invalid)?).bind::<Jsonb,_>(serde_json::to_value(outcome).map_err(invalid)?).execute(&mut *conn).await?;
            if written != 1 { return Err(conflict("first original outcome changed").into()); }
            fact_for_commit_in_connection(conn, event, commit).await?.ok_or_else(|| invalid("installed hosting source did not close"))?;
            Ok(outcome.clone())
        }).await.map_err(PgTransactionError::into_persistence)
    }

    /// Only the registered one-create Org outcome is a deterministic function
    /// of its genuine original Commit. Full Event/proof and exact vote vector
    /// binding are still enforced by the same original-install owner above.
    pub async fn recover_organization_hosting(
        &self,
        original: &EventAdmissionSubmission,
        hosting: &DidCoreId,
        bundle: &RealmAuthorityBundle,
        freshness: &arkret_identity::RealmAuthorityFreshness,
        keys: &arkret_identity::RealmAuthorityKeyMap,
    ) -> PersistenceResult<AuthoritySubmitResponseBody> {
        let outcome = AuthoritySubmitResponseBody::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit: bundle.genesis_commit.clone(),
        };
        self.complete_organization_hosting(original, hosting, &outcome, bundle, freshness, keys)
            .await
    }
}
