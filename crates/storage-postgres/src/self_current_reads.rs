//! Authenticated, non-enumerating self reads decided at one governing read
//! cut: `ak.self.realm.read.streams.v1`,
//! `ak.self.current_results.read.exact.v1`,
//! `ak.self.strand.watch.read.current.v1` and the anchor half of
//! `ak.self.media_service_binding.read.resolve.v1`.
//!
//! Every read opens one repeatable-read transaction that fixes the Realm's
//! governing tenure, the caller's membership and the stream heads together.
//! Original issuers can also read their exact owned Agent grant revisions
//! after membership ends; this exception grants no content visibility.
//! An unknown Realm and a caller that is not a currently joined member share
//! the universal `not_found`. Each selector must prove its own effective scope;
//! unrelated Circle or Sidecar streams do not invalidate a confirmed Realm-scope
//! Strand. No `never_written` answer is inferred from a missing row alone.

use arkret_models_collaboration::exact_current_results::{
    ExactCurrentResultEntry, ExactCurrentResultSelector, ExactCurrentResultsReadOutcome,
    ExactCurrentResultsReadRequestBody, ModerationStateCurrentValue,
    ModerationStateExactCurrentRow, ModerationStateExactCurrentSelector, RelationExactCurrentRow,
};
use arkret_models_collaboration::objects::relation::Relation;
use arkret_models_collaboration::strand_watch_operations::{
    StrandWatchCurrentOutcome, StrandWatchCurrentRequestBody, StrandWatchCurrentRow,
    StrandWatchCurrentSelector, StrandWatchSelectorKind,
};
use arkret_wire::{
    AccountId, ActorId, CommitStreamHead, CommitStreamRef, CurrentRevision, DidCoreId, RealmId,
    RealmStreamRow, ScopeRef,
};
use coland_storage::{AccountRealmStreamList, MediaServiceAnchorRead, SelfExactCurrentRead};
use diesel_async::AsyncPgConnection;

use super::{
    AsyncConnection, BigInt, ExistsRow, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, pg_conn,
    sql_query,
};

#[derive(QueryableByName)]
struct TenureRow {
    #[diesel(sql_type = BigInt)]
    generation: i64,
    #[diesel(sql_type = Text)]
    service_id: String,
}

pub(crate) const RELATION_CURRENT_SQL: &str = "SELECT r.current_commit_id, r.current_stream_position, r.value, c.stream_ref \
             FROM relation_current_results r \
             JOIN realm_commits c ON c.commit_id = r.current_commit_id \
             WHERE r.realm_id=$1 AND r.domain_key=$2 AND c.realm_id=r.realm_id \
               AND c.stream_position=r.current_stream_position";

pub(crate) const MODERATION_CURRENT_SQL: &str = "SELECT s.current_commit_id, s.current_stream_position, s.value, c.stream_ref \
         FROM moderation_state_current_results s \
         JOIN realm_commits c ON c.commit_id = s.current_commit_id \
         WHERE s.realm_id=$1 AND s.target_ref=$2 AND c.realm_id=s.realm_id \
           AND c.stream_position=s.current_stream_position";

// A scalar ordered probe preserves the Realm/member primary-key bound. Plain
// EXISTS may choose a low-startup sequential scan and inspect unrelated rows
// before reaching this member. Test the exact key and join state after LIMIT.
pub(crate) const MEMBER_PRESENT_SQL: &str = "SELECT COALESCE(( \
     SELECT realm_id=$1 AND member_id=$2 AND membership='join' \
       FROM member_state_current_results \
      WHERE (realm_id,member_id)>=($1,$2) \
      ORDER BY realm_id,member_id LIMIT 1 \
     ), FALSE) AS present";

pub(crate) const WATCH_CURRENT_SQL: &str = "SELECT w.current_commit_id,w.current_stream_position,w.value,c.stream_ref FROM strand_watch_current_results w JOIN realm_commits c ON c.commit_id=w.current_commit_id WHERE w.realm_id=$1 AND w.strand_id=$2 AND w.watcher_actor_id=$3 AND c.realm_id=w.realm_id AND c.stream_position=w.current_stream_position";

// Probe the adjacent keys on both sides of the Realm stream. Tuple bounds
// keep each probe on the Realm-prefixed index. Scalar ORDER BY/LIMIT prevents
// EXISTS from discarding that order and choosing a history scan instead.
pub(crate) const SCOPED_STREAMS_SQL: &str = "SELECT ( \
    (SELECT stream_key FROM realm_commits \
     WHERE realm_id=$1 AND (realm_id,stream_key)<($1,$2) \
     ORDER BY realm_id DESC,stream_key DESC LIMIT 1) IS NOT NULL OR \
    (SELECT stream_key FROM realm_commits \
     WHERE realm_id=$1 AND (realm_id,stream_key)>($1,$2) \
     ORDER BY realm_id,stream_key LIMIT 1) IS NOT NULL) AS present";

// Probe the first key at or above the exact selector. The ordered, bounded
// probe uses the (realm_id, kind) primary key even when PostgreSQL estimates
// a small table scan as cheaper for a plain EXISTS predicate.
pub(crate) const MEDIA_ANCHOR_SQL: &str = "SELECT EXISTS(SELECT 1 FROM ( \
     SELECT realm_id, kind FROM realm_commit_event_kinds \
     WHERE (realm_id, kind) >= ($1, $2) \
     ORDER BY realm_id, kind LIMIT 1 \
     ) candidate WHERE candidate.realm_id=$1 AND candidate.kind=$2) AS present";

#[derive(QueryableByName)]
struct HeadRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
}

#[derive(QueryableByName)]
struct ScopedHeadRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    stream_ref: serde_json::Value,
}

/// One typed current row with the stream of its covering RealmCommit.
#[derive(QueryableByName)]
struct CurrentRow {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    stream_ref: serde_json::Value,
}

/// The caller-visible facts every read in this module starts from.
enum MemberCut {
    /// Unknown Realm or not a currently joined member.
    NotVisible,
    /// A joined member of a Realm whose governing tenure is not `issuer`.
    ForeignTenure,
    Member {
        generation: u64,
        /// Head of the Realm stream; `None` before the genesis Commit.
        realm_head: Option<CommitStreamHead>,
        /// Whether any Circle or Sidecar stream has an established chain.
        scoped_streams: bool,
    },
}

fn corrupt(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Database(detail.into())
}

fn to_u64(value: i64, what: &str) -> PersistenceResult<u64> {
    u64::try_from(value).map_err(|_| corrupt(format!("stored {what} is negative")))
}

async fn begin_read_cut(conn: &mut AsyncPgConnection) -> Result<(), PgTransactionError> {
    sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(conn)
        .await?;
    Ok(())
}

async fn member_cut(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    caller: &ActorId,
    issuer: &DidCoreId,
) -> Result<MemberCut, PgTransactionError> {
    let Some(tenure) =
        sql_query("SELECT generation, service_id FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result::<TenureRow>(&mut *conn)
            .await
            .optional()?
    else {
        return Ok(MemberCut::NotVisible);
    };
    let joined = sql_query(MEMBER_PRESENT_SQL)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(caller.to_string())
        .get_result::<ExistsRow>(&mut *conn)
        .await?
        .present;
    if !joined {
        return Ok(MemberCut::NotVisible);
    }
    crate::agent_management_admission::read_controller_in_connection(conn, realm_id, None, caller)
        .await?;
    if tenure.service_id != issuer.as_str() {
        return Ok(MemberCut::ForeignTenure);
    }
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let realm_key = crate::authority_commit::stream_key(&realm_stream)?;
    let realm_head = sql_query(
        "SELECT commit_id, stream_position FROM realm_commits \
         WHERE realm_id=$1 AND stream_key=$2 ORDER BY stream_position DESC LIMIT 1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&realm_key)
    .get_result::<HeadRow>(&mut *conn)
    .await
    .optional()?
    .map(|row| {
        Ok::<_, PersistenceError>(CommitStreamHead {
            stream_ref: realm_stream.clone(),
            stream_position: to_u64(row.stream_position, "Realm stream position")?,
            commit_id: row
                .commit_id
                .parse()
                .map_err(|error| corrupt(format!("stored RealmCommit id is invalid: {error}")))?,
        })
    })
    .transpose()?;
    let scoped_streams = sql_query(SCOPED_STREAMS_SQL)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(&realm_key)
        .get_result::<ExistsRow>(&mut *conn)
        .await?
        .present;
    Ok(MemberCut::Member {
        generation: to_u64(tenure.generation, "governance generation")?,
        realm_head,
        scoped_streams,
    })
}

pub(crate) async fn list_realm_streams_for_account(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
    issuer: &DidCoreId,
) -> PersistenceResult<AccountRealmStreamList> {
    let caller = ActorId::account(account.clone());
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        begin_read_cut(conn).await?;
        list_streams_in_connection(conn, realm_id, &caller, issuer).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

#[derive(QueryableByName)]
struct HistoryBindingRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

/// Heads, caller visibility and policy provenance are frozen by one snapshot.
pub(crate) async fn realm_stream_subscription_cut(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
    issuer: &DidCoreId,
) -> PersistenceResult<coland_storage::AccountRealmStreamAuthorizationCut> {
    let caller = ActorId::account(account.clone());
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        begin_read_cut(conn).await?;
        let mut listing = list_streams_in_connection(conn, realm_id, &caller, issuer).await?;
        let mut history_digest = None;
        if let AccountRealmStreamList::Listed(streams) = &listing {
            let realm_policy = sql_query(
                "SELECT jsonb_build_array(h.value,h.current_commit_id,h.current_stream_position,m.current_commit_id,m.current_stream_position,a.generation,a.service_id) AS value \
                 FROM realm_bootstrap_current_results h \
                 LEFT JOIN realm_commits hc ON hc.realm_id=h.realm_id AND hc.commit_id=h.current_commit_id AND hc.stream_position=h.current_stream_position AND hc.stream_ref=jsonb_build_object('kind','realm','realm_id',h.realm_id) \
                 JOIN member_state_current_results m ON m.realm_id=h.realm_id AND m.member_id=$2 AND m.membership='join' \
                 LEFT JOIN realm_commits mc ON mc.realm_id=m.realm_id AND mc.commit_id=m.current_commit_id AND mc.stream_position=m.current_stream_position AND mc.stream_ref=jsonb_build_object('kind','realm','realm_id',m.realm_id) \
                 JOIN realm_authorities a ON a.realm_id=h.realm_id \
                 WHERE h.realm_id=$1 AND h.result_family='realm_history_access' \
                 AND (hc.commit_id IS NOT NULL OR EXISTS(SELECT 1 FROM replica_authorization_rows r WHERE r.realm_id=h.realm_id AND r.selector=jsonb_build_object('kind','realm_history_access') AND r.source_stream_ref=jsonb_build_object('kind','realm','realm_id',h.realm_id) AND r.current_commit_id=h.current_commit_id AND r.current_stream_position=h.current_stream_position AND r.value=h.value)) \
                 AND (mc.commit_id IS NOT NULL OR EXISTS(SELECT 1 FROM replica_authorization_rows r WHERE r.realm_id=m.realm_id AND r.selector=jsonb_build_object('kind','member_state','actor_id',$3::jsonb) AND r.source_stream_ref=jsonb_build_object('kind','realm','realm_id',m.realm_id) AND r.current_commit_id=m.current_commit_id AND r.current_stream_position=m.current_stream_position AND r.value=m.value))",
            ).bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(caller.to_string())
                .bind::<Jsonb,_>(serde_json::to_value(&caller).map_err(PersistenceError::database)?)
                .get_result::<HistoryBindingRow>(&mut *conn).await.optional()?;
            if let Some(policy) = realm_policy {
                let mut bindings = vec![policy.value];
                let mut complete = true;
                for row in streams {
                    let scoped = match &row.stream_ref {
                        CommitStreamRef::Realm { .. } => continue,
                        CommitStreamRef::Circle { circle_id, .. } => sql_query(
                            "SELECT jsonb_build_array(c.value->'history_access',c.current_commit_id,c.current_stream_position,m.current_commit_id,m.current_stream_position,m.value->'parent_membership_revision') AS value \
                             FROM circle_current_results c \
                             LEFT JOIN realm_commits cc ON cc.realm_id=c.realm_id AND cc.commit_id=c.current_commit_id AND cc.stream_position=c.current_stream_position AND cc.stream_ref=c.source_stream_ref \
                             JOIN circle_member_state_current_results m ON m.realm_id=c.realm_id AND m.circle_id=c.circle_id AND m.member_id=$3 AND m.membership='join' \
                             LEFT JOIN realm_commits mc ON mc.realm_id=m.realm_id AND mc.commit_id=m.current_commit_id AND mc.stream_position=m.current_stream_position AND mc.stream_ref=m.source_stream_ref \
                             WHERE c.realm_id=$1 AND c.circle_id=$2 AND circle_member_parent_join_current(m.realm_id,m.member_id,m.value) \
                             AND (cc.commit_id IS NOT NULL OR EXISTS(SELECT 1 FROM replica_authorization_rows r WHERE r.realm_id=c.realm_id AND r.selector=jsonb_build_object('kind','circle','circle_id',c.circle_id) AND r.source_stream_ref=c.source_stream_ref AND r.current_commit_id=c.current_commit_id AND r.current_stream_position=c.current_stream_position AND r.value=c.value)) \
                             AND (mc.commit_id IS NOT NULL OR EXISTS(SELECT 1 FROM replica_authorization_rows r WHERE r.realm_id=m.realm_id AND r.selector=jsonb_build_object('kind','circle_member_state','circle_id',m.circle_id,'member_actor_id',$4::jsonb) AND r.source_stream_ref=m.source_stream_ref AND r.current_commit_id=m.current_commit_id AND r.current_stream_position=m.current_stream_position AND r.value=m.value))",
                        ).bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(circle_id.as_str()).bind::<Text,_>(caller.to_string())
                            .bind::<Jsonb,_>(serde_json::to_value(&caller).map_err(PersistenceError::database)?)
                            .get_result::<HistoryBindingRow>(&mut *conn).await.optional()?,
                        CommitStreamRef::Sidecar { sidecar_id, .. } => sql_query(
                            "SELECT jsonb_build_array(s.value,s.current_commit_id,s.current_stream_position) AS value \
                             FROM sidecar_current_results s LEFT JOIN realm_commits c ON c.realm_id=s.realm_id AND c.commit_id=s.current_commit_id AND c.stream_position=s.current_stream_position AND c.stream_ref=s.source_stream_ref \
                             WHERE s.realm_id=$1 AND s.sidecar_id=$2 \
                             AND (c.commit_id IS NOT NULL OR EXISTS(SELECT 1 FROM replica_authorization_rows r WHERE r.realm_id=s.realm_id AND r.selector=jsonb_build_object('kind','sidecar','sidecar_id',s.sidecar_id) AND r.source_stream_ref=s.source_stream_ref AND r.current_commit_id=s.current_commit_id AND r.current_stream_position=s.current_stream_position AND r.value=s.value))",
                        ).bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(sidecar_id.as_str())
                            .get_result::<HistoryBindingRow>(&mut *conn).await.optional()?,
                        _ => None,
                    };
                    if let Some(scoped) = scoped { bindings.push(scoped.value); } else { complete = false; break; }
                }
                if complete {
                    let bytes = arkret_canonical::canonical_json_bytes(&(realm_id, caller, bindings)).map_err(PersistenceError::database)?;
                    history_digest = Some(arkret_canonical::base64url_encode(arkret_canonical::sha256_bytes(&bytes)));
                }
            }
            if history_digest.is_none() { listing = AccountRealmStreamList::Unproved("subscription policy provenance is not proved at this cut"); }
        }
        Ok(coland_storage::AccountRealmStreamAuthorizationCut { listing, history_digest })
    }).await.map_err(PgTransactionError::into_persistence)
}
async fn list_streams_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    caller: &ActorId,
    issuer: &DidCoreId,
) -> Result<AccountRealmStreamList, PgTransactionError> {
    let realm_head = match member_cut(conn, realm_id, caller, issuer).await? {
        MemberCut::NotVisible => return Ok(AccountRealmStreamList::NotVisible),
        MemberCut::ForeignTenure => {
            return Ok(crate::replica_stream_listing::in_connection(conn, realm_id, caller).await?);
        }
        MemberCut::Member { realm_head, .. } => realm_head,
    };
    let Some(head) = realm_head else {
        return Ok(AccountRealmStreamList::Listed(Vec::new()));
    };
    let Some(floor) =
        crate::account_stream_scan::caller_realm_floor_in_connection(conn, realm_id, caller)
            .await?
    else {
        return Ok(AccountRealmStreamList::Unproved(
            "a per-member join or history floor is not proved at this cut",
        ));
    };
    let mut visible = vec![RealmStreamRow {
        stream_ref: head.stream_ref,
        head_commit_ref: head.commit_id,
        next_position: head.stream_position.checked_add(1).ok_or_else(|| {
            PersistenceError::Internal("Realm stream position overflows".to_owned())
        })?,
        readable_floor: Some(floor),
    }];
    let heads = sql_query(crate::authority_commit::REALM_STREAM_HEADS_SQL)
        .bind::<Text, _>(realm_id.as_str())
        .load::<ScopedHeadRow>(&mut *conn)
        .await?;
    for head in heads {
        let stream: CommitStreamRef =
            serde_json::from_value(head.stream_ref).map_err(PersistenceError::database)?;
        let floor = match &stream {
            CommitStreamRef::Circle { circle_id, .. } => {
                crate::account_stream_scan::caller_circle_floor_in_connection(
                    conn, realm_id, circle_id, caller,
                )
                .await?
            }
            CommitStreamRef::Realm { .. } => continue,
            CommitStreamRef::Sidecar { sidecar_id, .. } => {
                crate::sidecar_authority_cut::public_material_floor_in_connection(
                    conn, realm_id, sidecar_id, caller,
                )
                .await?
            }
            _ => None,
        };
        let Some(floor) = floor else {
            continue;
        };
        visible.push(RealmStreamRow {
            stream_ref: stream,
            head_commit_ref: head.commit_id.parse().map_err(PersistenceError::database)?,
            next_position: to_u64(head.stream_position, "scoped stream position")?
                .checked_add(1)
                .ok_or_else(|| corrupt("scoped stream position overflows"))?,
            readable_floor: Some(floor),
        });
    }
    let mut keyed = visible
        .into_iter()
        .map(|row| {
            let key = arkret_canonical::canonical_json_bytes(&row.stream_ref)
                .map_err(PersistenceError::database)?;
            Ok((key, row))
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    let visible = keyed.into_iter().map(|(_, row)| row).collect();
    Ok(AccountRealmStreamList::Listed(visible))
}

pub(crate) async fn exact_current_result_for_actor(
    pool: &PgPool,
    request: &ExactCurrentResultsReadRequestBody,
    actor: &ActorId,
    issuer: &DidCoreId,
) -> PersistenceResult<SelfExactCurrentRead<ExactCurrentResultsReadOutcome>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        begin_read_cut(conn).await?;
        exact_current_result_for_actor_in_connection(conn, request, actor, issuer).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn exact_current_result_for_account(
    pool: &PgPool,
    request: &ExactCurrentResultsReadRequestBody,
    account: &AccountId,
    issuer: &DidCoreId,
) -> PersistenceResult<SelfExactCurrentRead<ExactCurrentResultsReadOutcome>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        begin_read_cut(conn).await?;
        exact_current_result_in_connection(conn, request, account, issuer).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn exact_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    request: &ExactCurrentResultsReadRequestBody,
    account: &AccountId,
    issuer: &DidCoreId,
) -> Result<SelfExactCurrentRead<ExactCurrentResultsReadOutcome>, PgTransactionError> {
    exact_current_result_for_actor_in_connection(
        conn,
        request,
        &ActorId::account(account.clone()),
        issuer,
    )
    .await
}

pub(crate) async fn exact_current_result_for_actor_in_connection(
    conn: &mut AsyncPgConnection,
    request: &ExactCurrentResultsReadRequestBody,
    actor: &ActorId,
    issuer: &DidCoreId,
) -> Result<SelfExactCurrentRead<ExactCurrentResultsReadOutcome>, PgTransactionError> {
    request
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let caller = actor.clone();
    if let ExactCurrentResultSelector::CapabilityGrant(selector) = &request.selector {
        let Some(account) = actor.as_account_id() else {
            return Ok(SelfExactCurrentRead::NotFound);
        };
        return owned_agent_grant_read(conn, request, selector, account, issuer).await;
    }
    let (generation, head) = match member_cut(conn, &request.realm_id, &caller, issuer).await? {
        MemberCut::NotVisible => return Ok(SelfExactCurrentRead::NotFound),
        MemberCut::ForeignTenure => {
            return Ok(SelfExactCurrentRead::Unresolved(
                "this Station does not hold the Realm's governing tenure",
            ));
        }
        MemberCut::Member {
            scoped_streams: true,
            ..
        } if matches!(request.selector, ExactCurrentResultSelector::Relation(_)) => {
            return Ok(SelfExactCurrentRead::Unresolved(
                "Circle and Sidecar scope visibility is not proved at this cut",
            ));
        }
        MemberCut::Member {
            realm_head: None, ..
        } => {
            return Ok(SelfExactCurrentRead::Unresolved(
                "the Realm stream has no established head",
            ));
        }
        MemberCut::Member {
            generation,
            realm_head: Some(head),
            ..
        } => (generation, head),
    };
    let selector = match &request.selector {
        ExactCurrentResultSelector::AppletRegistration(selector) => {
            use arkret_models_collaboration::exact_current_results::{
                AppletRegistrationExactCurrentRow, NeverWrittenExactCurrentSelector,
            };
            if caller.as_account_id().is_none() {
                return Ok(SelfExactCurrentRead::NotFound);
            }
            let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
                conn,
                &request.realm_id,
                &caller,
            )
            .await?;
            if !cut.permits_unreserved_current_actions(
                &[arkret_wire::CapabilityActionId::REALM_ADMIN],
                &arkret_wire::WireResourceSelector::realm(request.realm_id.clone()),
                chrono::Utc::now(),
            ) {
                return Ok(SelfExactCurrentRead::NotFound);
            }
            if let Some(account) = caller.as_account_id()
                && crate::realm_authorization_cut::is_owned_agent_in_connection(
                    conn,
                    &request.realm_id,
                    account,
                )
                .await?
            {
                let check =
                    arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody {
                        actor_id: caller.clone(),
                        action: arkret_wire::CapabilityActionId::REALM_ADMIN.to_owned(),
                        resource: Some(arkret_wire::WireResourceSelector::realm(
                            request.realm_id.clone(),
                        )),
                        context: None,
                    };
                if !crate::realm_authorization_cut::owned_agent_authorization_check_in_connection(
                    conn, &caller, &check,
                )
                .await?
                .is_some_and(|result| result.decision == arkret_wire::AuthzDecision::Allow)
                {
                    return Ok(SelfExactCurrentRead::NotFound);
                }
            }
            #[derive(QueryableByName)]
            struct RegistrationRow {
                #[diesel(sql_type = Text)]
                current_commit_id: String,
                #[diesel(sql_type = BigInt)]
                current_stream_position: i64,
                #[diesel(sql_type = Jsonb)]
                value: serde_json::Value,
            }
            let row = sql_query("SELECT r.current_commit_id,r.current_stream_position,r.value FROM applet_registration_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id AND c.realm_id=r.realm_id AND c.stream_position=r.current_stream_position WHERE r.realm_id=$1 AND r.applet_id=$2 AND r.service_id=$3 AND c.stream_ref->>'kind'='realm'")
                .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(selector.applet_id.as_str()).bind::<Text,_>(selector.service_id.as_str())
                .get_result::<RegistrationRow>(&mut *conn).await.optional()?;
            let outcome = if let Some(row) = row {
                let payload: arkret_models_integration::AppletRegistrationPayload =
                    serde_json::from_value(row.value.clone())
                        .map_err(PersistenceError::database)?;
                if payload.applet_id != selector.applet_id
                    || payload.service_id != selector.service_id
                {
                    return Err(PersistenceError::SchemaViolation(
                        "registration selector differs from accepted payload".into(),
                    )
                    .into());
                }
                ExactCurrentResultsReadOutcome::Present {
                    realm_id: request.realm_id.clone(),
                    governance_generation: generation,
                    effective_stream_head: head.clone(),
                    entry: ExactCurrentResultEntry::AppletRegistration(
                        AppletRegistrationExactCurrentRow {
                            selector: selector.clone(),
                            source_stream_ref: head.stream_ref.clone(),
                            revision: CurrentRevision {
                                commit_id: row
                                    .current_commit_id
                                    .parse()
                                    .map_err(PersistenceError::database)?,
                                stream_position: to_u64(
                                    row.current_stream_position,
                                    "Applet registration current",
                                )?,
                            },
                            value: row.value,
                        },
                    ),
                }
            } else {
                ExactCurrentResultsReadOutcome::NeverWritten {
                    realm_id: request.realm_id.clone(),
                    governance_generation: generation,
                    effective_stream_head: head,
                    selector: NeverWrittenExactCurrentSelector::AppletRegistration(
                        selector.clone(),
                    ),
                }
            };
            outcome
                .validate_for_request(request, generation)
                .map_err(PersistenceError::database)?;
            return Ok(SelfExactCurrentRead::Answer(outcome));
        }
        ExactCurrentResultSelector::Policy(selector) => {
            return policy_exact_read(conn, request, selector, &caller, generation, head).await;
        }
        ExactCurrentResultSelector::CalendarScheduleSource(selector) => {
            use arkret_models_collaboration::exact_current_results::CalendarScheduleSourceExactRow;
            #[derive(QueryableByName)]
            struct CalendarRow {
                #[diesel(sql_type = Text)]
                current_commit_id: String,
                #[diesel(sql_type = BigInt)]
                current_stream_position: i64,
                #[diesel(sql_type = Jsonb)]
                value: serde_json::Value,
                #[diesel(sql_type = Jsonb)]
                stream_ref: serde_json::Value,
            }
            let row = sql_query("SELECT s.current_commit_id,s.current_stream_position,s.calendar_schedule_source_value AS value,c.commit_json->'stream_ref' AS stream_ref FROM strand_current_results s JOIN realm_commits c ON c.realm_id=s.realm_id AND c.commit_id=s.current_commit_id AND c.stream_position=s.current_stream_position WHERE s.realm_id=$1 AND s.strand_id=$2 AND s.calendar_schedule_source_value IS NOT NULL")
                .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(selector.strand_id.as_str())
                .get_result::<CalendarRow>(&mut *conn).await.optional()?;
            let Some(row) = row else {
                return Ok(SelfExactCurrentRead::Unresolved(
                    "Calendar current source is not available at this cut",
                ));
            };
            let value: arkret_wire::CalendarScheduleSourceValue =
                serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            match crate::moderation_report_current_results::ensure_scope_member_snapshot(
                conn,
                &request.realm_id,
                &value.effective_scope,
                &caller,
            )
            .await
            {
                Ok(()) => {}
                Err(PersistenceError::NotFound(_)) => return Ok(SelfExactCurrentRead::NotFound),
                Err(error) => return Err(error.into()),
            }
            let stream: CommitStreamRef =
                serde_json::from_value(row.stream_ref).map_err(PersistenceError::database)?;
            let stream_key = crate::authority_commit::stream_key(&stream)?;
            let Some(stream_head) = sql_query("SELECT commit_id,stream_position FROM realm_commits WHERE realm_id=$1 AND stream_key=$2 ORDER BY stream_position DESC LIMIT 1")
                .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(stream_key).get_result::<HeadRow>(&mut *conn).await.optional()? else {
                return Ok(SelfExactCurrentRead::Unresolved("Calendar scope head is unavailable"));
            };
            let revision = CurrentRevision {
                commit_id: row
                    .current_commit_id
                    .parse()
                    .map_err(PersistenceError::database)?,
                stream_position: to_u64(row.current_stream_position, "Calendar current position")?,
            };
            value
                .validate_for_current(&request.realm_id, &stream, &revision)
                .map_err(PersistenceError::database)?;
            return Ok(SelfExactCurrentRead::Answer(
                ExactCurrentResultsReadOutcome::Present {
                    realm_id: request.realm_id.clone(),
                    governance_generation: generation,
                    effective_stream_head: CommitStreamHead {
                        stream_ref: stream.clone(),
                        commit_id: stream_head
                            .commit_id
                            .parse()
                            .map_err(PersistenceError::database)?,
                        stream_position: to_u64(
                            stream_head.stream_position,
                            "Calendar scope head",
                        )?,
                    },
                    entry: ExactCurrentResultEntry::CalendarScheduleSource(
                        CalendarScheduleSourceExactRow {
                            selector: selector.clone(),
                            source_stream_ref: stream,
                            revision,
                            value,
                        },
                    ),
                },
            ));
        }
        ExactCurrentResultSelector::CapabilityGrant(_) => {
            unreachable!("handled before membership gate")
        }
        ExactCurrentResultSelector::AgentInteraction(selector) => {
            use arkret_models_collaboration::agent_interaction::AgentInteractionExactCurrentRow;
            use arkret_models_collaboration::exact_current_results::NeverWrittenExactCurrentSelector;
            if !sql_query("SELECT EXISTS(SELECT 1 FROM member_state_current_results m JOIN realm_commits c ON c.realm_id=m.realm_id AND c.commit_id=m.current_commit_id AND c.stream_position=m.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join' AND e.envelope->'payload' ? 'agent_controller_binding') AS present")
                .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(ActorId::account(selector.agent_account_id.clone()).to_string()).get_result::<ExistsRow>(&mut *conn).await?.present { return Ok(SelfExactCurrentRead::NotFound); }
            let result = crate::agent_interaction_current_results::read_in_connection(
                conn,
                &request.realm_id,
                &selector.agent_account_id,
            )
            .await?;
            let outcome = match result {
                Some(row) => ExactCurrentResultsReadOutcome::Present {
                    realm_id: request.realm_id.clone(),
                    governance_generation: generation,
                    effective_stream_head: head.clone(),
                    entry: ExactCurrentResultEntry::AgentInteraction(
                        AgentInteractionExactCurrentRow {
                            selector: selector.clone(),
                            source_stream_ref: head.stream_ref.clone(),
                            revision: CurrentRevision {
                                commit_id: arkret_wire::RealmCommitId::new(row.current_commit_id)
                                    .map_err(|error| corrupt(error.to_string()))?,
                                stream_position: to_u64(
                                    row.current_stream_position,
                                    "Agent interaction position",
                                )?,
                            },
                            value: serde_json::from_value(row.value)
                                .map_err(|error| corrupt(error.to_string()))?,
                        },
                    ),
                },
                None if crate::agent_interaction_current_results::known_never_written(
                    conn,
                    &request.realm_id,
                    &selector.agent_account_id,
                    head.stream_position,
                )
                .await? =>
                {
                    ExactCurrentResultsReadOutcome::NeverWritten {
                        realm_id: request.realm_id.clone(),
                        governance_generation: generation,
                        effective_stream_head: head,
                        selector: NeverWrittenExactCurrentSelector::AgentInteraction(
                            selector.clone(),
                        ),
                    }
                }
                None => {
                    return Ok(SelfExactCurrentRead::Unresolved(
                        "Agent interaction absence is not confirmed",
                    ));
                }
            };
            outcome
                .validate_for_request(request, generation)
                .map_err(|error| corrupt(error.to_string()))?;
            return Ok(SelfExactCurrentRead::Answer(outcome));
        }
        ExactCurrentResultSelector::Relation(selector) => selector,
        ExactCurrentResultSelector::ModerationState(selector) => {
            return moderation_state_read(
                conn,
                &request.realm_id,
                generation,
                head,
                &caller,
                selector,
            )
            .await;
        }
    };
    let domain_key = arkret_canonical::canonical_json_string(&selector.primary_conflict_domain)
        .map_err(|error| {
            PersistenceError::Internal(format!(
                "Relation primary conflict domain canonicalization failed: {error}"
            ))
        })?;
    let Some(row) = sql_query(RELATION_CURRENT_SQL)
        .bind::<Text, _>(request.realm_id.as_str())
        .bind::<Text, _>(&domain_key)
        .get_result::<CurrentRow>(&mut *conn)
        .await
        .optional()?
    else {
        // Absence of a row cannot prove never_written until the domain's
        // endpoint visibility is decided at this cut.
        return Ok(SelfExactCurrentRead::Unresolved(
            "the Relation domain's endpoint visibility is not proved at this cut",
        ));
    };
    let value = serde_json::from_value::<Relation>(row.value)
        .map_err(|error| corrupt(format!("stored Relation current value is invalid: {error}")))?;
    let source_stream_ref = serde_json::from_value::<CommitStreamRef>(row.stream_ref)
        .map_err(|error| corrupt(format!("stored RealmCommit stream is invalid: {error}")))?;
    let realm_scoped = matches!(
        &value.effective_scope,
        Some(ScopeRef::Realm { realm_id }) if realm_id == &request.realm_id
    );
    if !realm_scoped || source_stream_ref != head.stream_ref {
        return Ok(SelfExactCurrentRead::Unresolved(
            "the Relation's scope visibility is not proved at this cut",
        ));
    }
    let revision = CurrentRevision {
        commit_id: row
            .current_commit_id
            .parse()
            .map_err(|error| corrupt(format!("stored Relation Commit id is invalid: {error}")))?,
        stream_position: to_u64(row.current_stream_position, "Relation stream position")?,
    };
    Ok(SelfExactCurrentRead::Answer(
        ExactCurrentResultsReadOutcome::Present {
            realm_id: request.realm_id.clone(),
            governance_generation: generation,
            effective_stream_head: head,
            entry: ExactCurrentResultEntry::Relation(RelationExactCurrentRow {
                selector: selector.clone(),
                source_stream_ref,
                revision,
                value,
            }),
        },
    ))
}

async fn policy_exact_read(
    conn: &mut AsyncPgConnection,
    request: &ExactCurrentResultsReadRequestBody,
    selector: &arkret_models_collaboration::exact_current_results::PolicyExactCurrentSelector,
    caller: &ActorId,
    generation: u64,
    realm_head: CommitStreamHead,
) -> Result<SelfExactCurrentRead<ExactCurrentResultsReadOutcome>, PgTransactionError> {
    use arkret_models_collaboration::exact_current_results::{
        NeverWrittenExactCurrentSelector, PolicyExactCurrentRow,
    };

    use crate::policy_current_results::ManagementPolicyCurrentRead;
    let current = match crate::policy_current_results::read_management_policy_exact_in_connection(
        conn,
        &request.realm_id,
        &selector.policy_id,
    )
    .await
    {
        Ok(value) => value,
        Err(error)
            if error.conflict_code() == Some(coland_storage::ConflictCode::FailedPrecondition) =>
        {
            return Ok(SelfExactCurrentRead::Unresolved(
                "Policy accepted current proof is unavailable",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    let source = match &current {
        ManagementPolicyCurrentRead::NotFound => return Ok(SelfExactCurrentRead::NotFound),
        ManagementPolicyCurrentRead::NeverWritten => &realm_head.stream_ref,
        ManagementPolicyCurrentRead::Present { source, .. } => source,
    };
    let target =
        crate::policy_current_results::management_policy_scope_target(&request.realm_id, source)?;
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &request.realm_id,
        caller,
    )
    .await?;
    let actions = arkret_schema::capability_actions_for_event_kind(
        arkret_wire::EventKind::PolicySet.as_str(),
    )
    .filter(|action| action.required_evaluator_checks.is_empty())
    .map(|action| action.action.as_str())
    .collect::<Vec<_>>();
    let facts = coland_storage::OperationFacts::default();
    let evaluation = cut.evaluate(&actions, &target, &facts, chrono::Utc::now());
    if evaluation.is_refusal()
        || (!cut.actor_is_root_controller() && evaluation.unreserved().is_empty())
    {
        return Ok(SelfExactCurrentRead::NotFound);
    }
    if let Some(account) = caller.as_account_id()
        && crate::realm_authorization_cut::is_owned_agent_in_connection(
            conn,
            &request.realm_id,
            account,
        )
        .await?
    {
        // An ordinary grant to the Agent cannot bypass its owner's current
        // upper bound merely because this read does not author an Event.
        let check = arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody {
            actor_id: caller.clone(),
            action: arkret_wire::CapabilityActionId::POLICY_SET.to_owned(),
            resource: Some(target.clone()),
            context: None,
        };
        if !crate::realm_authorization_cut::owned_agent_authorization_check_in_connection(
            conn, caller, &check,
        )
        .await?
        .is_some_and(|result| result.decision == arkret_wire::AuthzDecision::Allow)
        {
            return Ok(SelfExactCurrentRead::NotFound);
        }
    }
    let outcome = match current {
        ManagementPolicyCurrentRead::NeverWritten => ExactCurrentResultsReadOutcome::NeverWritten {
            realm_id: request.realm_id.clone(),
            governance_generation: generation,
            effective_stream_head: realm_head,
            selector: NeverWrittenExactCurrentSelector::Policy(selector.clone()),
        },
        ManagementPolicyCurrentRead::Present {
            source,
            revision,
            payload,
            head,
        } => ExactCurrentResultsReadOutcome::Present {
            realm_id: request.realm_id.clone(),
            governance_generation: generation,
            effective_stream_head: *head,
            entry: ExactCurrentResultEntry::Policy(PolicyExactCurrentRow {
                selector: selector.clone(),
                source_stream_ref: source,
                revision,
                value: payload.value,
            }),
        },
        ManagementPolicyCurrentRead::NotFound => {
            unreachable!("non-visible policies return before authorization")
        }
    };
    outcome
        .validate_for_request(request, generation)
        .map_err(PersistenceError::database)?;
    Ok(SelfExactCurrentRead::Answer(outcome))
}
async fn owned_agent_grant_read(
    conn: &mut AsyncPgConnection,
    request: &ExactCurrentResultsReadRequestBody,
    selector: &arkret_models_collaboration::exact_current_results::CapabilityGrantExactCurrentSelector,
    account: &AccountId,
    issuer: &DidCoreId,
) -> Result<SelfExactCurrentRead<ExactCurrentResultsReadOutcome>, PgTransactionError> {
    use arkret_models_collaboration::exact_current_results::CapabilityGrantExactCurrentRow;

    use crate::capability_grant_current_results::{
        CapabilityGrantCurrentResultReadRow, decode_row,
    };
    let owner = serde_json::to_value(ActorId::account(account.clone()))
        .map_err(PersistenceError::database)?;
    let current = sql_query("SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value FROM capability_grant_current_results WHERE realm_id=$1 AND grant_id=$2 AND value->'issuer_id'=$3 AND value->'issuer_authority_refs'->0->>'kind'='owned_agent'")
        .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(selector.grant_id.as_str())
        .bind::<Jsonb,_>(owner)
        .get_result::<CapabilityGrantCurrentResultReadRow>(&mut *conn).await.optional()?.map(decode_row).transpose()?;
    let Some(current) = current.filter(|row| row.value.owned_agent_issuer() == Some(account))
    else {
        return Ok(SelfExactCurrentRead::NotFound);
    };
    let Some(tenure) =
        sql_query("SELECT generation,service_id FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(request.realm_id.as_str())
            .get_result::<TenureRow>(&mut *conn)
            .await
            .optional()?
    else {
        return Ok(SelfExactCurrentRead::NotFound);
    };
    if tenure.service_id != issuer.as_str() {
        return Ok(SelfExactCurrentRead::Unresolved(
            "this Station does not hold the Realm's governing tenure",
        ));
    }
    let stream = CommitStreamRef::Realm {
        realm_id: request.realm_id.clone(),
    };
    let key = crate::authority_commit::stream_key(&stream)?;
    let Some(head) = sql_query("SELECT commit_id,stream_position FROM realm_commits WHERE realm_id=$1 AND stream_key=$2 ORDER BY stream_position DESC LIMIT 1")
        .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(&key).get_result::<HeadRow>(&mut *conn).await.optional()? else {
        return Ok(SelfExactCurrentRead::Unresolved("the Realm stream has no established head"));
    };
    let generation = to_u64(tenure.generation, "governance generation")?;
    let outcome = ExactCurrentResultsReadOutcome::Present {
        realm_id: request.realm_id.clone(),
        governance_generation: generation,
        effective_stream_head: CommitStreamHead {
            stream_ref: stream,
            commit_id: head.commit_id.parse().map_err(PersistenceError::database)?,
            stream_position: to_u64(head.stream_position, "Realm stream position")?,
        },
        entry: ExactCurrentResultEntry::CapabilityGrant(CapabilityGrantExactCurrentRow {
            selector: selector.clone(),
            source_stream_ref: current.source.stream_ref,
            revision: current.revision,
            value: current.value,
        }),
    };
    outcome
        .validate_for_request(request, generation)
        .map_err(|error| corrupt(error.to_string()))?;
    Ok(SelfExactCurrentRead::Answer(outcome))
}

/// A `moderation_state` selector on the provable cut: the durable row keyed
/// by the moderated target. A target no decision ever named has nothing a
/// lift could consume, so it is the same `not_found` as an unknown target;
/// `never_written` is structurally Relation-only.
async fn moderation_state_read(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    generation: u64,
    head: CommitStreamHead,
    caller: &ActorId,
    selector: &ModerationStateExactCurrentSelector,
) -> Result<SelfExactCurrentRead<ExactCurrentResultsReadOutcome>, PgTransactionError> {
    let Some(row) = sql_query(MODERATION_CURRENT_SQL)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(selector.target_ref.as_str())
        .get_result::<CurrentRow>(&mut *conn)
        .await
        .optional()?
    else {
        return Ok(SelfExactCurrentRead::NotFound);
    };
    let value =
        serde_json::from_value::<ModerationStateCurrentValue>(row.value).map_err(|error| {
            corrupt(format!(
                "stored moderation_state current value is invalid: {error}"
            ))
        })?;
    let source_stream_ref = serde_json::from_value::<CommitStreamRef>(row.stream_ref)
        .map_err(|error| corrupt(format!("stored RealmCommit stream is invalid: {error}")))?;
    let head = match &source_stream_ref {
        CommitStreamRef::Realm {
            realm_id: source_realm,
        } if source_realm == realm_id => head,
        CommitStreamRef::Circle {
            realm_id: source_realm,
            circle_id,
        } if source_realm == realm_id => {
            let scope = ScopeRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: circle_id.clone(),
            };
            match crate::moderation_report_current_results::ensure_scope_member_snapshot(
                conn, realm_id, &scope, caller,
            )
            .await
            {
                Ok(()) => {}
                Err(PersistenceError::NotFound(_)) => return Ok(SelfExactCurrentRead::NotFound),
                Err(error) => return Err(error.into()),
            }
            let key = crate::authority_commit::stream_key(&source_stream_ref)?;
            let Some(row) = sql_query("SELECT commit_id,stream_position FROM realm_commits WHERE realm_id=$1 AND stream_key=$2 ORDER BY stream_position DESC LIMIT 1")
                .bind::<Text, _>(realm_id.as_str()).bind::<Text, _>(key).get_result::<HeadRow>(&mut *conn).await.optional()? else {
                return Ok(SelfExactCurrentRead::Unresolved("the Circle stream has no established head"));
            };
            CommitStreamHead {
                stream_ref: source_stream_ref.clone(),
                commit_id: row
                    .commit_id
                    .parse()
                    .map_err(|error| corrupt(format!("invalid Circle head: {error}")))?,
                stream_position: to_u64(row.stream_position, "Circle head")?,
            }
        }
        _ => {
            return Ok(SelfExactCurrentRead::Unresolved(
                "the moderated target's scope visibility is not proved at this cut",
            ));
        }
    };
    if to_u64(
        row.current_stream_position,
        "moderation_state stream position",
    )? > head.stream_position
    {
        return Err(corrupt("moderation_state revision exceeds its exact source head").into());
    }
    let revision = CurrentRevision {
        commit_id: row.current_commit_id.parse().map_err(|error| {
            corrupt(format!(
                "stored moderation_state Commit id is invalid: {error}"
            ))
        })?,
        stream_position: to_u64(
            row.current_stream_position,
            "moderation_state stream position",
        )?,
    };
    Ok(SelfExactCurrentRead::Answer(
        ExactCurrentResultsReadOutcome::Present {
            realm_id: realm_id.clone(),
            governance_generation: generation,
            effective_stream_head: head,
            entry: ExactCurrentResultEntry::ModerationState(ModerationStateExactCurrentRow {
                selector: selector.clone(),
                source_stream_ref,
                revision,
                value,
            }),
        },
    ))
}

pub(crate) async fn strand_watch_current_for_account(
    pool: &PgPool,
    request: &StrandWatchCurrentRequestBody,
    account: &AccountId,
    issuer: &DidCoreId,
) -> PersistenceResult<SelfExactCurrentRead<StrandWatchCurrentOutcome>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        begin_read_cut(conn).await?;
        strand_watch_current_in_connection(conn, request, account, issuer).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn strand_watch_current_in_connection(
    conn: &mut AsyncPgConnection,
    request: &StrandWatchCurrentRequestBody,
    account: &AccountId,
    issuer: &DidCoreId,
) -> Result<SelfExactCurrentRead<StrandWatchCurrentOutcome>, PgTransactionError> {
    strand_watch_observation_in_connection(conn, request, account, issuer, None).await
}

pub(crate) async fn strand_watch_observation_in_connection(
    conn: &mut AsyncPgConnection,
    request: &StrandWatchCurrentRequestBody,
    account: &AccountId,
    issuer: &DidCoreId,
    audit: Option<&arkret_models_collaboration::strand_watch_operations::WatchAuditReadRequest>,
) -> Result<SelfExactCurrentRead<StrandWatchCurrentOutcome>, PgTransactionError> {
    let caller = ActorId::account(account.clone());
    if audit.is_none() && request.watcher_actor_id != caller {
        return Ok(SelfExactCurrentRead::NotFound);
    }
    if let Some(audit) = audit {
        audit.validate().map_err(PersistenceError::database)?;
        if audit.audit_submission.event.actor_id != caller
            || audit.selector().map_err(PersistenceError::database)? != *request
        {
            return Ok(SelfExactCurrentRead::NotFound);
        }
    }
    let (generation, head) = match member_cut(conn, &request.realm_id, &caller, issuer).await? {
        MemberCut::NotVisible => return Ok(SelfExactCurrentRead::NotFound),
        MemberCut::ForeignTenure => {
            return Ok(SelfExactCurrentRead::Unresolved(
                "this Station does not hold the Realm's governing tenure",
            ));
        }
        MemberCut::Member {
            generation,
            realm_head: Some(head),
            ..
        } => (generation, head),
        MemberCut::Member { .. } => {
            return Ok(SelfExactCurrentRead::Unresolved(
                "watch current stream head is unavailable",
            ));
        }
    };
    let Some(strand) = sql_query("SELECT s.current_commit_id,s.current_stream_position,s.value,c.stream_ref FROM strand_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE s.realm_id=$1 AND s.strand_id=$2 AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position")
        .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(request.strand_id.as_str())
        .get_result::<CurrentRow>(&mut *conn).await.optional()? else {
            let orphan = sql_query("SELECT EXISTS(SELECT 1 FROM strand_current_results WHERE realm_id=$1 AND strand_id=$2) AS present")
                .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(request.strand_id.as_str())
                .get_result::<ExistsRow>(&mut *conn).await?.present;
            return Ok(if orphan { SelfExactCurrentRead::Unresolved("Strand covering Commit is unavailable") } else { SelfExactCurrentRead::NotFound });
        };
    if strand
        .value
        .get("state")
        .and_then(serde_json::Value::as_str)
        != Some("active")
    {
        return Ok(SelfExactCurrentRead::NotFound);
    }
    let scope = match strand
        .value
        .get("scope_circle_id")
        .and_then(serde_json::Value::as_str)
    {
        Some(circle) => ScopeRef::Circle {
            realm_id: request.realm_id.clone(),
            circle_id: circle.parse().map_err(PersistenceError::database)?,
        },
        None => ScopeRef::Realm {
            realm_id: request.realm_id.clone(),
        },
    };
    let stream = CommitStreamRef::from_scope(&scope, None).map_err(PersistenceError::database)?;
    if strand.stream_ref != serde_json::to_value(&stream).map_err(PersistenceError::database)? {
        return Ok(SelfExactCurrentRead::Unresolved(
            "Strand source differs from its effective namespace",
        ));
    }
    let head = if let ScopeRef::Circle { circle_id, .. } = &scope {
        let visible = sql_query("SELECT EXISTS(SELECT 1 FROM circle_member_state_current_results m JOIN circle_current_results c ON c.realm_id=m.realm_id AND c.circle_id=m.circle_id JOIN realm_commits mc ON mc.commit_id=m.current_commit_id AND mc.realm_id=m.realm_id AND mc.stream_ref=m.source_stream_ref AND mc.stream_position=m.current_stream_position JOIN realm_commits cc ON cc.commit_id=c.current_commit_id AND cc.realm_id=c.realm_id AND cc.stream_ref=c.source_stream_ref AND cc.stream_position=c.current_stream_position WHERE m.realm_id=$1 AND m.circle_id=$2 AND m.member_id=$3 AND m.membership='join' AND circle_member_parent_join_current(m.realm_id,m.member_id,m.value) AND c.value->>'state'='active') AS present")
            .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(circle_id.as_str()).bind::<Text,_>(caller.to_string()).get_result::<ExistsRow>(&mut *conn).await?.present;
        if !visible && audit.is_none() {
            return Ok(SelfExactCurrentRead::NotFound);
        }
        let key = crate::authority_commit::stream_key(&stream)?;
        let Some(row) = sql_query("SELECT commit_id,stream_position FROM realm_commits WHERE realm_id=$1 AND stream_key=$2 ORDER BY stream_position DESC LIMIT 1")
            .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(key).get_result::<HeadRow>(&mut *conn).await.optional()? else {
                return Ok(SelfExactCurrentRead::Unresolved("Circle watch stream head is unavailable"));
            };
        CommitStreamHead {
            stream_ref: stream,
            commit_id: row.commit_id.parse().map_err(PersistenceError::database)?,
            stream_position: to_u64(row.stream_position, "Circle watch head")?,
        }
    } else {
        head
    };
    if to_u64(strand.current_stream_position, "Strand current position")? > head.stream_position
        || (to_u64(strand.current_stream_position, "Strand current position")?
            == head.stream_position
            && strand.current_commit_id != head.commit_id.as_str())
    {
        return Ok(SelfExactCurrentRead::Unresolved(
            "Strand current is outside the effective stream prefix",
        ));
    }
    crate::agent_management_admission::read_controller_in_connection(
        conn,
        &request.realm_id,
        match &scope {
            ScopeRef::Circle { circle_id, .. } => Some(circle_id),
            _ => None,
        },
        &caller,
    )
    .await?;
    if let Err(error) = crate::strand_watch_current_results::require_current_basis_in_connection(
        conn,
        &request.realm_id,
        &head,
        &request.strand_id,
        &request.watcher_actor_id,
        "",
    )
    .await
    {
        return match error {
            PersistenceError::Conflict(_) => Ok(SelfExactCurrentRead::Unresolved(
                "watch accepted sources or durable current are incomplete",
            )),
            error => Err(error.into()),
        };
    }
    let source = crate::account_content_delivery::current_source_in_connection(
        conn,
        &request.realm_id,
        &head.stream_ref,
        &CurrentRevision {
            commit_id: strand
                .current_commit_id
                .parse()
                .map_err(PersistenceError::database)?,
            stream_position: to_u64(strand.current_stream_position, "Strand current position")?,
        },
    )
    .await?;
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &request.realm_id,
        &caller,
    )
    .await?;
    let owned = crate::realm_authorization_cut::owned_source_in_connection(
        conn,
        &request.realm_id,
        &caller,
        chrono::Utc::now(),
        false,
    )
    .await?;
    let markers = if let Some(audit) = audit {
        crate::registered_audit::read_approval_markers_in_connection(conn, audit).await?
    } else {
        Vec::new()
    };
    if let Err(error) = cut.require_content_read_constraints_with_approvals(
        &source,
        chrono::Utc::now(),
        owned,
        if audit.is_some() {
            arkret_wire::CapabilityActionId::RealmNotificationAudit
        } else {
            arkret_wire::CapabilityActionId::ObjectRead
        },
        &markers,
    ) {
        tracing::debug!(error = %error, "Strand Watch disclosure refused at the accepting cut");
        return Ok(SelfExactCurrentRead::NotFound);
    }
    let selector = StrandWatchCurrentSelector {
        kind: StrandWatchSelectorKind::StrandWatch,
        strand_id: request.strand_id.clone(),
        watcher_actor_id: request.watcher_actor_id.clone(),
    };
    let row = sql_query(WATCH_CURRENT_SQL)
        .bind::<Text, _>(request.realm_id.as_str())
        .bind::<Text, _>(request.strand_id.as_str())
        .bind::<Text, _>(request.watcher_actor_id.to_string())
        .get_result::<CurrentRow>(&mut *conn)
        .await
        .optional()?;
    let outcome = if let Some(row) = row {
        let source_stream_ref: CommitStreamRef =
            serde_json::from_value(row.stream_ref).map_err(PersistenceError::database)?;
        let revision = CurrentRevision {
            commit_id: row
                .current_commit_id
                .parse()
                .map_err(PersistenceError::database)?,
            stream_position: to_u64(row.current_stream_position, "watch current position")?,
        };
        if source_stream_ref != head.stream_ref
            || revision.stream_position > head.stream_position
            || (revision.stream_position == head.stream_position
                && revision.commit_id != head.commit_id)
        {
            return Ok(SelfExactCurrentRead::Unresolved(
                "watch current does not belong to the confirmed stream prefix",
            ));
        }
        StrandWatchCurrentOutcome::Current {
            realm_id: request.realm_id.clone(),
            governance_generation: generation,
            stream_head: head,
            result: StrandWatchCurrentRow {
                selector,
                source_stream_ref,
                revision,
                value: serde_json::from_value(row.value).map_err(PersistenceError::database)?,
            },
        }
    } else {
        let previously_written = sql_query(crate::strand_watch_current_results::WATCH_HISTORY_SQL)
            .bind::<Text, _>(request.realm_id.as_str())
            .bind::<Text, _>(request.strand_id.as_str())
            .bind::<Jsonb, _>(
                serde_json::to_value(&request.watcher_actor_id)
                    .map_err(PersistenceError::database)?,
            )
            .bind::<Text, _>("")
            .get_result::<ExistsRow>(&mut *conn)
            .await?
            .present;
        let orphan_current = sql_query("SELECT EXISTS(SELECT 1 FROM strand_watch_current_results WHERE realm_id=$1 AND strand_id=$2 AND watcher_actor_id=$3) AS present")
            .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(request.strand_id.as_str()).bind::<Text,_>(request.watcher_actor_id.to_string()).get_result::<ExistsRow>(&mut *conn).await?.present;
        if previously_written || orphan_current {
            return Ok(SelfExactCurrentRead::Unresolved(
                "written watch current or tenure import is unavailable",
            ));
        }
        StrandWatchCurrentOutcome::NeverWritten {
            realm_id: request.realm_id.clone(),
            governance_generation: generation,
            stream_head: head,
            selector,
        }
    };
    Ok(SelfExactCurrentRead::Answer(outcome))
}

pub(crate) async fn media_service_anchor_for_account(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
    issuer: &DidCoreId,
) -> PersistenceResult<MediaServiceAnchorRead> {
    let caller = ActorId::account(account.clone());
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        begin_read_cut(conn).await?;
        if matches!(
            member_cut(conn, realm_id, &caller, issuer).await?,
            MemberCut::NotVisible
        ) {
            return Ok(MediaServiceAnchorRead::NotFound);
        }
        let anchored = sql_query(MEDIA_ANCHOR_SQL)
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(arkret_wire::EventKind::RealmMediaService.as_str())
            .get_result::<ExistsRow>(&mut *conn)
            .await?
            .present;
        if !anchored {return Ok(MediaServiceAnchorRead::NotFound);}
        #[derive(QueryableByName)] struct MediaAnchor {#[diesel(sql_type=Jsonb)] value:serde_json::Value,#[diesel(sql_type=Text)] commit_id:String,#[diesel(sql_type=BigInt)] stream_position:i64}
        let row=sql_query("SELECT value,current_commit_id AS commit_id,current_stream_position AS stream_position FROM realm_media_service_current_results WHERE realm_id=$1")
            .bind::<Text,_>(realm_id.as_str()).get_result::<MediaAnchor>(&mut *conn).await.optional()?.ok_or_else(||PersistenceError::Conflict("temporarily_unavailable: accepted media current is incomplete".into()))?;
        let value:arkret_models_collaboration::events_payloads::realm::RealmMediaServiceValue=serde_json::from_value(row.value).map_err(PersistenceError::database)?;
        value.validate().map_err(PersistenceError::database)?;
        Ok(MediaServiceAnchorRead::Anchored{value,revision:arkret_wire::CurrentRevision{commit_id:row.commit_id.parse().map_err(PersistenceError::database)?,stream_position:u64::try_from(row.stream_position).map_err(PersistenceError::database)?}})

    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
