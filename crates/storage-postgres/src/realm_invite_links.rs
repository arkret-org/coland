//! Realm invite link admission and immutable use facts at the accepting Realm cut.

use arkret_models_collaboration::governance::realm_invite_link::{
    RealmInviteLinkAcceptPayload, RealmInviteLinkCreatePayload, RealmInviteLinkDefinitionValue,
    RealmInviteLinkLimits, RealmInviteLinkProof, RealmInviteLinkRevokePayload,
    RealmInviteLinkUseRecord,
};
use arkret_wire::{
    AccountId, Event, EventKind, RealmCommit, RealmId, RealmInviteLinkId, RequestId,
};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::Value;

use crate::realm_authorization_cut::{RealmAuthorizationCut, lock_realm_authorization_cut};

#[derive(diesel::QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

fn unavailable() -> PersistenceError {
    PersistenceError::NotFound("Realm invite link not found".into())
}
fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(error.to_string())
}
fn corrupt(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!(
        "invalid accepted Realm invite link source: {error}"
    ))
}
fn payload<T: serde::de::DeserializeOwned>(event: &Event) -> PersistenceResult<T> {
    serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?).map_err(invalid)
}

async fn current(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    link: &RealmInviteLinkId,
    family: &str,
) -> PersistenceResult<Value> {
    diesel::sql_query("SELECT l.value FROM realm_invite_link_current_states l \
        JOIN realm_commits c ON c.commit_id=l.current_commit_id AND c.realm_id=l.realm_id \
          AND c.stream_position=l.current_stream_position \
        JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
        WHERE l.realm_id=$1 AND l.realm_invite_link_id=$2 AND l.state_kind=$3 AND l.subject_account_id='' FOR UPDATE OF l")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(link.as_str()).bind::<Text,_>(family)
        .get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .map(|r|r.value).ok_or_else(unavailable)
}

async fn put(
    conn: &mut AsyncPgConnection,
    commit: &RealmCommit,
    family: &str,
    link: &RealmInviteLinkId,
    account: &str,
    value: Value,
    replacing: bool,
) -> PersistenceResult<()> {
    let sql = if replacing {
        "UPDATE realm_invite_link_current_states SET current_commit_id=$5,current_stream_position=$6,value=$7,updated_at=$8 \
         WHERE realm_id=$1 AND state_kind=$2 AND realm_invite_link_id=$3 AND subject_account_id=$4"
    } else {
        "INSERT INTO realm_invite_link_current_states \
         (realm_id,state_kind,realm_invite_link_id,subject_account_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING"
    };
    let changed = diesel::sql_query(sql)
        .bind::<Text, _>(commit.realm_id.as_str())
        .bind::<Text, _>(family)
        .bind::<Text, _>(link.as_str())
        .bind::<Text, _>(account)
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<BigInt, _>(i64::try_from(commit.stream_position).map_err(invalid)?)
        .bind::<Jsonb, _>(value)
        .bind::<Timestamptz, _>(commit.committed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(unavailable());
    }
    Ok(())
}

async fn definition(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    link: &RealmInviteLinkId,
) -> PersistenceResult<(RealmInviteLinkDefinitionValue, Event)> {
    let definition: RealmInviteLinkDefinitionValue =
        serde_json::from_value(current(conn, realm, link, "realm_invite_link_definition").await?)
            .map_err(corrupt)?;
    let token = crate::ids::parse_event_id(link.event_id().as_str())
        .ok_or_else(|| corrupt("invalid derived ID"))?;
    let source=diesel::sql_query("SELECT e.envelope AS value FROM canonical_events e \
        JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=e.realm_id \
        WHERE e.id=$1 AND e.realm_id=$2 AND e.kind='ak.realm_invite_link.create' AND e.state='committed'")
        .bind::<diesel::sql_types::Binary,_>(token.to_vec()).bind::<Text,_>(realm.as_str())
        .get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||corrupt("definition has no accepted creation Event"))?;
    let source: Event = serde_json::from_value(source.value).map_err(corrupt)?;
    let p: RealmInviteLinkCreatePayload = payload(&source)?;
    if definition.create_event_id != source.event_id
        || definition.creator_actor_id != source.actor_id
        || definition.public_key != p.public_key
        || definition.expires_at != p.expires_at
        || definition.max_uses != p.max_uses
    {
        return Err(corrupt("definition differs from its accepted original"));
    }
    Ok((definition, source))
}

async fn usable(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    link: &RealmInviteLinkId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<RealmInviteLinkDefinitionValue> {
    let (definition, source) = definition(conn, realm, link).await?;
    if current(conn, realm, link, "realm_invite_link_lifecycle").await?
        != Value::String("active".into())
        || at >= definition.expires_at
    {
        return Err(unavailable());
    }
    let creator = RealmAuthorizationCut::read(conn, realm, &source.actor_id).await?;
    creator
        .require_live_invitation_creator(&source, at)
        .map_err(|error| match error {
            PersistenceError::Conflict(_) | PersistenceError::NotFound(_) => unavailable(),
            other => other,
        })?;
    let count = diesel::sql_query(
        "SELECT count(*) AS count FROM realm_invite_link_current_states \
        WHERE realm_id=$1 AND realm_invite_link_id=$2 AND state_kind='realm_invite_link_use'",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(link.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .count;
    if count >= i64::from(definition.max_uses) {
        return Err(unavailable());
    }
    Ok(definition)
}

/// Preview uses an independent purpose and never writes or consumes an allowance.
pub(crate) async fn preview_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    link: &RealmInviteLinkId,
    subject: &AccountId,
    request: &RequestId,
    proof: &RealmInviteLinkProof,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    lock_realm_authorization_cut(conn, realm).await?;
    let definition = usable(conn, realm, link, at).await?;
    arkret_signatures::realm_invite_link::verify_realm_invite_link_proof(
        &definition.public_key,
        proof,
        realm,
        link,
        subject,
        request,
        false,
    )
    .map_err(|_| unavailable())
}

/// Called only for new authority admissions, before the ordinary member current writer.
pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    approvals: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if !matches!(
        event.kind,
        EventKind::RealmInviteLinkCreate
            | EventKind::RealmInviteLinkRevoke
            | EventKind::RealmInviteLinkAccept
    ) {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event).map_err(invalid)?;
    if event.actor_id.as_account_id().is_none()
        || event.executed_by.is_some()
        || event.applet_id.is_some()
        || !matches!(&event.scope_ref,arkret_wire::ScopeRef::Realm{realm_id} if realm_id==&event.realm_id)
        || commit.event_ref != event.event_id
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(unavailable());
    }
    lock_realm_authorization_cut(conn, &event.realm_id).await?;
    match event.kind {
        EventKind::RealmInviteLinkCreate => {
            crate::member_state_admission::require_ordinary_member(
                conn,
                &event.realm_id,
                &event.actor_id,
            )
            .await?;
            crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
                conn, event, commit, approvals,
            )
            .await?;
            let p: RealmInviteLinkCreatePayload = payload(event)?;
            p.validate().map_err(invalid)?;
            arkret_signatures::realm_invite_link::validate_realm_invite_link_public_key(
                &p.public_key,
            )
            .map_err(invalid)?;
            let policy = diesel::sql_query(
                "SELECT value FROM realm_policy_bundle_current_states WHERE realm_id=$1 FOR SHARE",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .get_result::<ValueRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            let limits = policy
                .and_then(|r| r.value.get("invite_link_limits").cloned())
                .map(serde_json::from_value::<RealmInviteLinkLimits>)
                .transpose()
                .map_err(corrupt)?
                .unwrap_or_default();
            limits.validate().map_err(corrupt)?;
            let lifetime = p.expires_at.signed_duration_since(event.created_at);
            if p.expires_at <= commit.committed_at
                || lifetime < chrono::Duration::seconds(60)
                || lifetime > chrono::Duration::seconds(i64::from(limits.max_lifetime_seconds))
                || p.max_uses > limits.max_uses_per_link
            {
                return Err(invalid("Realm invite link exceeds generation limits"));
            }
            let id = RealmInviteLinkId::from_event_id(&event.event_id);
            let definition = RealmInviteLinkDefinitionValue {
                public_key: p.public_key,
                expires_at: p.expires_at,
                max_uses: p.max_uses,
                create_event_id: event.event_id.clone(),
                creator_actor_id: event.actor_id.clone(),
            };
            put(
                conn,
                commit,
                "realm_invite_link_definition",
                &id,
                "",
                serde_json::to_value(definition).map_err(invalid)?,
                false,
            )
            .await?;
            put(
                conn,
                commit,
                "realm_invite_link_lifecycle",
                &id,
                "",
                Value::String("active".into()),
                false,
            )
            .await
        }
        EventKind::RealmInviteLinkRevoke => {
            crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
                conn, event, commit, approvals,
            )
            .await?;
            let p: RealmInviteLinkRevokePayload = payload(event)?;
            definition(conn, &event.realm_id, &p.realm_invite_link_id).await?;
            if current(
                conn,
                &event.realm_id,
                &p.realm_invite_link_id,
                "realm_invite_link_lifecycle",
            )
            .await?
                != Value::String("active".into())
            {
                return Err(unavailable());
            }
            put(
                conn,
                commit,
                "realm_invite_link_lifecycle",
                &p.realm_invite_link_id,
                "",
                Value::String("revoked".into()),
                true,
            )
            .await
        }
        EventKind::RealmInviteLinkAccept => {
            let p: RealmInviteLinkAcceptPayload = payload(event)?;
            if event.actor_id.as_account_id() != Some(&p.subject_account_id) {
                return Err(unavailable());
            }
            let definition = usable(
                conn,
                &event.realm_id,
                &p.realm_invite_link_id,
                commit.committed_at,
            )
            .await?;
            arkret_signatures::realm_invite_link::verify_realm_invite_link_proof(
                &definition.public_key,
                &p.link_proof,
                &event.realm_id,
                &p.realm_invite_link_id,
                &p.subject_account_id,
                &p.request_id,
                true,
            )
            .map_err(|_| unavailable())?;
            crate::member_state_admission::require_invitation_entry(conn, event).await?;
            let subject = String::from_utf8(
                arkret_canonical::canonical_json_bytes(&p.subject_account_id).map_err(invalid)?,
            )
            .map_err(invalid)?;
            let record = RealmInviteLinkUseRecord {
                realm_invite_link_id: p.realm_invite_link_id.clone(),
                subject_account_id: p.subject_account_id,
                accept_event_id: event.event_id.clone(),
            };
            put(
                conn,
                commit,
                "realm_invite_link_use",
                &p.realm_invite_link_id,
                &subject,
                serde_json::to_value(record).map_err(invalid)?,
                false,
            )
            .await
        }
        _ => Ok(()),
    }
}
