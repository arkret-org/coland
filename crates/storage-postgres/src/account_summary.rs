//! Account summary rows derived from a Realm's typed current results.
//!
//! The only writer of `account_summary_current` and `account_summary_versions`.
//! Every authority transaction that changes one of the inputs -- member state,
//! the Realm profile, or the default Strand pointer -- calls
//! [`publish_realm_account_summary_in_connection`] after installing its typed
//! current rows, so the summary shares the Commit's transaction and a failed
//! Commit leaves no summary behind.

use arkret_models_collaboration::events_payloads::realm::RealmProfile;
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Bool, Jsonb, Nullable, Text};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct MemberRow {
    #[diesel(sql_type = Text)]
    member_id: String,
    #[diesel(sql_type = Text)]
    membership: String,
}

#[derive(diesel::QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct SummaryRow {
    #[diesel(sql_type = Text)]
    actor_key: String,
    #[diesel(sql_type = Nullable<Text>)]
    membership: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    title: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    default_strand_id: Option<String>,
    #[diesel(sql_type = Bool)]
    available: bool,
}

#[derive(diesel::QueryableByName)]
struct RevisionRow {
    #[diesel(sql_type = BigInt)]
    revision: i64,
}

#[derive(Debug, PartialEq, Eq)]
struct Summary {
    membership: Option<&'static str>,
    title: Option<String>,
    default_strand_id: Option<String>,
}

/// Whether an accepted Event of `kind` can change an account summary input.
pub(crate) fn changes_account_summary_inputs(kind: &arkret_wire::EventKind) -> bool {
    matches!(
        *kind,
        arkret_wire::EventKind::MemberState
            | arkret_wire::EventKind::InviteAccept
            | arkret_wire::EventKind::RealmInviteLinkAccept
            | arkret_wire::EventKind::RealmProfile
            | arkret_wire::EventKind::RealmSetDefaultStrand
    )
}

fn malformed(detail: &str) -> PersistenceError {
    PersistenceError::Internal(format!("account summary input is malformed: {detail}"))
}

fn visible_membership(membership: &str) -> PersistenceResult<Option<&'static str>> {
    match membership {
        "join" => Ok(Some("join")),
        "knock" => Ok(Some("knock")),
        "leave" | "ban" => Ok(None),
        _ => Err(malformed("unknown membership")),
    }
}

fn derive(
    membership: &str,
    title: Option<&str>,
    default_strand_id: Option<&str>,
) -> PersistenceResult<Summary> {
    let membership = visible_membership(membership)?;
    // Realm details are disclosed only to joined members; a knock row names
    // the Realm and nothing else.
    let joined = membership == Some("join");
    Ok(Summary {
        membership,
        title: title.filter(|_| joined).map(str::to_owned),
        default_strand_id: default_strand_id.filter(|_| joined).map(str::to_owned),
    })
}

async fn realm_title(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<String>> {
    let row = diesel::sql_query(
        "SELECT value FROM realm_bootstrap_current_states \
         WHERE realm_id=$1 AND state_family='realm_profile'",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<ValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    row.map(|row| {
        serde_json::from_value::<RealmProfile>(row.value)
            .map(|profile| profile.title)
            .map_err(|_| malformed("realm_profile"))
    })
    .transpose()
}

async fn realm_default_strand_id(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<String>> {
    let row = diesel::sql_query(
        "SELECT value FROM realm_set_default_strand_current_states WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<ValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    row.map(|row| {
        row.value
            .get("default_strand_id")
            .and_then(Value::as_str)
            .and_then(|id| arkret_wire::StrandId::new(id.to_owned()).ok())
            .map(|id| id.to_string())
            .ok_or_else(|| malformed("realm_set_default_strand"))
    })
    .transpose()
}

/// Recompute every member's account summary for `realm_id` from the typed
/// current rows this transaction can see, and publish the rows that changed
/// under one revision of the account summary clock.
///
/// The caller holds the Realm authority row lock through its authority
/// transaction, so concurrent writers of the same Realm's inputs serialize.
/// Taking the revision from the single clock row inside this transaction
/// keeps revisions gap-free and ordered by commit.
pub(crate) async fn publish_realm_account_summary_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<()> {
    let members = diesel::sql_query(
        "SELECT member_id,membership FROM member_state_current_states \
         WHERE realm_id=$1 ORDER BY member_id COLLATE \"C\"",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<MemberRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if members.is_empty() {
        return Ok(());
    }
    let title = realm_title(conn, realm_id).await?;
    let default_strand_id = realm_default_strand_id(conn, realm_id).await?;
    let existing = diesel::sql_query(
        "SELECT actor_key,membership,title,default_strand_id,available \
         FROM account_summary_current WHERE realm_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<SummaryRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .into_iter()
    .map(|row| {
        (
            row.actor_key,
            (
                row.membership,
                row.title,
                row.default_strand_id,
                row.available,
            ),
        )
    })
    .collect::<std::collections::BTreeMap<_, _>>();
    let mut changed = Vec::new();
    for member in members {
        let summary = derive(
            &member.membership,
            title.as_deref(),
            default_strand_id.as_deref(),
        )?;
        let unchanged = match existing.get(&member.member_id) {
            Some((membership, title, default_strand_id, available)) => {
                *available
                    && membership.as_deref() == summary.membership
                    && *title == summary.title
                    && *default_strand_id == summary.default_strand_id
            }
            // A departed actor this Station never summarized has nothing to
            // withdraw.
            None => summary.membership.is_none(),
        };
        if !unchanged {
            changed.push((member.member_id, summary));
        }
    }
    if changed.is_empty() {
        return Ok(());
    }
    let revision = diesel::sql_query(
        "UPDATE account_summary_clock SET revision=revision+1 WHERE singleton RETURNING revision",
    )
    .get_result::<RevisionRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .revision;
    for (actor_key, summary) in changed {
        diesel::sql_query(
            "UPDATE account_summary_versions SET valid_until=$3 \
             WHERE actor_key=$1 AND realm_id=$2 AND valid_until IS NULL",
        )
        .bind::<Text, _>(&actor_key)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<BigInt, _>(revision)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        diesel::sql_query(
            "INSERT INTO account_summary_versions \
             (actor_key,realm_id,revision,activity_position,membership,title,default_strand_id,invalidated) \
             VALUES($1,$2,$3,$3,$4,$5,$6,FALSE)",
        )
        .bind::<Text, _>(&actor_key)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<BigInt, _>(revision)
        .bind::<Nullable<Text>, _>(summary.membership)
        .bind::<Nullable<Text>, _>(summary.title.as_deref())
        .bind::<Nullable<Text>, _>(summary.default_strand_id.as_deref())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        diesel::sql_query(
            "INSERT INTO account_summary_current \
             (actor_key,realm_id,revision,membership,title,default_strand_id,available) \
             VALUES($1,$2,$3,$4,$5,$6,TRUE) \
             ON CONFLICT(actor_key,realm_id) DO UPDATE SET revision=EXCLUDED.revision, \
             membership=EXCLUDED.membership,title=EXCLUDED.title, \
             default_strand_id=EXCLUDED.default_strand_id,available=TRUE",
        )
        .bind::<Text, _>(&actor_key)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<BigInt, _>(revision)
        .bind::<Nullable<Text>, _>(summary.membership)
        .bind::<Nullable<Text>, _>(summary.title.as_deref())
        .bind::<Nullable<Text>, _>(summary.default_strand_id.as_deref())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_joined_members_carry_realm_details() {
        let strand = "ak:strand:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(
            derive("join", Some("Title"), Some(strand)).unwrap(),
            Summary {
                membership: Some("join"),
                title: Some("Title".to_owned()),
                default_strand_id: Some(strand.to_owned()),
            }
        );
        assert_eq!(
            derive("knock", Some("Title"), Some(strand)).unwrap(),
            Summary {
                membership: Some("knock"),
                title: None,
                default_strand_id: None,
            }
        );
        for terminal in ["leave", "ban"] {
            assert_eq!(
                derive(terminal, Some("Title"), Some(strand)).unwrap(),
                Summary {
                    membership: None,
                    title: None,
                    default_strand_id: None,
                }
            );
        }
        assert!(derive("invite", None, None).is_err());
    }
}
