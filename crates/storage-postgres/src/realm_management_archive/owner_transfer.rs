//! Stable accepted successor witnesses in the existing private handoff digest.

use arkret_models_collaboration::events_payloads::RealmOwnerTransferPayload;
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{CommittedEventFullView, EventId, EventKind, RealmCommitId};
use diesel::sql_types::Binary;
use serde::{Deserialize, Serialize};

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedSuccessor {
    event_id: EventId,
    commit_id: RealmCommitId,
    successor_device_evidence: AccountDeviceSignerEvidence,
}

fn verify_original(
    realm: &RealmId,
    entry: &AcceptedSuccessor,
    row: &Value,
) -> PersistenceResult<()> {
    let full = CommittedEventFullView {
        event: serde_json::from_value(row["event"].clone()).map_err(invalid)?,
        commit: serde_json::from_value(row["commit"].clone()).map_err(invalid)?,
    };
    full.validate_shape().map_err(invalid)?;
    full.event
        .verify_event_id_matches_content_with_digest_suite(
            full.event.realm_id.digest_suite_code().digest_suite(),
        )
        .map_err(invalid)?;
    full.commit
        .verify_commit_id_matches_content()
        .map_err(invalid)?;
    if full.event.kind != EventKind::RealmOwnerTransfer
        || &full.event.realm_id != realm
        || &full.commit.realm_id != realm
        || full.event.event_id != entry.event_id
        || full.commit.event_ref != entry.event_id
        || full.commit.commit_id != entry.commit_id
        || !matches!(&full.commit.stream_ref, arkret_wire::CommitStreamRef::Realm { realm_id } if realm_id == realm)
    {
        return Err(invalid(
            "successor witness differs from its accepted Realm original",
        ));
    }
    let payload: RealmOwnerTransferPayload =
        serde_json::from_value(serde_json::to_value(&full.event.payload).map_err(invalid)?)
            .map_err(invalid)?;
    let intent = payload
        .acceptance_intent(&full.event.scope_ref, &full.event.actor_id)
        .map_err(invalid)?;
    arkret_identity::account_device_signer_evidence::verify_owner_transfer_successor_evidence(
        &entry.successor_device_evidence,
        &intent,
        &payload.successor_acceptance,
        full.commit.committed_at,
    )
    .map_err(invalid)?;
    Ok(())
}

pub(super) async fn export(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<Value> {
    let rows = sql_query(
        "SELECT jsonb_build_object('event',e.envelope,'commit',c.commit_json, \
         'witness',e.successor_device_evidence_json) AS value \
         FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.realm_id=$1 AND e.kind='ak.realm.owner.transfer' AND e.state='committed' \
         ORDER BY e.envelope->>'event_id',c.commit_id",
    )
    .bind::<Text, _>(realm.as_str())
    .get_results::<JsonRow>(conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut entries = Vec::with_capacity(rows.len());
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let entry = AcceptedSuccessor {
            event_id: serde_json::from_value(row.value["event"]["event_id"].clone())
                .map_err(invalid)?,
            commit_id: serde_json::from_value(row.value["commit"]["commit_id"].clone())
                .map_err(invalid)?,
            successor_device_evidence: serde_json::from_value(row.value["witness"].clone())
                .map_err(|_| {
                    invalid("accepted owner transfer lacks its original successor witness")
                })?,
        };
        if !seen.insert(entry.event_id.clone()) {
            return Err(invalid(
                "owner transfer has multiple accepted Commit bindings",
            ));
        }
        verify_original(realm, &entry, &row.value)?;
        entries.push(entry);
    }
    // SQL uses the database collation; portable order is explicitly UTF-8.
    entries.sort_by(|a, b| {
        a.event_id
            .as_str()
            .as_bytes()
            .cmp(b.event_id.as_str().as_bytes())
            .then_with(|| {
                a.commit_id
                    .as_str()
                    .as_bytes()
                    .cmp(b.commit_id.as_str().as_bytes())
            })
    });
    serde_json::to_value(entries).map_err(invalid)
}

pub(super) async fn import(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    archive: &Value,
) -> PersistenceResult<()> {
    let entries: Vec<AcceptedSuccessor> =
        serde_json::from_value(archive.clone()).map_err(invalid)?;
    let mut previous: Option<(&str, &str)> = None;
    let mut seen = std::collections::BTreeSet::new();
    for entry in &entries {
        let key = (entry.event_id.as_str(), entry.commit_id.as_str());
        if previous.is_some_and(|previous| previous >= key) || !seen.insert(entry.event_id.clone())
        {
            return Err(invalid(
                "successor inventory is duplicated or not in portable order",
            ));
        }
        previous = Some(key);
    }
    for entry in entries {
        let row = sql_query(
            "SELECT jsonb_build_object('event',e.envelope,'commit',c.commit_json, \
             'witness',e.successor_device_evidence_json) AS value \
             FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
             WHERE e.id=$1 AND c.commit_id=$2 AND e.realm_id=$3 \
             AND e.kind='ak.realm.owner.transfer' AND e.state='committed' \
             FOR UPDATE OF e,c",
        )
        .bind::<Binary, _>(entry.event_id.token_bytes().to_vec())
        .bind::<Text, _>(entry.commit_id.as_str())
        .bind::<Text, _>(realm.as_str())
        .get_result::<JsonRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| {
            invalid("successor inventory requires its exact already installed Full original")
        })?;
        verify_original(realm, &entry, &row.value)?;
        let witness = serde_json::to_value(&entry.successor_device_evidence).map_err(invalid)?;
        if row.value["witness"].is_null() {
            let written = sql_query(
                "UPDATE canonical_events SET successor_device_evidence_json=$1 \
                 WHERE id=$2 AND realm_id=$3 AND state='committed' \
                 AND kind='ak.realm.owner.transfer' AND successor_device_evidence_json IS NULL",
            )
            .bind::<Jsonb, _>(&witness)
            .bind::<Binary, _>(entry.event_id.token_bytes().to_vec())
            .bind::<Text, _>(realm.as_str())
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            if written != 1 {
                return Err(invalid(
                    "successor witness could not fill its original empty slot",
                ));
            }
        } else if row.value["witness"] != witness {
            return Err(invalid(
                "accepted successor witness conflicts with the private original",
            ));
        }
    }
    // The enclosing transaction re-exports the entire state and compares its
    // manifest digest. Missing or extra accepted witnesses cannot activate.
    Ok(())
}
