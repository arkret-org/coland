//! Contact command completion keyed by the authority's committed Event ref.

use arkret_models_collaboration::contact_operations::{
    ContactAcceptedOutcome, ContactCurrentProof, ContactPeer, ContactRound,
    ContactRoundEvidenceBundle,
};
use arkret_wire::{ActorId, Hash};
use coland_storage::{
    CommittedContactCompletionIntent, ContactCompletionBinding, ContactCompletionIntent,
    ContactCompletionResult, ContactCompletionState, FederationOutboxRecord, PersistenceError,
    PersistenceResult,
};
use diesel::sql_types::{BigInt, Integer, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

use crate::{PgPool, PgTransactionError, pg_conn};

fn invalid(error: impl ToString) -> PersistenceError {
    PersistenceError::SchemaViolation(error.to_string())
}

#[derive(QueryableByName)]
struct CompletionRow {
    #[diesel(sql_type = Text)]
    event_digest: String,
    #[diesel(sql_type = Jsonb)]
    event_json: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    binding: serde_json::Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    intent: Option<serde_json::Value>,
    #[diesel(sql_type = Text)]
    intent_digest: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    committed_ref: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    result: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Text>)]
    delivery_outbox_id: Option<String>,
}

#[derive(QueryableByName)]
struct ExistingOutbox {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    endpoint: String,
    #[diesel(sql_type = Text)]
    payload_json: String,
}

const COLUMNS: &str =
    "event_digest,event_json,binding,intent,intent_digest,committed_ref,result,delivery_outbox_id";

/// Storage-local domain of the frozen plan digest. It never leaves this table.
const INTENT_DIGEST_DOMAIN: &str = "coland.storage.contact-completion-intent.v1";

/// Canonical digest of the exact frozen business plan. The terminal row keeps
/// it after the plan itself is replaced by the result, so a replay can still be
/// bound to the one plan that produced that result.
fn intent_digest(intent: &ContactCompletionIntent) -> PersistenceResult<String> {
    arkret_canonical::domain_prefixed_canonical_sha256(INTENT_DIGEST_DOMAIN, intent)
        .map_err(invalid)
}

pub(super) async fn lookup(
    pool: &PgPool,
    actor: &ActorId,
    key: &str,
    request_hash: &str,
) -> PersistenceResult<Option<ContactCompletionState>> {
    let mut conn = pg_conn(pool).await?;
    let row = sql_query(format!(
        "SELECT {COLUMNS} FROM contact_completion_intents \
         WHERE binding->'authenticated_actor'=$1 AND binding->>'idempotency_key'=$2"
    ))
    .bind::<Jsonb, _>(serde_json::to_value(actor).map_err(invalid)?)
    .bind::<Text, _>(key)
    .get_result::<CompletionRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    row.map(|row| {
        let binding: ContactCompletionBinding =
            serde_json::from_value(row.binding).map_err(invalid)?;
        if binding.request_hash != request_hash {
            return Err(PersistenceError::Conflict(
                "Contact commit key was used for different canonical bytes".into(),
            ));
        }
        Ok(ContactCompletionState {
            event: serde_json::from_value(row.event_json).map_err(invalid)?,
            result: row
                .result
                .map(serde_json::from_value)
                .transpose()
                .map_err(invalid)?,
        })
    })
    .transpose()
}

pub(super) async fn confirmed(
    pool: &PgPool,
    limit: u16,
    after: Option<&Hash>,
) -> PersistenceResult<Vec<CommittedContactCompletionIntent>> {
    let mut conn = pg_conn(pool).await?;
    let rows = sql_query(format!(
        "SELECT {COLUMNS} FROM contact_completion_intents \
         WHERE committed_ref IS NOT NULL AND intent IS NOT NULL AND result IS NULL \
           AND ($2::text IS NULL OR event_digest>$2) ORDER BY event_digest LIMIT $1"
    ))
    .bind::<BigInt, _>(i64::from(limit))
    .bind::<Nullable<Text>, _>(after.map(Hash::as_str))
    .load::<CompletionRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    rows.into_iter()
        .map(|row| {
            Ok(CommittedContactCompletionIntent {
                event_digest: Hash::new(row.event_digest).map_err(invalid)?,
                committed_ref: serde_json::from_value(
                    row.committed_ref
                        .ok_or_else(|| invalid("Contact committed ref missing"))?,
                )
                .map_err(invalid)?,
                intent: serde_json::from_value(
                    row.intent
                        .ok_or_else(|| invalid("Contact completion intent missing"))?,
                )
                .map_err(invalid)?,
            })
        })
        .collect()
}

/// Stages the contact business plan alongside an already durable authority
/// commit. An exact replay is idempotent; a different plan for the same Event
/// is rejected.
pub(crate) async fn stage_in_transaction(
    conn: &mut AsyncPgConnection,
    committed_ref: &arkret_wire::CommittedEventRef,
    intent: &ContactCompletionIntent,
) -> PersistenceResult<()> {
    let event = &intent.plan.event;
    let event_json = serde_json::to_value(event).map_err(invalid)?;
    let binding = serde_json::to_value(&intent.plan.response_binding).map_err(invalid)?;
    let intent_json = serde_json::to_value(intent).map_err(invalid)?;
    let committed_ref_json = serde_json::to_value(committed_ref).map_err(invalid)?;
    let affected = sql_query(
        "INSERT INTO contact_completion_intents \
         (event_id,event_digest,event_json,binding,intent,intent_digest,committed_ref,created_at) \
         VALUES ($1,$2,$3,$4,$5,$8,$6,$7) \
         ON CONFLICT (event_id) DO UPDATE SET event_id=contact_completion_intents.event_id \
         WHERE contact_completion_intents.event_digest=EXCLUDED.event_digest \
           AND contact_completion_intents.event_json=EXCLUDED.event_json \
           AND contact_completion_intents.binding=EXCLUDED.binding \
           AND contact_completion_intents.intent=EXCLUDED.intent \
           AND contact_completion_intents.intent_digest=EXCLUDED.intent_digest \
           AND contact_completion_intents.committed_ref=EXCLUDED.committed_ref",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(event.event_id.event_digest().as_str())
    .bind::<Jsonb, _>(event_json)
    .bind::<Jsonb, _>(binding)
    .bind::<Jsonb, _>(intent_json)
    .bind::<Jsonb, _>(committed_ref_json)
    .bind::<Timestamptz, _>(intent.accepted_at()?)
    .bind::<Text, _>(intent_digest(intent)?)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if affected != 1 {
        return Err(PersistenceError::Conflict(
            "Contact completion Event is already bound to different bytes".into(),
        ));
    }
    Ok(())
}

pub(super) async fn finalize(
    pool: &PgPool,
    ready: &CommittedContactCompletionIntent,
    result: &ContactCompletionResult,
    delivery: Option<&FederationOutboxRecord>,
    counterpart_proof: Option<&ContactCurrentProof>,
) -> PersistenceResult<bool> {
    ready.intent.validate_event_binding()?;
    let ContactCompletionResult::Accepted { outcome } = result else {
        return Err(invalid(
            "rejected Contact commands do not enter the committed completion queue",
        ));
    };
    ready.intent.validate_finalized_outcome(outcome)?;
    match (ready.intent.requires_delivery(), delivery) {
        (true, Some(delivery)) => {
            validate_destination(&ready.intent.plan.target, delivery)?;
            validate_delivery_payload(&ready.intent, outcome, delivery)?;
        }
        (false, None) => {}
        _ => {
            return Err(invalid(
                "Contact completion changed its delivery obligation",
            ));
        }
    }
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        let row = sql_query(format!(
            "SELECT {COLUMNS} FROM contact_completion_intents WHERE event_digest=$1 FOR UPDATE"
        ))
        .bind::<Text, _>(ready.event_digest.as_str())
        .get_result::<CompletionRow>(conn)
        .await
        .map_err(PersistenceError::database)?;
        // Finalization replaces the staged plan with its result, so the plan is
        // bound through its immutable digest: a concurrent or later replay of
        // the same completion still matches the terminal row, and any other
        // plan for this Event does not.
        if row.committed_ref.as_ref()
            != Some(&serde_json::to_value(&ready.committed_ref).map_err(invalid)?)
            || row.intent_digest != intent_digest(&ready.intent)?
            || row.event_json != serde_json::to_value(&ready.intent.plan.event).map_err(invalid)?
            || row.binding
                != serde_json::to_value(&ready.intent.plan.response_binding).map_err(invalid)?
        {
            return Err(
                invalid("Contact completion does not bind the exact committed Event").into(),
            );
        }
        if let Some(existing) = row.result {
            // The first durable terminal result is fixed. A worker that lost
            // the race for this exact plan may have signed different bytes
            // (signatures carry their own signing time); its result was
            // already proven a valid terminal for this plan above, so it is a
            // lost race, not a conflict. It never replaces the fixed result or
            // delivery, and callers answer from the stored result.
            let same_result = existing == serde_json::to_value(result).map_err(invalid)?;
            let outbox_id = match delivery {
                Some(delivery) => Some(assert_same_outbox(conn, delivery, same_result).await?),
                None => None,
            };
            if outbox_id != row.delivery_outbox_id {
                return Err(invalid("Contact terminal delivery cannot be replaced").into());
            }
            return Ok(false);
        }
        if row.intent.as_ref() != Some(&serde_json::to_value(&ready.intent).map_err(invalid)?) {
            return Err(
                invalid("Contact completion does not bind the exact committed Event").into(),
            );
        }
        let outbox_id = if let Some(delivery) = delivery {
            crate::federation::insert_federation_outbox_row(conn, delivery).await?;
            Some(assert_same_outbox(conn, delivery, true).await?)
        } else {
            None
        };
        install_evidence(conn, &ready.intent, outcome, counterpart_proof).await?;
        persist_result(
            conn,
            ready.event_digest.as_str(),
            &ready.intent.plan.response_binding,
            result,
            outbox_id.as_deref(),
        )
        .await?;
        Ok(true)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// Install the finalized source evidence on the pair row in the transaction
/// that fixes the command's result: the request receipt (and a same-Station
/// target's verified request mirror), a normal round's evidence bundle, or a
/// successor's refreshed directional current proof. A current proof must name
/// the row's exact directional head.
///
/// `counterpart_proof` is the requester direction's proof this Station issued
/// itself when both pair members are its holders; a normal round is complete
/// only with both directions.
async fn install_evidence(
    conn: &mut AsyncPgConnection,
    intent: &ContactCompletionIntent,
    outcome: &ContactAcceptedOutcome,
    counterpart_proof: Option<&ContactCurrentProof>,
) -> PersistenceResult<()> {
    let event = &intent.plan.event;
    let peer: ContactPeer = serde_json::from_value(
        event
            .payload
            .get("peer")
            .cloned()
            .ok_or_else(|| invalid("Contact Event omits peer"))?,
    )
    .map_err(invalid)?;
    let holder = &event.actor_id;
    let peer_actor = peer.contact_actor_id();
    let mut record = crate::contacts::lock_pair_contact_in_connection(conn, holder, &peer_actor)
        .await?
        .ok_or_else(|| invalid("committed Contact row is absent"))?;
    let expected = record.updated_at;
    let head_of = |record: &coland_storage::ContactRecord, issuer: &arkret_wire::ActorId| {
        if &record.requester_id == issuer {
            record.request_event_ref.clone()
        } else {
            record.response_event_ref.clone()
        }
    };
    let binds_head = |record: &coland_storage::ContactRecord, proof: &ContactCurrentProof| {
        let issuer = if proof.peer.contact_actor_id() == record.requester_id {
            &record.target_id
        } else {
            &record.requester_id
        };
        record.contact_round_id.as_ref() == Some(&proof.contact_round_id)
            && head_of(record, issuer).as_ref() == Some(&proof.head_event_ref)
    };
    let mut mirror = None;
    match outcome {
        ContactAcceptedOutcome::Request {
            request_acceptance_receipt: receipt,
            ..
        } => {
            if let Some(prior) = record
                .request_receipts
                .iter()
                .find(|prior| prior.core.request_event_ref == event.event_id)
            {
                if prior != receipt {
                    return Err(invalid("Contact source receipt is immutable"));
                }
            } else {
                record.request_receipts.push(receipt.clone());
            }
            if let Some(target) = &intent.plan.local_mirror_target {
                mirror = Some(coland_storage::ContactVerifiedMirrorRecord {
                    target_holder_principal_id: target.clone(),
                    request_event_id: event.event_id.to_string(),
                    request_digest: event.event_id.event_digest().to_string(),
                    canonical_event_bytes: arkret_canonical::canonical_json_bytes(event)
                        .map_err(invalid)?,
                    source_receipt: receipt.clone(),
                    issuer_id: receipt.core.issuer_id.to_string(),
                    verified_at: intent.accepted_at()?,
                });
            }
        }
        ContactAcceptedOutcome::Response {
            normal_response_acceptance_receipt: receipt,
            current_proof,
            ..
        } => {
            let payload: arkret_models_collaboration::events_payloads::contact::ContactAcceptedPayload =
                serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?)
                    .map_err(invalid)?;
            if !binds_head(&record, current_proof) {
                return Err(PersistenceError::Conflict(
                    "Contact current head changed before signature publication".into(),
                ));
            }
            let mut current_proofs = vec![current_proof.clone()];
            if let Some(counterpart) = counterpart_proof {
                if counterpart.terminal
                    || counterpart.peer != intent.plan.holder
                    || !binds_head(&record, counterpart)
                {
                    return Err(invalid(
                        "Contact requester proof does not bind its accepted request head",
                    ));
                }
                current_proofs.push(counterpart.clone());
            }
            current_proofs.sort_by_key(|proof| proof.peer.contact_actor_id());
            let mut pair = [
                receipt.request_receipt.core.holder.contact_actor_id(),
                receipt.request_receipt.core.peer.contact_actor_id(),
            ];
            if arkret_canonical::canonical_json_bytes(&pair[0]).map_err(invalid)?
                > arkret_canonical::canonical_json_bytes(&pair[1]).map_err(invalid)?
            {
                pair.swap(0, 1);
            }
            record.contact_round_evidence = Some(ContactRoundEvidenceBundle {
                contact_round_id: receipt.contact_round_id.clone(),
                previous_terminal_contact_round_id: payload.previous_terminal_contact_round_id,
                contact_round: ContactRound::Normal {
                    sorted_pair_member_ids: pair,
                    request_event_ref: payload.request_event_ref,
                    request_acceptance_receipt_digest: payload.request_acceptance_receipt_digest,
                },
                request_receipts: vec![receipt.request_receipt.clone()],
                normal_response_receipt: Some(receipt.clone()),
                glare_concurrency_attestations: None,
                current_proofs,
                continuity_checkpoint: record
                    .contact_round_evidence_history
                    .iter()
                    .find_map(|bundle| bundle.continuity_checkpoint.clone()),
            });
        }
        ContactAcceptedOutcome::ScopeUpdate { current_proof, .. }
        | ContactAcceptedOutcome::Tombstone { current_proof, .. } => {
            let terminal = matches!(outcome, ContactAcceptedOutcome::Tombstone { .. });
            if record.contact_round_id.as_ref() != Some(&current_proof.contact_round_id)
                || (!terminal && !binds_head(&record, current_proof))
                || (terminal
                    && record.tombstone_event_ref.as_ref() != Some(&current_proof.head_event_ref))
            {
                return Err(PersistenceError::Conflict(
                    "Contact current head changed before signature publication".into(),
                ));
            }
            let bundle = record
                .contact_round_evidence
                .as_mut()
                .ok_or_else(|| invalid("Contact original round evidence has not completed"))?;
            bundle
                .current_proofs
                .retain(|proof| proof.peer != current_proof.peer);
            bundle.current_proofs.push(current_proof.clone());
            bundle
                .current_proofs
                .sort_by_key(|proof| proof.peer.contact_actor_id());
        }
        ContactAcceptedOutcome::Reject { .. } => return Ok(()),
    }
    record.updated_at = chrono::Utc::now().max(expected + chrono::Duration::microseconds(1));
    crate::unit_of_work::commit_contact_projection(
        conn,
        None,
        coland_storage::ContactProjectionCommit {
            completion_intent: None,
            record,
            expected_updated_at: Some(expected),
            conflict_code: "contact_lineage_conflict".into(),
            verified_mirror: mirror,
            invite_policy: None,
        },
    )
    .await
}

/// Returns the durable outbox row bound to this delivery's peer and
/// idempotency key. `same_payload` also requires its exact bytes; a lost-race
/// worker's own carrier differs only through its own valid signing.
async fn assert_same_outbox(
    conn: &mut AsyncPgConnection,
    delivery: &FederationOutboxRecord,
    same_payload: bool,
) -> PersistenceResult<String> {
    let existing = sql_query(
        "SELECT id,endpoint,payload_json FROM federation_outbox \
         WHERE peer_id=$1 AND idempotency_key=$2 FOR UPDATE",
    )
    .bind::<Text, _>(delivery.peer_id.as_str())
    .bind::<Text, _>(&delivery.idempotency_key)
    .get_result::<ExistingOutbox>(conn)
    .await
    .map_err(PersistenceError::database)?;
    if existing.endpoint != delivery.endpoint
        || (same_payload && existing.payload_json != delivery.payload_json)
    {
        return Err(invalid(
            "Contact delivery idempotency key binds different bytes",
        ));
    }
    Ok(existing.id)
}

async fn persist_result(
    conn: &mut AsyncPgConnection,
    digest: &str,
    binding: &ContactCompletionBinding,
    result: &ContactCompletionResult,
    outbox_id: Option<&str>,
) -> PersistenceResult<()> {
    let (status, body) = match result {
        ContactCompletionResult::Accepted { outcome } => (
            200,
            serde_json::to_value(
                arkret_models_collaboration::contact_operations::ContactOperationOutcome::Accepted {
                    outcome: outcome.as_ref().clone(),
                },
            )
            .map_err(invalid)?,
        ),
        ContactCompletionResult::Rejected { problem } => (
            i32::from(problem.status),
            serde_json::to_value(problem).map_err(invalid)?,
        ),
    };
    let at = chrono::Utc::now();
    let changed = sql_query(
        "INSERT INTO idempotency_keys \
         (actor_key,authenticated_actor,operation_id,idempotency_key,request_hash,response_status,response_body,created_at,expires_at) \
         VALUES($1,$2,'ak.self.contact.command.commit',$3,$4,$5,$6,$7,$8) \
         ON CONFLICT(actor_key,operation_id,idempotency_key) DO UPDATE SET \
           response_body=idempotency_keys.response_body \
         WHERE idempotency_keys.request_hash=EXCLUDED.request_hash \
           AND idempotency_keys.response_status=EXCLUDED.response_status \
           AND idempotency_keys.response_body=EXCLUDED.response_body",
    )
    .bind::<Text, _>(binding.authenticated_actor.canonical_key().map_err(invalid)?)
    .bind::<Jsonb, _>(serde_json::to_value(&binding.authenticated_actor).map_err(invalid)?)
    .bind::<Text, _>(&binding.idempotency_key)
    .bind::<Text, _>(&binding.request_hash)
    .bind::<Integer, _>(status)
    .bind::<Jsonb, _>(body)
    .bind::<Timestamptz, _>(at)
    .bind::<Timestamptz, _>(at + chrono::Duration::hours(24))
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Conflict(
            "Contact commit idempotency terminal conflict".into(),
        ));
    }
    let changed = sql_query(
        "UPDATE contact_completion_intents SET intent=NULL,result=$2,delivery_outbox_id=$3 \
         WHERE event_digest=$1 AND (result IS NULL OR result=$2)",
    )
    .bind::<Text, _>(digest)
    .bind::<Jsonb, _>(serde_json::to_value(result).map_err(invalid)?)
    .bind::<Nullable<Text>, _>(outbox_id)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(invalid("Contact terminal result is immutable"));
    }
    Ok(())
}

/// The delivery must be the exact canonical peer carrier of this result.
fn validate_delivery_payload(
    intent: &ContactCompletionIntent,
    outcome: &arkret_models_collaboration::contact_operations::ContactAcceptedOutcome,
    delivery: &FederationOutboxRecord,
) -> PersistenceResult<()> {
    let carrier = intent.finalized_carrier(outcome)?;
    let bytes = arkret_canonical::canonical_json_bytes(&carrier).map_err(invalid)?;
    if delivery.payload_json.as_bytes() != bytes.as_slice() {
        return Err(invalid(
            "Contact delivery does not carry its finalized result",
        ));
    }
    Ok(())
}

fn validate_destination(
    intent: &coland_storage::ContactDeliveryTarget,
    delivery: &FederationOutboxRecord,
) -> PersistenceResult<()> {
    if delivery.endpoint != "/_arkret/peer/contacts"
        || &delivery.peer_id != intent.contact_address.delivery_station_id()
        || delivery.idempotency_key != intent.idempotency_key.as_str()
    {
        return Err(invalid(
            "Contact delivery destination or idempotency binding changed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
