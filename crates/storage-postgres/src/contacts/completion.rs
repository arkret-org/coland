//! Contact command completion keyed by the authority's committed Event ref.

use arkret_models_collaboration::contact_operations::{
    ContactAcceptedOutcome, ContactCurrentProof,
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
            validate_delivery_payload(&ready.intent, outcome, delivery, counterpart_proof)?;
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
        Box::pin(install_evidence(
            conn,
            &ready.intent,
            outcome,
            counterpart_proof,
        ))
        .await?;
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
/// `counterpart_proof` confirms the other local direction when this Station
/// hosts both pair members, for normal acceptance or a terminal fence.
async fn install_evidence(
    conn: &mut AsyncPgConnection,
    intent: &ContactCompletionIntent,
    outcome: &ContactAcceptedOutcome,
    counterpart_proof: Option<&ContactCurrentProof>,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::contact_operations::*;
    let event = &intent.plan.event;
    let peer: ContactPeer = serde_json::from_value(
        event
            .payload
            .get("peer")
            .cloned()
            .ok_or_else(|| invalid("Contact peer missing"))?,
    )
    .map_err(invalid)?;
    let mut record = crate::contacts::lock_pair_contact_in_connection(
        conn,
        &event.actor_id,
        &peer.contact_actor_id(),
    )
    .await?
    .ok_or_else(|| invalid("committed Contact row absent"))?;
    let expected = record.updated_at;
    let (operation, proof) = match outcome {
        ContactAcceptedOutcome::Request {
            request_acceptance_receipt,
            ..
        } => (
            ContactOperationEvidence::Request {
                signed_event: event.clone(),
                request_receipt: request_acceptance_receipt.clone(),
            },
            None,
        ),
        ContactAcceptedOutcome::Response {
            normal_response_acceptance_receipt,
            current_proof,
            ..
        } => (
            ContactOperationEvidence::Response {
                signed_event: event.clone(),
                response_receipt: normal_response_acceptance_receipt.clone(),
            },
            Some(current_proof),
        ),
        ContactAcceptedOutcome::Reject {
            reject_acceptance_receipt,
            ..
        } => (
            ContactOperationEvidence::Reject {
                signed_event: event.clone(),
                reject_receipt: reject_acceptance_receipt.clone(),
            },
            None,
        ),
        ContactAcceptedOutcome::ScopeUpdate {
            lineage,
            current_proof,
            ..
        } => (
            ContactOperationEvidence::ScopeUpdate {
                signed_event: event.clone(),
                lineage: lineage.clone(),
            },
            Some(current_proof),
        ),
        ContactAcceptedOutcome::Tombstone {
            lineage,
            current_proof,
            ..
        } => (
            ContactOperationEvidence::Tombstone {
                signed_event: event.clone(),
                lineage: lineage.clone(),
            },
            Some(current_proof),
        ),
    };
    let cursor = record
        .request_slot_states
        .iter_mut()
        .find(|slot| slot.owner_id == event.actor_id)
        .ok_or_else(|| invalid("Contact operation cursor missing"))?;
    if cursor.head_event_ref != event.event_id || cursor.version != operation.version() {
        return Err(PersistenceError::Conflict(
            "Contact head changed before source evidence publication".into(),
        ));
    }
    let original_digest =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&operation).map_err(invalid)?)
            .map_err(invalid)?;
    if cursor
        .operation_digest
        .as_ref()
        .is_some_and(|known| known != &original_digest)
    {
        return Err(invalid(
            "same operation version changes frozen source confirmation",
        ));
    }
    cursor.operation_digest = Some(original_digest);
    record
        .current_state
        .apply_confirmed(operation.clone())
        .map_err(invalid)?;
    let mut mirror = None;
    if let ContactOperationEvidence::Request {
        request_receipt, ..
    } = &operation
    {
        if let Some(prior) = record
            .request_receipts
            .iter()
            .find(|prior| prior.core.request_event_ref == event.event_id)
        {
            if prior != request_receipt {
                return Err(invalid("Contact original source receipt immutable"));
            }
        } else {
            record.request_receipts.push(request_receipt.clone());
        }
        if let Some(target) = &intent.plan.local_mirror_target {
            mirror = Some(coland_storage::ContactVerifiedMirrorRecord {
                target_holder_principal_id: target.clone(),
                request_event_id: event.event_id.to_string(),
                request_digest: event.event_id.event_digest().to_string(),
                canonical_event_bytes: arkret_canonical::canonical_json_bytes(event)
                    .map_err(invalid)?,
                source_receipt: request_receipt.clone(),
                issuer_id: request_receipt.core.issuer_id.to_string(),
                verified_at: intent.accepted_at()?,
            });
        }
    }
    if let ContactOperationEvidence::Response {
        response_receipt, ..
    } = &operation
    {
        let original = record
            .current_state
            .directions
            .iter()
            .find(|d| {
                d.head_operation.event().event_id
                    == response_receipt.request_receipt.core.request_event_ref
            })
            .ok_or_else(|| invalid("normal round original request unavailable"))?
            .head_operation
            .event()
            .clone();
        let mut pair = [
            response_receipt
                .request_receipt
                .core
                .holder
                .contact_actor_id(),
            response_receipt
                .request_receipt
                .core
                .peer
                .contact_actor_id(),
        ];
        if arkret_canonical::canonical_json_bytes(&pair[0]).map_err(invalid)?
            > arkret_canonical::canonical_json_bytes(&pair[1]).map_err(invalid)?
        {
            pair.swap(0, 1);
        }
        let basis = ContactRoundBasis {
            contact_round_id: response_receipt.contact_round_id.clone(),
            contact_round: ContactRound::Normal {
                sorted_pair_member_ids: pair,
                request_event_ref: original.event_id.clone(),
                request_acceptance_receipt_digest: response_receipt
                    .request_receipt
                    .computed_receipt_digest()
                    .map_err(invalid)?,
            },
            request_receipts: vec![response_receipt.request_receipt.clone()],
            normal_response_receipt: Some(response_receipt.clone()),
            glare_concurrency_attestations: None,
        };
        record
            .current_state
            .establish(basis, vec![original, event.clone()])
            .map_err(invalid)?;
    }
    if let ContactOperationEvidence::Tombstone { lineage, .. } = &operation {
        record
            .current_state
            .close_round(ContactRoundClosure {
                contact_round_id: lineage
                    .contact_round_id
                    .clone()
                    .ok_or_else(|| invalid("tombstone round missing"))?,
                operation: ContactTombstoneEvidence {
                    kind: ContactTombstoneEvidenceKind::Tombstone,
                    signed_event: event.clone(),
                    lineage: lineage.clone(),
                },
            })
            .map_err(invalid)?;
    }
    if let Some(proof) = proof {
        proof.validate_shape().map_err(invalid)?;
        let own = record
            .current_state
            .directions
            .iter_mut()
            .find(|d| d.head_operation.holder() == &intent.plan.holder)
            .ok_or_else(|| invalid("source direction missing"))?;
        if proof.trust_domain_id != *operation.trust_domain_id()
            || proof.initial_contact_round_id
                != record
                    .current_state
                    .initial_identity
                    .as_ref()
                    .map(|i| i.round.contact_round_id.clone())
            || proof.contact_round_id
                != record
                    .current_state
                    .round_basis
                    .as_ref()
                    .map(|r| r.contact_round_id.clone())
            || proof.holder != intent.plan.holder
            || proof.peer != peer
            || proof.head_event_ref != event.event_id
            || proof.version != operation.version()
            || proof.scope_instances != own.scope_instances
        {
            return Err(invalid(
                "source current differs from installed exact direction",
            ));
        }
        own.current_proof = Some(proof.clone());
    }
    if let Some(proof) = counterpart_proof {
        proof.validate_shape().map_err(invalid)?;
        if proof.holder.delivery_station_id() != &proof.issuer_id
            || proof.trust_domain_id != *operation.trust_domain_id()
            || proof.initial_contact_round_id
                != record
                    .current_state
                    .initial_identity
                    .as_ref()
                    .map(|i| i.round.contact_round_id.clone())
            || proof.contact_round_id
                != record
                    .current_state
                    .round_basis
                    .as_ref()
                    .map(|r| r.contact_round_id.clone())
        {
            return Err(invalid(
                "additional source proof changes direction domain or fixed identity",
            ));
        }
        let direction = record
            .current_state
            .directions
            .iter_mut()
            .find(|d| d.head_operation.holder() == &proof.holder)
            .ok_or_else(|| invalid("counterpart original operation missing"))?;
        if direction.head_operation.event().event_id != proof.head_event_ref
            || direction.head_operation.version() != proof.version
            || direction.scope_instances != proof.scope_instances
        {
            return Err(invalid("counterpart current changes original own head"));
        }
        direction.current_proof = Some(proof.clone());
    }
    record.contact_round_evidence = record.current_state.evidence_bundle().ok();
    record.updated_at = chrono::Utc::now().max(expected + chrono::Duration::microseconds(1));
    Box::pin(crate::unit_of_work::commit_contact_projection(
        conn,
        None,
        coland_storage::ContactProjectionCommit {
            completion_intent: None,
            record: Box::new(record),
            expected_updated_at: Some(expected),
            conflict_code: "contact_lineage_conflict".into(),
            verified_mirror: mirror,
            invite_policy: None,
        },
    ))
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
         VALUES($1,$2,'org.arkret.coland.contact.commit.v1',$3,$4,$5,$6,$7,$8) \
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
    additional_proof: Option<&ContactCurrentProof>,
) -> PersistenceResult<()> {
    let mut carrier = intent.finalized_carrier(outcome)?;
    if let arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody::Request { current_proof, .. } = &mut carrier { *current_proof = additional_proof.cloned(); }
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
