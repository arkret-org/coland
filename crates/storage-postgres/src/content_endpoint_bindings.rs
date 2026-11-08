//! Native endpoint bindings follow the verified RFC leaf, not an Event key.

use std::collections::BTreeMap;

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact;
use arkret_models_collaboration::mls_roster_authority::MlsAddAuthorityAttestation;
use arkret_models_crypto::ContentEndpoint;
use arkret_wire::{MlsGroupValue, MlsWelcomeRecipientEndpoint};
use coland_storage::{AuthorityCommitTransaction, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use horme::RunQueryDsl;
use serde_json::Value;

use crate::AsyncPgConnection;

fn invalid(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.into())
}

#[derive(QueryableByName)]
struct BindingRow {
    #[diesel(sql_type=BigInt)]
    leaf_index: i64,
    #[diesel(sql_type=Jsonb)]
    actor_id: Value,
    #[diesel(sql_type=Nullable<Jsonb>)]
    binding: Option<Value>,
    #[diesel(sql_type=Text)]
    origin_event_ref: String,
    #[diesel(sql_type=Text)]
    origin_signature_key: String,
    #[diesel(sql_type=Text)]
    leaf_signature_key: String,
}

/// The caller verified the RFC transition and installs this with its winner.
pub(crate) async fn install_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> PersistenceResult<()> {
    let event = &transaction.event;
    let installation = transaction
        .mls_state
        .as_ref()
        .ok_or_else(|| invalid("MLS endpoint install has no verified RFC result"))?;
    let key = crate::mls_group_current_states::scope_key(&event.scope_ref)?;
    let old = sql_query("SELECT leaf_index,actor_id,binding,origin_event_ref,origin_signature_key,leaf_signature_key FROM mls_endpoint_current_bindings WHERE scope_key=$1 FOR UPDATE")
        .bind::<Text,_>(&key).get_results::<BindingRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut old: BTreeMap<_, _> = old.into_iter().map(|row| (row.leaf_index, row)).collect();
    let tracker = arkret_mls::MlsPublicGroupTracker::restore(
        &installation.public_state,
        event
            .scope_ref
            .canonical_mls_group_id()
            .map_err(|error| invalid(error.to_string()))?
            .as_str(),
        installation.epoch,
    )
    .map_err(|error| invalid(error.to_string()))?;
    let creator = if event.kind == arkret_wire::EventKind::MlsGenesis {
        Some(
            event
                .as_mls_genesis()
                .map_err(|error| invalid(error.to_string()))?
                .creator_leaf_authority,
        )
    } else {
        None
    };
    let recovery = if event.kind == arkret_wire::EventKind::MlsCommit {
        event
            .as_mls_commit()
            .map_err(|error| invalid(error.to_string()))?
            .recovery_binding()
            .cloned()
    } else {
        None
    };
    sql_query("DELETE FROM mls_endpoint_current_bindings WHERE scope_key=$1")
        .bind::<Text, _>(&key)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    for leaf in tracker
        .leaves()
        .map_err(|error| invalid(error.to_string()))?
    {
        let index = i64::from(leaf.leaf_index);
        let actor = serde_json::to_value(&leaf.actor_id).map_err(PersistenceError::database)?;
        let added = installation.consumed_proposals.iter().any(|proposal| {
            proposal.proposal_type == 1
                && proposal
                    .target_after
                    .as_ref()
                    .is_some_and(|target| target.leaf_index == leaf.leaf_index)
        });
        let previous = old.remove(&index).filter(|previous| {
            previous.actor_id == actor
                && !added
                && !installation.consumed_proposals.iter().any(|proposal| {
                    proposal.proposal_type == 3
                        && proposal.target_before.as_ref().is_some_and(|target| {
                            target.signature_key.as_str() == previous.leaf_signature_key
                        })
                })
        });
        let (mut binding, origin_event, origin_key) = if let Some(creator) = &creator {
            if leaf.actor_id != event.actor_id
                || leaf.signature_key != creator.leaf_signature_key_base64url
            {
                return Err(invalid(
                    "creator endpoint differs from the verified RFC leaf",
                ));
            }
            (
                Some(ContentEndpoint {
                    actor_id: leaf.actor_id.clone(),
                    endpoint: creator.endpoint.clone(),
                    authorization_event_ref: creator.authorization_event_ref.clone(),
                    signature_key_base64url: leaf.signature_key.as_str().to_owned(),
                }),
                event.event_id.to_string(),
                leaf.signature_key.as_str().to_owned(),
            )
        } else if let Some(recovery) = &recovery
            && recovery.replacement.actor_id == leaf.actor_id
            && recovery.replacement.signature_key_base64url == leaf.signature_key.as_str()
        {
            (
                Some(recovery.replacement.clone()),
                event.event_id.to_string(),
                leaf.signature_key.as_str().to_owned(),
            )
        } else if let Some(previous) = previous {
            (
                previous
                    .binding
                    .map(serde_json::from_value::<ContentEndpoint>)
                    .transpose()
                    .map_err(PersistenceError::database)?,
                previous.origin_event_ref,
                previous.origin_signature_key,
            )
        } else {
            // An Add binds only after the native original dual-signature proof.
            (
                None,
                event.event_id.to_string(),
                leaf.signature_key.as_str().to_owned(),
            )
        };
        if let Some(binding) = &mut binding {
            binding.signature_key_base64url = leaf.signature_key.as_str().to_owned();
            binding
                .validate()
                .map_err(|error| invalid(error.to_string()))?;
        }
        sql_query("INSERT INTO mls_endpoint_current_bindings(scope_key,leaf_index,actor_id,leaf_signature_key,binding,origin_event_ref,origin_signature_key,current_event_ref,epoch) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind::<Text,_>(&key).bind::<BigInt,_>(index).bind::<Jsonb,_>(actor).bind::<Text,_>(leaf.signature_key.as_str())
            .bind::<Nullable<Jsonb>,_>(binding.map(serde_json::to_value).transpose().map_err(PersistenceError::database)?)
            .bind::<Text,_>(origin_event).bind::<Text,_>(origin_key).bind::<Text,_>(event.event_id.as_str())
            .bind::<BigInt,_>(i64::try_from(installation.epoch).map_err(PersistenceError::database)?)
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    }
    Ok(())
}

/// Called after both native Add signatures and all original selectors pass.
pub(crate) async fn bind_add_in_connection(
    conn: &mut AsyncPgConnection,
    attestation: &MlsAddAuthorityAttestation,
) -> PersistenceResult<()> {
    let key = crate::mls_group_current_states::scope_key(&attestation.effective_scope)?;
    let rows = sql_query("SELECT leaf_index,actor_id,binding,origin_event_ref,origin_signature_key,leaf_signature_key FROM mls_endpoint_current_bindings WHERE scope_key=$1 AND origin_event_ref=$2 AND origin_signature_key=$3 FOR UPDATE")
        .bind::<Text,_>(&key).bind::<Text,_>(attestation.commit_event_ref.as_str()).bind::<Text,_>(attestation.leaf_signature_key_base64url.as_str())
        .get_results::<BindingRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in rows {
        let binding = ContentEndpoint {
            actor_id: attestation.actor_id.clone(),
            endpoint: attestation.endpoint.clone(),
            authorization_event_ref: attestation.authorization_event_ref.clone(),
            signature_key_base64url: row.leaf_signature_key,
        };
        let value = serde_json::to_value(&binding).map_err(PersistenceError::database)?;
        if row.actor_id
            != serde_json::to_value(&binding.actor_id).map_err(PersistenceError::database)?
            || row
                .binding
                .as_ref()
                .is_some_and(|previous| previous != &value)
        {
            return Err(invalid("native Add cannot rebind another current endpoint"));
        }
        sql_query("UPDATE mls_endpoint_current_bindings SET binding=$3 WHERE scope_key=$1 AND leaf_index=$2")
            .bind::<Text,_>(&key).bind::<BigInt,_>(row.leaf_index).bind::<Jsonb,_>(value)
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    }
    Ok(())
}

fn unavailable(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {}", detail.into()))
}

/// Resolve an independently verified Event producer to its exact current native MLS leaf.
pub(crate) async fn current_producer_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    group: &MlsGroupValue,
) -> PersistenceResult<ContentEndpoint> {
    let (actor, endpoint, authorization) = match transaction.producer_signer_fact.as_ref() {
        None => own_human_pcr_producer(conn, transaction).await?,
        Some(fact) => match fact {
            HistoricalProducerSignerFact::AccountDevice(fact) => (
                fact.actor.clone(),
                MlsWelcomeRecipientEndpoint::Device {
                    device_id: fact.device_id.clone(),
                },
                fact.key.authorization_ref.event_id.clone(),
            ),
            HistoricalProducerSignerFact::AgentRuntime(fact) => (
                fact.actor_id.clone(),
                MlsWelcomeRecipientEndpoint::AgentRuntime {
                    verification_method: fact.verification_method.clone(),
                },
                fact.authorization_event_ref.clone(),
            ),
            HistoricalProducerSignerFact::RealmDevice(fact) => (
                fact.actor_id.clone(),
                MlsWelcomeRecipientEndpoint::Device {
                    device_id: fact.device_id.clone(),
                },
                fact.authorization_event_id.clone(),
            ),
            _ => {
                return Err(unavailable(
                    "producer has no registered application-content endpoint",
                ));
            }
        },
    };
    if actor != *transaction.event.actual_signer() {
        return Err(invalid(
            "content endpoint differs from the original actual signer",
        ));
    }
    let rows = sql_query("SELECT binding AS payload FROM mls_endpoint_current_bindings WHERE scope_key=$1 AND epoch=$2 AND current_event_ref=$3 AND actor_id=$4 AND binding->'endpoint'=$5 AND binding->>'authorization_event_ref'=$6 LIMIT 2 FOR SHARE")
        .bind::<Text,_>(crate::mls_group_current_states::scope_key(&group.effective_scope)?)
        .bind::<diesel::sql_types::BigInt,_>(i64::try_from(group.epoch).map_err(PersistenceError::database)?)
        .bind::<Text,_>(group.current_mls_commit_event_ref.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(&actor).map_err(PersistenceError::database)?)
        .bind::<Jsonb,_>(serde_json::to_value(&endpoint).map_err(PersistenceError::database)?)
        .bind::<Text,_>(authorization.as_str()).get_results::<crate::JsonPayloadRow>(&mut *conn)
        .await.map_err(PersistenceError::database)?;
    if rows.len() != 1 {
        return Err(unavailable(
            "producer has no unique current native MLS endpoint binding",
        ));
    }
    let binding: ContentEndpoint = serde_json::from_value(
        rows.into_iter()
            .next()
            .ok_or_else(|| unavailable("producer binding disappeared"))?
            .payload,
    )
    .map_err(PersistenceError::database)?;
    if binding.actor_id != actor
        || binding.endpoint != endpoint
        || binding.authorization_event_ref != authorization
    {
        return Err(invalid(
            "retained producer binding differs from its exact native source",
        ));
    }
    binding
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    Ok(binding)
}

/// Own-PCR originals use the separately registered self-admission contract,
/// rather than an ordinary collaboration historical-signer fact. Independently
/// verify the accepted Human inception and its current real Device proof; an
/// absent ordinary fact never becomes an authority fallback for another scope.
pub(crate) async fn own_human_pcr_producer(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> PersistenceResult<(
    arkret_wire::ActorId,
    MlsWelcomeRecipientEndpoint,
    arkret_wire::EventId,
)> {
    let event = &transaction.event;
    if event.executed_by.is_some()
        || event.authorization_ref.is_some()
        || event.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(unavailable(
            "content producer has no qualified own-Human PCR role",
        ));
    }
    let origin = crate::pcr_private_authority::accepted_governance(conn, &event.realm_id).await?;
    let arkret_wire::GenesisGovernance::Human(account) = origin else {
        return Err(unavailable(
            "content producer requires its native signer fact",
        ));
    };
    if event.actor_id.as_account_id() != Some(&account) {
        return Err(unavailable(
            "own-PCR producer differs from the accepted full Account",
        ));
    }
    arkret_wire::GenesisGovernance::Human(account.clone())
        .validate_current(
            &transaction.expected_authority.service_id,
            transaction.expected_authority.generation,
        )
        .map_err(|error| unavailable(error.to_string()))?;
    let producer = event
        .account_device_producer()
        .map_err(|error| unavailable(error.to_string()))?
        .ok_or_else(|| unavailable("own-PCR content has no real Human Device producer"))?;
    if producer.account_id != account {
        return Err(unavailable("own-PCR Device producer has another Account"));
    }
    let (cut, _) = crate::actor_profiles::verify_device_signer_in_connection(
        conn,
        event,
        &account,
        &producer.device_id,
        &event.realm_id,
        chrono::Utc::now(),
        event.realm_id.digest_suite_code().digest_suite(),
        "PCR encrypted original",
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?;
    let accepted = cut
        .authority
        .authorization
        .ok_or_else(|| unavailable("own-PCR Device has no current accepted authorization"))?;
    Ok((
        event.actor_id.clone(),
        MlsWelcomeRecipientEndpoint::Device {
            device_id: producer.device_id,
        },
        accepted.event_id,
    ))
}
