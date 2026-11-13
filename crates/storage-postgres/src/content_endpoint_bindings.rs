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
    let group = crate::mls_group_current_states::locked_group(conn, &key)
        .await?
        .ok_or_else(|| invalid("endpoint install has no accepted group current"))?;
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
        if previous
            .as_ref()
            .is_none_or(|previous| previous.leaf_signature_key != leaf.signature_key.as_str())
        {
            crate::content_recovery_fence::require_unfenced(conn, &leaf.actor_id).await?;
        }
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
            crate::content_endpoint_history::record(
                conn,
                &event.scope_ref,
                &group.value.genesis_event_ref,
                binding,
                &event.event_id,
            )
            .await?;
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
    crate::content_endpoint_history::record_add(conn, attestation).await?;
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
    if let Some(fact) = transaction.producer_signer_fact.as_ref() {
        return current_producer_from_fact_in_connection(conn, &transaction.event, fact, group)
            .await;
    }
    let (actor, endpoint, authorization) = if let Some(producer) = local_agent_producer(
        conn,
        &transaction.event,
        &transaction.expected_authority.service_id,
        group,
    )
    .await?
    {
        producer
    } else {
        own_human_pcr_producer(conn, transaction).await?
    };
    current_endpoint_in_connection(
        conn,
        &transaction.event,
        group,
        actor,
        endpoint,
        authorization,
    )
    .await
}

/// Ordinary local Agent originals have a native runtime guard, not the
/// Human historical-fact adapter. Resolve the already installed leaf's exact
/// authorization, then repeat its current PCR and original signature checks.
async fn local_agent_producer(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    service_id: &arkret_wire::DidCoreId,
    group: &MlsGroupValue,
) -> PersistenceResult<
    Option<(
        arkret_wire::ActorId,
        MlsWelcomeRecipientEndpoint,
        arkret_wire::EventId,
    )>,
> {
    use horme::OptionalExtension as _;
    let Some(account) = event.actual_signer().as_account_id() else {
        return Ok(None);
    };
    let pcr = sql_query("SELECT to_jsonb(pcr_realm_id) AS payload FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<crate::JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(pcr) = pcr else { return Ok(None) };
    let pcr: arkret_wire::RealmId =
        serde_json::from_value(pcr.payload).map_err(PersistenceError::database)?;
    if crate::pcr_private_authority::accepted_governance(conn, &pcr).await?
        != arkret_wire::GenesisGovernance::Agent(account.clone())
    {
        return Ok(None);
    }
    if &account.station_id != service_id || event.executed_by.is_some() || event.realm_id == pcr {
        return Err(unavailable(
            "Agent content requires its own local ordinary runtime source",
        ));
    }
    // Resource authority is independently checked by native Event admission.
    // In particular a Direct participant must carry its registered authority
    // ref; that ref is not the runtime key's authorization instance below.
    crate::content_recovery_fence::require_unfenced(conn, event.actual_signer()).await?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| unavailable("Agent content has no producer proof"))?;
    let endpoint = MlsWelcomeRecipientEndpoint::AgentRuntime {
        verification_method: proof.verification_method.clone(),
    };
    let rows = sql_query("SELECT binding AS payload FROM mls_endpoint_current_bindings WHERE scope_key=$1 AND epoch=$2 AND current_event_ref=$3 AND actor_id=$4 AND binding->'endpoint'=$5 LIMIT 2 FOR SHARE")
        .bind::<Text,_>(crate::mls_group_current_states::scope_key(&group.effective_scope)?)
        .bind::<BigInt,_>(i64::try_from(group.epoch).map_err(PersistenceError::database)?)
        .bind::<Text,_>(group.current_mls_commit_event_ref.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(event.actual_signer()).map_err(PersistenceError::database)?)
        .bind::<Jsonb,_>(serde_json::to_value(&endpoint).map_err(PersistenceError::database)?)
        .get_results::<crate::JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if rows.len() != 1 {
        return Err(unavailable(
            "Agent content has no unique admitted current runtime leaf",
        ));
    }
    let binding: ContentEndpoint = serde_json::from_value(rows.into_iter().next().unwrap().payload)
        .map_err(PersistenceError::database)?;
    binding
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    let authorization = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &binding.authorization_event_ref,
    )
    .await?
    .ok_or_else(|| unavailable("Agent content authorization original is unavailable"))?;
    if authorization.event.realm_id != pcr
        || authorization.event.actor_id != *event.actual_signer()
        || binding.actor_id != *event.actual_signer()
        || binding.endpoint != endpoint
    {
        return Err(unavailable(
            "Agent content leaf differs from its native Account and PCR",
        ));
    }
    crate::mls_keypackage_claim_endpoints::agent(
        conn,
        &account.principal_id,
        &proof.verification_method,
        &binding.authorization_event_ref,
    )
    .await?
    .require_current(conn)
    .await?;
    let payload: arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload =
        serde_json::from_value(
            serde_json::to_value(&authorization.event.payload)
                .map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
    if event.created_at < payload.issued_at
        || payload
            .expires_at
            .is_some_and(|end| event.created_at >= end)
    {
        return Err(unavailable(
            "Agent content is outside its original authorization window",
        ));
    }
    let key = arkret_signatures::agent::validate_agent_runtime_public_key(
        &payload.public_key,
        &proof.verification_method,
    )
    .map_err(|error| invalid(error.to_string()))?;
    let suite = event.realm_id.digest_suite_code().digest_suite();
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(|error| invalid(error.to_string()))?;
    event
        .verify_producer_proof_self_consistency(suite)
        .map_err(|error| invalid(error.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(event)
            .map_err(|error| invalid(error.to_string()))?,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.raw_public_key.to_vec(),
        },
        suite,
    )
    .map_err(|error| invalid(error.to_string()))?;
    Ok(Some((
        event.actual_signer().clone(),
        endpoint,
        binding.authorization_event_ref,
    )))
}

/// The caller independently qualified this original producer at its native
/// source cut. No target Commit or synthetic governance transaction is needed.
pub(crate) async fn current_producer_from_fact_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    fact: &HistoricalProducerSignerFact,
    group: &MlsGroupValue,
) -> PersistenceResult<ContentEndpoint> {
    let (actor, endpoint, authorization) = match fact {
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
    };
    current_endpoint_in_connection(conn, event, group, actor, endpoint, authorization).await
}

async fn current_endpoint_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    group: &MlsGroupValue,
    actor: arkret_wire::ActorId,
    endpoint: MlsWelcomeRecipientEndpoint,
    authorization: arkret_wire::EventId,
) -> PersistenceResult<ContentEndpoint> {
    if actor != *event.actual_signer() {
        return Err(invalid(
            "content endpoint differs from the original actual signer",
        ));
    }
    current_exact_endpoint_in_connection(conn, group, actor, endpoint, authorization).await
}

pub(crate) async fn native_backup_endpoint_in_connection(
    conn: &mut AsyncPgConnection,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    group: &MlsGroupValue,
) -> PersistenceResult<ContentEndpoint> {
    current_exact_endpoint_in_connection(
        conn,
        group,
        authority.actor_id.clone(),
        MlsWelcomeRecipientEndpoint::Device {
            device_id: authority.device_id.clone(),
        },
        authority.authorization_ref.event_id.clone(),
    )
    .await
}

async fn current_exact_endpoint_in_connection(
    conn: &mut AsyncPgConnection,
    group: &MlsGroupValue,
    actor: arkret_wire::ActorId,
    endpoint: MlsWelcomeRecipientEndpoint,
    authorization: arkret_wire::EventId,
) -> PersistenceResult<ContentEndpoint> {
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

/// Requalify the accepted request's original native signer and its current
/// exact leaf. A retained request or leaf row alone is never current authority.
pub(crate) async fn current_history_recipient_in_connection(
    conn: &mut AsyncPgConnection,
    original: &arkret_wire::CommittedEventFullView,
    group: &MlsGroupValue,
    native_station: &arkret_wire::DidCoreId,
) -> PersistenceResult<ContentEndpoint> {
    let request = original
        .event
        .as_mls_history_request()
        .map_err(|error| invalid(error.to_string()))?;
    let recipient = &request.recipient;
    let fact = crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
        conn,
        &original.event,
        &original.commit,
    )
    .await?;
    let mut original_runtime_qualified = false;
    if let Some(fact) = fact.as_ref() {
        let bound =
            current_producer_from_fact_in_connection(conn, &original.event, fact, group).await?;
        if &bound != recipient {
            return Err(unavailable(
                "history request native producer differs from its exact recipient",
            ));
        }
    } else if let Some((actor, endpoint, authorization)) =
        local_agent_producer(conn, &original.event, native_station, group).await?
    {
        if actor != recipient.actor_id
            || endpoint != recipient.endpoint
            || authorization != recipient.authorization_event_ref
        {
            return Err(unavailable("history Agent request native instance differs"));
        }
        original_runtime_qualified = true;
    } else if original.event.scope_ref
        != (arkret_wire::ScopeRef::Realm {
            realm_id: original.event.realm_id.clone(),
        })
    {
        return Err(unavailable(
            "history request has no independently qualified original producer",
        ));
    }
    crate::content_recovery_fence::require_unfenced(conn, &recipient.actor_id).await?;
    if let Some(account) = recipient.actor_id.as_account_id() {
        // Use the actual PCR writer lock without waiting backwards while the
        // resource Realm is held. Then verify the native holder, not a replica.
        let holder = sql_query("SELECT to_jsonb(a.service_id) AS payload FROM principal_resolutions p JOIN realm_authorities a ON a.realm_id=p.pcr_realm_id WHERE p.principal_id=$1 AND p.station_id=$2 FOR UPDATE OF a NOWAIT")
            .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
            .get_result::<crate::JsonPayloadRow>(&mut *conn).await
            .map_err(|_| PersistenceError::Conflict("temporarily_unavailable: history recipient current native cut is busy or unavailable".into()))?;
        if holder.payload.as_str() != Some(native_station.as_str()) {
            return Err(unavailable(
                "history recipient has no qualified current native holder at this Station",
            ));
        }
        crate::pcr_private_authority::lock_holder(conn, account, Some(native_station)).await?;
    }
    match &recipient.endpoint {
        MlsWelcomeRecipientEndpoint::Device { device_id }
            if recipient.actor_id.as_realm_actor_id().is_some() =>
        {
            if fact.is_none() {
                return Err(unavailable(
                    "history Realm Device request has no original native signer source",
                ));
            }
            let authority = crate::realm_actor_device_authority::current_in_connection(
                conn,
                &recipient.actor_id,
                device_id,
                chrono::Utc::now(),
            )
            .await
            .map_err(crate::PgTransactionError::into_persistence)?
            .ok_or_else(|| unavailable("history recipient has no current native Realm Device"))?;
            if authority.authorization_ref.event_id != recipient.authorization_event_ref
                || !authority.scopes.contains_scope(&original.event.scope_ref)
            {
                return Err(unavailable(
                    "history Realm Device authorization instance or scope changed",
                ));
            }
        }
        MlsWelcomeRecipientEndpoint::Device { device_id } => {
            let account = recipient
                .actor_id
                .as_account_id()
                .ok_or_else(|| unavailable("history Device has no full Account"))?;
            // This is the existing native holder barrier, not a private PCR
            // replica inferred from a current leaf or public DID key. Missing
            // qualified origin/current material remains unavailable.
            let current = crate::mls_keypackage_claim_endpoints::device(
                conn,
                account,
                device_id,
                &recipient.authorization_event_ref,
            )
            .await?;
            current.require_current(conn).await?;
            if fact.is_none() {
                if current.realm() != &original.event.realm_id
                    || crate::pcr_private_authority::accepted_governance(conn, current.realm())
                        .await?
                        != arkret_wire::GenesisGovernance::Human(account.clone())
                {
                    return Err(unavailable(
                        "history request is missing its original native signer fact",
                    ));
                }
                crate::actor_profiles::verify_device_signer_in_connection(
                    conn,
                    &original.event,
                    account,
                    device_id,
                    current.realm(),
                    chrono::Utc::now(),
                    original.event.realm_id.digest_suite_code().digest_suite(),
                    "history recipient original",
                )
                .await
                .map_err(crate::PgTransactionError::into_persistence)?;
            }
        }
        MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method,
        } => {
            if fact.is_none() && !original_runtime_qualified {
                return Err(unavailable(
                    "history runtime request has no original native signer source",
                ));
            }
            let account = recipient
                .actor_id
                .as_account_id()
                .ok_or_else(|| unavailable("history runtime has no full Agent Account"))?;
            crate::mls_keypackage_claim_endpoints::agent(
                conn,
                &account.principal_id,
                verification_method,
                &recipient.authorization_event_ref,
            )
            .await?
            .require_current(conn)
            .await?;
        }
    }
    let current = current_exact_endpoint_in_connection(
        conn,
        group,
        recipient.actor_id.clone(),
        recipient.endpoint.clone(),
        recipient.authorization_event_ref.clone(),
    )
    .await?;
    if current != *recipient {
        return Err(unavailable("history recipient leaf binding changed"));
    }
    Ok(current)
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
