//! Exact current projection reads at the real native Account and resource cut.
use arkret_models_collaboration::exact_current_results::{
    ExactCurrentResultEntry as Entry, ExactCurrentResultsReadOutcome as Outcome,
    ExactCurrentResultsReadRequestBody as Request, NeverWrittenExactCurrentSelector,
};
use arkret_wire::{CommitStreamRef, CurrentRevision};

use super::*;

fn scope_for_stream(stream: &CommitStreamRef) -> PersistenceResult<ScopeRef> {
    match stream {
        CommitStreamRef::Realm { realm_id } => Ok(ScopeRef::Realm {
            realm_id: realm_id.clone(),
        }),
        CommitStreamRef::Circle {
            realm_id,
            circle_id,
        } => Ok(ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        }),
        _ => Err(refused(
            "native exact current has no applicable resource scope",
        )),
    }
}

fn coordinates(entry: &Entry) -> PersistenceResult<(&CommitStreamRef, &CurrentRevision)> {
    Ok(match entry {
        Entry::Relation(row) => (&row.source_stream_ref, &row.revision),
        Entry::ModerationState(row) => (&row.source_stream_ref, &row.revision),
        Entry::AgentInteraction(row) => (&row.source_stream_ref, &row.revision),
        Entry::Policy(row) => (&row.source_stream_ref, &row.revision),
        Entry::CalendarScheduleSource(row) => (&row.source_stream_ref, &row.revision),
        // This selector's only registered exception belongs to the original
        // owned Agent issuer, not an Applet Device or the owning Service.
        Entry::CapabilityGrant(_) => {
            return Err(refused(
                "native exact read cannot borrow owned Agent issuer authority",
            ));
        }
    })
}

pub(super) async fn prepare(
    conn: &mut diesel_async::AsyncPgConnection,
    station: &DidCoreId,
    endpoint: &AppletManagedDeviceScopeGuard,
    expiry: chrono::DateTime<chrono::Utc>,
    request: &Request,
    outcome: &Outcome,
) -> PersistenceResult<ReadProof> {
    request.validate().map_err(PersistenceError::database)?;
    if &request.realm_id != endpoint.effective_scope.realm_id() {
        return Err(refused("native exact current has another Realm"));
    }
    let fresh = crate::boxed_future(|| {
        crate::self_current_reads::exact_current_result_for_actor_in_connection(
            conn,
            request,
            &endpoint.authority.actor_id,
            station,
        )
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)?;
    let coland_storage::SelfExactCurrentRead::Answer(fresh) = fresh else {
        return Err(refused("native exact current is not currently disclosed"));
    };
    let generation = match &fresh {
        Outcome::Present {
            governance_generation,
            ..
        }
        | Outcome::NeverWritten {
            governance_generation,
            ..
        } => *governance_generation,
    };
    outcome
        .validate_for_request(request, generation)
        .map_err(PersistenceError::database)?;
    if arkret_canonical::canonical_json_bytes(&fresh).map_err(PersistenceError::database)?
        != arkret_canonical::canonical_json_bytes(outcome).map_err(PersistenceError::database)?
    {
        return Err(refused("native exact current changed before handoff"));
    }
    let stream = match outcome {
        Outcome::Present { entry, .. } => coordinates(entry)?.0,
        Outcome::NeverWritten {
            effective_stream_head,
            ..
        } => &effective_stream_head.stream_ref,
    };
    if scope_for_stream(stream)? != endpoint.effective_scope {
        return Err(refused(
            "native exact current differs from its actual data scope",
        ));
    }
    let mut proof =
        crate::boxed_future(|| super::mls_scope_read_proof(conn, endpoint, expiry, None)).await?;
    let mut resources = Vec::new();
    match outcome {
        Outcome::Present { entry, .. } => {
            let (stream, revision) = coordinates(entry)?;
            let source = crate::boxed_future(|| {
                crate::account_content_delivery::current_source_in_connection(
                    conn,
                    &request.realm_id,
                    stream,
                    revision,
                )
            })
            .await?;
            if source.scope_ref != endpoint.effective_scope {
                return Err(refused(
                    "native exact current source differs from its stream",
                ));
            }
            if let Entry::Policy(row) = entry {
                resources.push(PolicyResourceSelector {
                    kind: PolicyResourceKind::Object,
                    realm_id: Some(request.realm_id.clone()),
                    resource_ref: Some(row.selector.policy_id.to_string()),
                });
            }
            // Current metadata can legitimately predate the reader's history
            // floor. Its accepted source supplies resource facts, never a Full
            // historical Event disclosure or authority for an embedded Event.
            super::source_read_proof(
                proof.context,
                &source,
                &[CapabilityActionId::EventRead],
                &resources,
            )
        }
        Outcome::NeverWritten { selector, .. } => {
            match selector {
                NeverWrittenExactCurrentSelector::Policy(selector) => {
                    resources.push(PolicyResourceSelector {
                        kind: PolicyResourceKind::Object,
                        realm_id: Some(request.realm_id.clone()),
                        resource_ref: Some(selector.policy_id.to_string()),
                    })
                }
                NeverWrittenExactCurrentSelector::AgentInteraction(_) => (),
                // The common reader currently supplies no authorized absent
                // Relation endpoint cut; a missing row cannot invent one.
                NeverWrittenExactCurrentSelector::Relation(_) => {
                    return Err(refused(
                        "native Relation absence has no actual endpoint visibility proof",
                    ));
                }
            }
            for resource in resources {
                if !proof.resources.contains(&resource) {
                    proof.resources.push(resource);
                }
            }
            let mut targets = crate::agent_management_admission::content_capability_targets(
                &request.realm_id,
                &proof.resources,
            );
            for operation in &mut proof.operations {
                for target in operation.targets.drain(..) {
                    if !targets.contains(&target) {
                        targets.push(target);
                    }
                }
                operation.targets = targets.clone();
            }
            Ok(proof)
        }
    }
}
