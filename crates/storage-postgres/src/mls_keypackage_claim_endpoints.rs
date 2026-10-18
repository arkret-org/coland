//! Current local claim endpoints, derived from their accepted SDK originals.
use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload;
use arkret_models_crypto::{
    PeerKeyPackageRequesterAuthorization, PeerKeyPackagesClaimOutcome,
    PeerKeyPackagesClaimRequestBody,
};
use arkret_wire::{
    AccountId, ActorId, CommittedEventRef, DeviceId, DidCoreId, DidUrl, EventId, EventKind, RealmId,
};

use super::*;

fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}

#[derive(Clone)]
pub(crate) struct EndpointWindow {
    not_before: Option<chrono::DateTime<Utc>>,
    expires_at: Option<chrono::DateTime<Utc>>,
}
impl EndpointWindow {
    pub(crate) fn permits_at(&self, at: chrono::DateTime<Utc>) -> bool {
        self.not_before.is_none_or(|start| at >= start)
            && self.expires_at.is_none_or(|end| at < end)
    }
}
enum Endpoint {
    Device {
        account: AccountId,
        device: DeviceId,
        original: CommittedEventRef,
    },
    Agent {
        agent: DidCoreId,
        method: DidUrl,
        original: CommittedEventRef,
    },
}
pub(crate) struct ClaimEndpoint {
    realm: RealmId,
    endpoint: Endpoint,
    window: EndpointWindow,
}
impl ClaimEndpoint {
    pub(crate) fn realm(&self) -> &RealmId {
        &self.realm
    }
    pub(crate) fn window(&self) -> EndpointWindow {
        self.window.clone()
    }
    pub(crate) async fn require_current(
        &self,
        conn: &mut AsyncPgConnection,
    ) -> PersistenceResult<()> {
        let at = Utc::now();
        if !self.window.permits_at(at) {
            return Err(denied("claim endpoint authorization window ended"));
        }
        match &self.endpoint {
            Endpoint::Device {
                account,
                device,
                original,
            } => {
                let cut =
                    crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
                        conn, account, device, at,
                    )
                    .await
                    .map_err(crate::PgTransactionError::into_persistence)?
                    .ok_or_else(|| denied("claim Device current is absent"))?;
                if cut.admission().error_code().is_some() || cut.authority.realm_id != self.realm {
                    return Err(denied("claim Device is no longer admitted"));
                }
                let authorization = cut
                    .authority
                    .authorization
                    .ok_or_else(|| denied("claim Device authorization is absent"))?;
                if authorization.event_id != original.event_id
                    || authorization.source_commit_id != original.commit_id
                {
                    return Err(denied("claim Device authorization instance changed"));
                }
                let inactive=sql_query("SELECT EXISTS(SELECT 1 FROM account_lifecycle l JOIN accounts a ON a.pk=l.account_pk WHERE a.principal_id=$1 AND a.station_id=$2 AND l.state<>'active') AS present")
                    .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str()).get_result::<ExistsRow>(&mut *conn).await.map_err(PersistenceError::database)?;
                if inactive.present {
                    return Err(denied("claim Account is inactive"));
                }
            }
            Endpoint::Agent {
                agent,
                method,
                original,
            } => {
                // Fail rather than form a wait cycle with a concurrent Agent
                // producer. The actual current checker reacquires this same
                // transaction-local lock without opening another connection.
                let locked = sql_query(
                    "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0)) AS present",
                )
                .bind::<Text, _>(format!("agent-producer-current:{}:{}", self.realm, agent))
                .get_result::<ExistsRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
                if !locked.present {
                    return Err(PersistenceError::Conflict(
                        "temporarily_unavailable: claim Agent current is busy".into(),
                    ));
                }
                crate::boxed_future(|| {
                    crate::authority_commit::check_agent_endpoint_current_in_connection(
                        conn,
                        &self.realm,
                        agent,
                        original,
                        method,
                        at,
                    )
                })
                .await?;
            }
        }
        if !self.window.permits_at(Utc::now()) {
            return Err(denied("claim endpoint expired during current verification"));
        }
        Ok(())
    }
}

async fn original(
    conn: &mut AsyncPgConnection,
    event: &EventId,
) -> PersistenceResult<arkret_wire::CommittedEventFullView> {
    crate::committed_disclosure::accepted_full_event_in_connection(conn, event)
        .await?
        .ok_or_else(|| denied("claim endpoint original is not accepted"))
}
fn reference(full: &arkret_wire::CommittedEventFullView) -> CommittedEventRef {
    CommittedEventRef {
        event_id: full.event.event_id.clone(),
        commit_id: full.commit.commit_id.clone(),
        stream_ref: full.commit.stream_ref.clone(),
        stream_position: full.commit.stream_position,
    }
}
async fn device(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    id: &DeviceId,
    event: &EventId,
) -> PersistenceResult<ClaimEndpoint> {
    let full = original(conn, event).await?;
    let payload: DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&full.event.payload).map_err(denied)?)
            .map_err(denied)?;
    payload.validate_wire_constraints().map_err(denied)?;
    if full.event.kind != EventKind::DeviceAuthorize
        || full.event.actor_id != ActorId::account(account.clone())
        || payload.device_id != *id
    {
        return Err(denied(
            "claim Device original differs from its exact Account and Device",
        ));
    }
    Ok(ClaimEndpoint {
        realm: full.event.realm_id.clone(),
        endpoint: Endpoint::Device {
            account: account.clone(),
            device: id.clone(),
            original: reference(&full),
        },
        window: EndpointWindow {
            not_before: Some(payload.not_before),
            expires_at: payload.expires_at.flatten(),
        },
    })
}
async fn agent(
    conn: &mut AsyncPgConnection,
    id: &DidCoreId,
    method: &DidUrl,
    event: &EventId,
) -> PersistenceResult<ClaimEndpoint> {
    let full = original(conn, event).await?;
    let payload: AgentKeyAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&full.event.payload).map_err(denied)?)
            .map_err(denied)?;
    if full.event.kind != EventKind::AgentKeyAuthorize
        || payload.agent_id != *id
        || payload.verification_method != *method
    {
        return Err(denied(
            "claim Agent original differs from its exact current method",
        ));
    }
    Ok(ClaimEndpoint {
        realm: full.event.realm_id.clone(),
        endpoint: Endpoint::Agent {
            agent: id.clone(),
            method: method.clone(),
            original: reference(&full),
        },
        window: EndpointWindow {
            not_before: Some(payload.issued_at),
            expires_at: payload.expires_at,
        },
    })
}

/// Remote participant authority belongs to its authenticated origin Station.
/// Every local source and target is instead re-read under the real local PCR.
pub(crate) async fn prepare(
    conn: &mut AsyncPgConnection,
    outcome: &PeerKeyPackagesClaimOutcome,
    command: Option<&PeerKeyPackagesClaimRequestBody>,
    station: &DidCoreId,
) -> PersistenceResult<Vec<ClaimEndpoint>> {
    outcome.validate_shape().map_err(denied)?;
    let mut result = Vec::new();
    if let Some(command) = command {
        if arkret_canonical::canonical_sha256(command).map_err(denied)?
            != outcome.claim_receipt.request_digest.as_str()
        {
            return Err(denied(
                "delivery command differs from original receipt digest",
            ));
        }
        if &command.service_binding.source_id == station {
            match &command.requester_authorization {
                PeerKeyPackageRequesterAuthorization::Device {
                    requester_device_id,
                    device_authorize_event_id,
                    ..
                } => {
                    let account = command
                        .requester_account_id
                        .as_ref()
                        .filter(|account| &account.station_id == station)
                        .ok_or_else(|| denied("local Device requester route differs"))?;
                    result.push(
                        device(
                            conn,
                            account,
                            requester_device_id,
                            device_authorize_event_id,
                        )
                        .await?,
                    );
                }
                PeerKeyPackageRequesterAuthorization::Agent {
                    requester_agent_id,
                    verification_method,
                    agent_key_authorize_event_id,
                    ..
                } => result.push(
                    agent(
                        conn,
                        requester_agent_id,
                        verification_method,
                        agent_key_authorize_event_id,
                    )
                    .await?,
                ),
            }
        }
    }
    for claim in &outcome.claims {
        if claim.actor_id.route_service_id() != station {
            return Err(denied("claim target has no local original barrier"));
        }
        match (
            &claim.device_id,
            &claim.device_authorize_event_id,
            &claim.agent_id,
            &claim.agent_verification_method,
            &claim.agent_key_authorize_event_id,
        ) {
            (Some(id), Some(event), None, None, None) => {
                let account = claim
                    .actor_id
                    .as_account_id()
                    .ok_or_else(|| denied("claim Device omits full Account"))?;
                result.push(device(conn, account, id, event).await?);
            }
            (None, None, Some(id), Some(method), Some(event)) => {
                result.push(agent(conn, id, method, event).await?)
            }
            _ => return Err(denied("claim target endpoint branch is incomplete")),
        }
    }
    Ok(result)
}
