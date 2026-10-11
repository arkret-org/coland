//! Transport-independent public Push Gateway handoff retry planning.

use std::future::Future;

use arkret::PushRegisterDeviceRequestBody;
use arkret_identifiers::PushTargetId;
use arkret_wire::{AccountId, DidCoreId, Hash, WebOrigin};
use coland_storage::{
    PushRegistrationHandoffIntentRecord, PushRegistrationHandoffIntentStatus,
    PushRegistrationHandoffRetryCursor,
};

use crate::{ServiceError, ServiceResult};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RevokeRetryReport {
    pub scanned: usize,
    pub confirmed: usize,
    pub failed: usize,
}

/// Confirm a bounded caller-selected batch without letting one failed
/// transport attempt block later durable tombstones.
///
/// Only canonical `revoked + awaiting_receipt` records reach `confirm`.
/// Errors are deliberately reduced to counts here so transport or remote
/// response details cannot leak through worker reporting.
pub async fn retry_revoked_handoff_intents<E, F, Fut>(
    intents: Vec<PushRegistrationHandoffIntentRecord>,
    mut confirm: F,
) -> RevokeRetryReport
where
    F: FnMut(PushRegistrationHandoffIntentRecord) -> Fut,
    Fut: Future<Output = Result<(), E>>,
{
    let mut report = RevokeRetryReport {
        scanned: intents.len(),
        ..RevokeRetryReport::default()
    };
    for intent in intents {
        let is_awaiting_revoke = intent
            .request()
            .is_ok_and(|request| request.state() == arkret::PushRegistrationHandoffState::Revoked)
            && intent.status == PushRegistrationHandoffIntentStatus::AwaitingReceipt;
        if !is_awaiting_revoke {
            report.failed += 1;
            continue;
        }
        match confirm(intent).await {
            Ok(()) => report.confirmed += 1,
            Err(_) => report.failed += 1,
        }
    }
    report
}

/// Load and confirm one stable retry page, advancing an in-process cursor only
/// after the complete page has been attempted. At the end of the ordered view
/// the next pass wraps to the head, so a failed prefix remains retryable while
/// it cannot permanently starve later destinations.
pub async fn retry_revoked_handoff_page<E, Fetch, FetchFuture, Confirm, ConfirmFuture>(
    cursor: &mut Option<PushRegistrationHandoffRetryCursor>,
    limit: usize,
    mut fetch: Fetch,
    confirm: Confirm,
) -> Result<RevokeRetryReport, E>
where
    Fetch: FnMut(Option<PushRegistrationHandoffRetryCursor>, usize) -> FetchFuture,
    FetchFuture: Future<Output = Result<Vec<PushRegistrationHandoffIntentRecord>, E>>,
    Confirm: FnMut(PushRegistrationHandoffIntentRecord) -> ConfirmFuture,
    ConfirmFuture: Future<Output = Result<(), E>>,
{
    if limit == 0 {
        return Ok(RevokeRetryReport::default());
    }
    let mut page = fetch(cursor.clone(), limit).await?;
    if page.is_empty() && cursor.is_some() {
        page = fetch(None, limit).await?;
    }
    page.truncate(limit);
    let next_cursor = page.last().map(PushRegistrationHandoffRetryCursor::after);
    let report = retry_revoked_handoff_intents(page, confirm).await;
    *cursor = next_cursor;
    Ok(report)
}

pub fn active_push_registration_client_input_digest(
    account_id: &AccountId,
    body: &PushRegisterDeviceRequestBody,
    push_route_id: &str,
    origin: &WebOrigin,
    destination_gateway_id: &DidCoreId,
) -> ServiceResult<Hash> {
    let input = serde_json::json!({
        "account_id": account_id,
        "device_id": body.device_id,
        "push_route_id": push_route_id,
        "destination_gateway_id": destination_gateway_id,
        "gateway_origin": origin,
        "push_key": body.push_key,
        "platform": body.platform,
        "app_id": body.app_id,
        "visible_notification_opt_in": body.visible_notification_opt_in,
    });
    let digest = arkret_canonical::canonical_sha256(&input)
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    Hash::new(digest).map_err(|error| ServiceError::Internal(error.to_string()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivePushRegistrationPlan {
    ReturnVerified(PushRegistrationHandoffIntentRecord),
    ReplayPending(PushRegistrationHandoffIntentRecord),
    Create {
        predecessor: Option<arkret::PushRegistrationId>,
    },
}

pub fn plan_active_push_registration(
    existing: Option<PushRegistrationHandoffIntentRecord>,
    client_input_digest: &Hash,
    current_push_target_id: &PushTargetId,
) -> ServiceResult<ActivePushRegistrationPlan> {
    let Some(existing) = existing else {
        return Ok(ActivePushRegistrationPlan::Create { predecessor: None });
    };
    let request = existing.request()?;
    if request.state() == arkret::PushRegistrationHandoffState::Revoked {
        return match existing.status {
            PushRegistrationHandoffIntentStatus::AwaitingReceipt => Err(ServiceError::Conflict(
                "cas_conflict: public Push Gateway revocation is awaiting a receipt".to_owned(),
            )),
            PushRegistrationHandoffIntentStatus::ReceiptVerified => {
                Ok(ActivePushRegistrationPlan::Create {
                    predecessor: Some(existing.registration_id),
                })
            }
        };
    }
    match existing.status {
        PushRegistrationHandoffIntentStatus::AwaitingReceipt => {
            if &existing.client_input_digest != client_input_digest {
                return Err(ServiceError::Conflict(
                    "cas_conflict: another public Push Gateway registration is awaiting a receipt"
                        .to_owned(),
                ));
            }
            Ok(ActivePushRegistrationPlan::ReplayPending(existing))
        }
        PushRegistrationHandoffIntentStatus::ReceiptVerified => {
            if &existing.client_input_digest == client_input_digest
                && request.push_target_id() == current_push_target_id
            {
                Ok(ActivePushRegistrationPlan::ReturnVerified(existing))
            } else {
                Ok(ActivePushRegistrationPlan::Create {
                    predecessor: Some(existing.registration_id),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use arkret::PushRegistrationHandoffRequestBody;
    use arkret_identifiers::PushTargetId;
    use arkret_wire::{AccountId, DeviceId, DidCoreId};
    use chrono::{DateTime, Utc};
    use coland_storage::PushRegistrationHandoffRouteLocator;
    use serde_json::json;

    use super::*;

    fn device_authorization(
        source: &DidCoreId,
        device_id: &DeviceId,
    ) -> coland_storage::DeviceRevocationGateSelector {
        let event_id =
            arkret_wire::EventId::new("ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD")
                .unwrap();
        coland_storage::DeviceRevocationGateSelector {
            principal_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            station_id: source.clone(),
            device_id: device_id.as_str().to_owned(),
            authorization_ref: arkret_wire::CommittedEventRef {
                commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                    event_id.as_str().as_bytes(),
                )),
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: arkret_wire::RealmId::new(
                        "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
                    )
                    .unwrap(),
                },
                stream_position: 1,
                event_id,
            },
        }
    }

    fn record(status: PushRegistrationHandoffIntentStatus) -> PushRegistrationHandoffIntentRecord {
        let source = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:push.example").unwrap();
        let request: PushRegistrationHandoffRequestBody = serde_json::from_value(json!({
            "registration_id": "registration_0123456789abcdef",
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "platform": "desktop",
            "app_id": "inkson",
            "visible_notification_opt_in": false
        }))
        .unwrap();
        let device_id = request.device_id().clone();
        let digest = Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap();
        let now = DateTime::parse_from_rfc3339("2026-09-22T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut record = PushRegistrationHandoffIntentRecord::prepare(
            source.clone(),
            PushRegistrationHandoffRouteLocator {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    source.clone(),
                ),
                device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
                push_route_id: "inkson".to_owned(),
                destination_gateway_id: destination,
            },
            device_authorization(&source, &device_id),
            digest,
            &request,
            now,
        )
        .unwrap();
        if status == PushRegistrationHandoffIntentStatus::ReceiptVerified {
            record.status = status;
        }
        record
    }

    fn revoked_record(
        status: PushRegistrationHandoffIntentStatus,
    ) -> PushRegistrationHandoffIntentRecord {
        let active = record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let request = active.request().unwrap();
        let revoked = PushRegistrationHandoffRequestBody::Revoked {
            registration_id: active.registration_id.clone(),
            push_target_id: request.push_target_id().clone(),
            device_id: request.device_id().clone(),
        };
        let mut record = PushRegistrationHandoffIntentRecord::prepare(
            active.source_station_id,
            active.local_route,
            active.device_authorization,
            active.client_input_digest,
            &revoked,
            active.created_at,
        )
        .unwrap();
        record.status = status;
        record
    }

    #[test]
    fn pending_cross_epoch_replays_stored_body_but_verified_cross_epoch_supersedes() {
        let next_epoch_target =
            PushTargetId::new("ak:pseudonym:push:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap();
        let pending = record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let pending_body = pending.canonical_request.clone();
        let digest = pending.client_input_digest.clone();
        match plan_active_push_registration(Some(pending), &digest, &next_epoch_target).unwrap() {
            ActivePushRegistrationPlan::ReplayPending(record) => {
                assert_eq!(record.canonical_request, pending_body)
            }
            other => panic!("pending cross-epoch retry did not replay: {other:?}"),
        }

        let verified = record(PushRegistrationHandoffIntentStatus::ReceiptVerified);
        let predecessor = verified.registration_id.clone();
        assert_eq!(
            plan_active_push_registration(Some(verified), &digest, &next_epoch_target).unwrap(),
            ActivePushRegistrationPlan::Create {
                predecessor: Some(predecessor)
            }
        );
    }

    #[test]
    fn exact_pending_replays_and_changed_pending_conflicts() {
        let pending = record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let digest = pending.client_input_digest.clone();
        let target = pending.request().unwrap().push_target_id().clone();
        assert!(matches!(
            plan_active_push_registration(Some(pending.clone()), &digest, &target).unwrap(),
            ActivePushRegistrationPlan::ReplayPending(_)
        ));
        let changed = Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap();
        assert!(plan_active_push_registration(Some(pending), &changed, &target).is_err());
    }

    #[test]
    fn exact_verified_returns_and_changed_verified_supersedes() {
        let verified = record(PushRegistrationHandoffIntentStatus::ReceiptVerified);
        let digest = verified.client_input_digest.clone();
        let target = verified.request().unwrap().push_target_id().clone();
        assert!(matches!(
            plan_active_push_registration(Some(verified.clone()), &digest, &target).unwrap(),
            ActivePushRegistrationPlan::ReturnVerified(_)
        ));
        let changed = Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap();
        let predecessor = verified.registration_id.clone();
        assert_eq!(
            plan_active_push_registration(Some(verified), &changed, &target).unwrap(),
            ActivePushRegistrationPlan::Create {
                predecessor: Some(predecessor)
            }
        );
    }

    #[test]
    fn revoked_pending_waits_but_verified_revoke_creates_successor() {
        let pending = revoked_record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let digest = pending.client_input_digest.clone();
        let target = pending.request().unwrap().push_target_id().clone();
        assert!(plan_active_push_registration(Some(pending), &digest, &target).is_err());

        let verified = revoked_record(PushRegistrationHandoffIntentStatus::ReceiptVerified);
        let predecessor = verified.registration_id.clone();
        assert_eq!(
            plan_active_push_registration(Some(verified), &digest, &target).unwrap(),
            ActivePushRegistrationPlan::Create {
                predecessor: Some(predecessor)
            }
        );
    }

    #[tokio::test]
    async fn revoke_retry_isolates_partial_failure_and_continues_batch() {
        let intent = revoked_record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let report = retry_revoked_handoff_intents(
            vec![intent.clone(), intent.clone(), intent],
            move |_| {
                let observed = observed.clone();
                async move {
                    let call = observed.fetch_add(1, Ordering::SeqCst) + 1;
                    if call == 2 { Err(()) } else { Ok(()) }
                }
            },
        )
        .await;

        assert_eq!(
            report,
            RevokeRetryReport {
                scanned: 3,
                confirmed: 2,
                failed: 1,
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn revoke_retry_replays_exact_intent_across_gateways() {
        let first = revoked_record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let mut second = first.clone();
        let second_gateway = DidCoreId::new("ak:did_core:web:push-2.example").unwrap();
        second.destination_gateway_id = second_gateway.clone();
        second.local_route.destination_gateway_id = second_gateway;
        let observed = Arc::new(Mutex::new(Vec::new()));

        for intents in [
            vec![first.clone(), second.clone()],
            vec![first.clone(), second.clone()],
        ] {
            let observed = observed.clone();
            let report = retry_revoked_handoff_intents(intents, move |intent| {
                let observed = observed.clone();
                async move {
                    observed.lock().unwrap().push((
                        intent.destination_gateway_id,
                        intent.registration_id,
                        intent.request_digest,
                        intent.canonical_request,
                    ));
                    Ok::<(), ()>(())
                }
            })
            .await;
            assert_eq!(report.confirmed, 2);
            assert_eq!(report.failed, 0);
        }

        let observed = observed.lock().unwrap();
        assert_eq!(observed.len(), 4);
        assert_eq!(observed[0], observed[2], "retry must replay exact bytes");
        assert_eq!(observed[1], observed[3], "retry must replay exact bytes");
        assert_ne!(observed[0].0, observed[1].0, "both Gateways are visited");
    }

    #[tokio::test]
    async fn revoke_retry_never_sends_or_revives_late_active_intent() {
        let active = record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let revoked = revoked_record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let report = retry_revoked_handoff_intents(vec![active, revoked], move |_| {
            let observed = observed.clone();
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok::<(), ()>(())
            }
        })
        .await;

        assert_eq!(
            report,
            RevokeRetryReport {
                scanned: 2,
                confirmed: 1,
                failed: 1,
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retry_cursor_reaches_item_after_permanently_failing_full_prefix() {
        let base = revoked_record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let records = Arc::new(
            (0..65)
                .map(|index| {
                    let mut record = base.clone();
                    record.updated_at = base.updated_at + chrono::Duration::seconds(index);
                    record
                })
                .collect::<Vec<_>>(),
        );
        let last_updated_at = records.last().unwrap().updated_at;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut cursor = None;

        let first_page = retry_revoked_handoff_page(
            &mut cursor,
            64,
            {
                let records = records.clone();
                move |after, limit| {
                    let records = records.clone();
                    async move {
                        Ok::<_, ()>(
                            records
                                .iter()
                                .filter(|record| {
                                    after.as_ref().is_none_or(|after| {
                                        record.updated_at > after.updated_at
                                            || (record.updated_at == after.updated_at
                                                && record.registration_id > after.registration_id)
                                    })
                                })
                                .take(limit)
                                .cloned()
                                .collect(),
                        )
                    }
                }
            },
            {
                let calls = calls.clone();
                move |_| {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Err::<(), ()>(())
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(first_page.scanned, 64);
        assert_eq!(first_page.failed, 64);

        let second_page = retry_revoked_handoff_page(
            &mut cursor,
            64,
            {
                let records = records.clone();
                move |after, limit| {
                    let records = records.clone();
                    async move {
                        Ok::<_, ()>(
                            records
                                .iter()
                                .filter(|record| {
                                    after.as_ref().is_none_or(|after| {
                                        record.updated_at > after.updated_at
                                            || (record.updated_at == after.updated_at
                                                && record.registration_id > after.registration_id)
                                    })
                                })
                                .take(limit)
                                .cloned()
                                .collect(),
                        )
                    }
                }
            },
            {
                let calls = calls.clone();
                move |record| {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        if record.updated_at == last_updated_at {
                            Ok(())
                        } else {
                            Err(())
                        }
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(second_page.scanned, 1);
        assert_eq!(second_page.confirmed, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 65);
    }
}
