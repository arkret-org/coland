use arkret_wire::{AccountId, MlsGroupId, RealmId, ScopeRef};

use super::{DeviceRevocationGateSelector, PersistenceResult, Value, async_trait};
/// G3.S1 — durable KeyPackage row.
///
/// The Pg backend's `(actor_id, device_id, id)` composite key is what
/// enforces at-most-one row per `keypackage_id`. `try_claim` is the
/// CAS path — it returns `Ok(true)` on the first claim, `Ok(false)` if
/// the row is already claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsKeyPackageRow {
    pub id: String,
    pub keypackage_ref: String,
    pub keypackage_digest: String,
    /// Complete Account owner; Agent endpoints retain their real controller.
    pub owner_account_id: AccountId,
    /// Immutable target binding for scope-restricted Device publication.
    pub effective_scope: Option<ScopeRef>,
    pub actor_id: String,
    pub device_id: Option<String>,
    pub endpoint_verification_method: Option<String>,
    pub key_package_bytes: Vec<u8>,
    pub capabilities: Vec<String>,
    pub capabilities_digest: String,
    pub last_resort: bool,
    pub last_resort_realm_id: Option<String>,
    pub lifetime_not_before: i64,
    pub lifetime_not_after: i64,
    /// MLS group id that claimed this row. `None` while claimable.
    pub claimed_by_mls_group_id: Option<String>,
    pub device_authorize_event_id: Option<String>,
    pub agent_key_authorize_event_id: Option<String>,
    /// Unix seconds at which the single-use claim was accepted.
    pub claimed_at: Option<i64>,
    /// Unix milliseconds for the claim authorization deadline. An unconsumed
    /// row is terminally revoked at or after this instant.
    pub claim_expires_at_unix_ms: Option<i64>,
    /// Unix seconds at which the target device consumed the accepted claim.
    pub consumed_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersistedKeyPackageReusePolicy {
    SingleUse,
    LastResort { bound_realm_id: Option<RealmId> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersistedKeyPackageClaimState {
    Available,
    Claimed {
        mls_group_id: MlsGroupId,
        claimed_at: i64,
        claim_expires_at_unix_ms: Option<i64>,
    },
    Consumed {
        mls_group_id: MlsGroupId,
        claimed_at: i64,
        claim_expires_at_unix_ms: Option<i64>,
        consumed_at: i64,
    },
    Retired,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedKeyPackageLifecycle {
    pub reuse_policy: PersistedKeyPackageReusePolicy,
    pub claim_state: PersistedKeyPackageClaimState,
}

pub fn classify_key_package_lifecycle(
    last_resort: bool,
    last_resort_realm_id: Option<&str>,
    claimed_by_mls_group_id: Option<&str>,
    claimed_at: Option<i64>,
    claim_expires_at_unix_ms: Option<i64>,
    consumed_at: Option<i64>,
) -> Result<PersistedKeyPackageLifecycle, String> {
    const REVOKED_CLAIM_SENTINEL: &str = "revoked";
    const RETIRED_CLAIM_SENTINEL: &str = "retired";

    let reuse_policy = if last_resort {
        PersistedKeyPackageReusePolicy::LastResort {
            bound_realm_id: last_resort_realm_id
                .map(|value| {
                    RealmId::new(value.to_owned()).map_err(|error| {
                        format!("last-resort KeyPackage Realm id is invalid: {error}")
                    })
                })
                .transpose()?,
        }
    } else {
        if last_resort_realm_id.is_some() {
            return Err("ordinary KeyPackage must not carry last_resort_realm_id".to_owned());
        }
        PersistedKeyPackageReusePolicy::SingleUse
    };
    let claim_state = match claimed_by_mls_group_id {
        Some(REVOKED_CLAIM_SENTINEL) => {
            if claimed_at.is_some() || claim_expires_at_unix_ms.is_some() || consumed_at.is_some() {
                return Err(
                    "revoked KeyPackage must not carry claim or consumption timestamps".to_owned(),
                );
            }
            PersistedKeyPackageClaimState::Revoked
        }
        Some(RETIRED_CLAIM_SENTINEL) => {
            if last_resort
                || claimed_at.is_some()
                || claim_expires_at_unix_ms.is_some()
                || consumed_at.is_some()
            {
                return Err(
                    "retired KeyPackage must be ordinary, unused, and timestamp-free".to_owned(),
                );
            }
            PersistedKeyPackageClaimState::Retired
        }
        Some(group_id) if last_resort => {
            return Err(format!(
                "last-resort KeyPackage must not be claimed by MLS group `{group_id}`"
            ));
        }
        Some(group_id) => {
            let group_id = MlsGroupId::new(group_id.to_owned())
                .map_err(|error| format!("claimed KeyPackage MLS group id is invalid: {error}"))?;
            let claimed_at =
                claimed_at.ok_or_else(|| "claimed KeyPackage is missing claimed_at".to_owned())?;
            match consumed_at {
                Some(consumed_at) => PersistedKeyPackageClaimState::Consumed {
                    mls_group_id: group_id,
                    claimed_at,
                    claim_expires_at_unix_ms,
                    consumed_at,
                },
                None => PersistedKeyPackageClaimState::Claimed {
                    mls_group_id: group_id,
                    claimed_at,
                    claim_expires_at_unix_ms,
                },
            }
        }
        None => {
            if claimed_at.is_some() || claim_expires_at_unix_ms.is_some() || consumed_at.is_some() {
                return Err(
                    "available KeyPackage must not carry claim or consumption timestamps"
                        .to_owned(),
                );
            }
            PersistedKeyPackageClaimState::Available
        }
    };
    Ok(PersistedKeyPackageLifecycle {
        reuse_policy,
        claim_state,
    })
}

impl MlsKeyPackageRow {
    pub fn same_publication(&self, other: &Self) -> bool {
        fn original(row: &MlsKeyPackageRow) -> MlsKeyPackageRow {
            let mut row = row.clone();
            row.last_resort_realm_id = None;
            row.claimed_by_mls_group_id = None;
            row.claimed_at = None;
            row.claim_expires_at_unix_ms = None;
            row.consumed_at = None;
            row
        }
        original(self) == original(other)
    }

    pub fn lifecycle(&self) -> Result<PersistedKeyPackageLifecycle, String> {
        classify_key_package_lifecycle(
            self.last_resort,
            self.last_resort_realm_id.as_deref(),
            self.claimed_by_mls_group_id.as_deref(),
            self.claimed_at,
            self.claim_expires_at_unix_ms,
            self.consumed_at,
        )
    }
}

#[cfg(test)]
mod key_package_lifecycle_tests {
    use super::*;

    #[test]
    fn ordinary_claim_and_consumption_are_explicit_states() {
        const GROUP_ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let claimed = classify_key_package_lifecycle(
            false,
            None,
            Some(GROUP_ID),
            Some(10),
            Some(20_000),
            None,
        )
        .unwrap();
        assert!(matches!(
            claimed.claim_state,
            PersistedKeyPackageClaimState::Claimed {
                ref mls_group_id,
                ..
            } if mls_group_id.as_str() == GROUP_ID
        ));

        let consumed = classify_key_package_lifecycle(
            false,
            None,
            Some(GROUP_ID),
            Some(10),
            Some(20_000),
            Some(15),
        )
        .unwrap();
        assert!(matches!(
            consumed.claim_state,
            PersistedKeyPackageClaimState::Consumed {
                consumed_at: 15,
                ..
            }
        ));
    }

    #[test]
    fn last_resort_binding_is_a_reuse_policy_not_a_group_claim() {
        let realm_id = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K";
        let lifecycle =
            classify_key_package_lifecycle(true, Some(realm_id), None, None, None, None).unwrap();
        assert_eq!(
            lifecycle.reuse_policy,
            PersistedKeyPackageReusePolicy::LastResort {
                bound_realm_id: Some(RealmId::new(realm_id).unwrap())
            }
        );
        assert_eq!(
            lifecycle.claim_state,
            PersistedKeyPackageClaimState::Available
        );
    }

    #[test]
    fn invalid_column_combinations_fail_closed() {
        assert!(
            classify_key_package_lifecycle(false, Some("realm"), None, None, None, None).is_err()
        );
        assert!(
            classify_key_package_lifecycle(true, None, Some("group-a"), Some(1), None, None)
                .is_err()
        );
        assert!(
            classify_key_package_lifecycle(false, None, Some("group-a"), None, None, None).is_err()
        );
        assert!(
            classify_key_package_lifecycle(false, None, Some("revoked"), Some(1), None, Some(2))
                .is_err()
        );
        assert!(
            classify_key_package_lifecycle(
                false,
                None,
                Some("revoked"),
                Some(1),
                Some(2_000),
                None,
            )
            .is_err()
        );
    }
}

/// Durable terminal result for a peer KeyPackage claim request.
///
/// `(source_id, claim_request_id)` is the protocol idempotency key.
/// `request_digest` prevents a caller from reusing that key for a different
/// canonical request. `outcome` is the exact serialized success response and
/// is absent for the opaque `claim_failed` terminal state.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerKeyPackageClaimLedgerRecord {
    pub source_id: String,
    pub claim_request_id: String,
    pub request_digest: String,
    /// Durable use class of the claimed KeyPackage (`single_use`,
    /// `last_resort`, or `none` for an opaque failure/remote mirror without a
    /// local package row). This remains stable after the ledger reaches a
    /// terminal state and therefore must not be inferred from `state`.
    pub key_package_use: String,
    /// KeyPackage referenced by this ledger row. Absent for an opaque failure
    /// or a source-side mirror of a remote claim.
    pub keypackage_id: Option<String>,
    pub outcome: Option<Value>,
    pub terminal_receipt: Option<Value>,
    pub consume_receipt: Option<Value>,
    /// Unix milliseconds for the protocol claim deadline, distinct from
    /// `expires_at` (Unix-second ledger retention).
    pub claim_expires_at_unix_ms: Option<i64>,
    pub expires_at: i64,
    pub state: String,
    pub updated_at: i64,
}

/// The one Welcome a claim destination queued for one claim, recorded on
/// that claim's ledger row in the queueing transaction (device-lifecycle.md
/// §9.2.3, decision 0121). Consume is checked against it alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcomeClaimBinding {
    pub claim_id: String,
    pub source_id: String,
    pub claim_request_id: String,
    pub welcome_id: String,
    /// `sha256` of the JCS bytes of the complete delivery, proof included.
    pub welcome_digest: String,
    pub commit_event_ref: String,
}

/// Actual SDK command and any authenticated local native requester. Internal
/// acceptance inputs only; the target still has its own independent guard.
#[derive(Clone)]
pub struct MlsKeyPackageClaimAdmission {
    pub request: arkret_models_crypto::PeerKeyPackagesClaimRequestBody,
    pub requester: Option<(
        crate::AppletManagedDeviceScopeGuard,
        chrono::DateTime<chrono::Utc>,
    )>,
}

/// Actual prepared claim response and native endpoint evidence. A fresh
/// command is retained only when this response is to that command, never
/// reconstructed from the historical receipt's unsigned request.
#[derive(Clone, Debug)]
pub struct MlsKeyPackageClaimDelivery {
    pub outcome: arkret_models_crypto::PeerKeyPackagesClaimOutcome,
    pub endpoints: Vec<crate::AppletManagedDeviceScopeGuard>,
    pub command: Option<arkret_models_crypto::PeerKeyPackagesClaimRequestBody>,
}

/// Private attempt accounting, never a claim receipt or business authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerKeyPackageClaimRateDecision {
    Allowed,
    RateLimited,
    DuplicateConflict,
    Unavailable,
}

/// One candidate CAS attempt for a peer claim. The storage adapter must make
/// the KeyPackage transition and terminal ledger insert atomic.
pub struct PeerKeyPackageClaimAttempt<'a> {
    pub admission: Option<std::sync::Arc<MlsKeyPackageClaimAdmission>>,
    pub keypackage_id: &'a str,
    pub mls_group_id: &'a str,
    pub device_authorize_event_id: Option<&'a str>,
    pub agent_key_authorize_event_id: Option<&'a str>,
    pub device_revocation_gate: Option<DeviceRevocationGateSelector>,
    pub claimed_at_unix_ms: i64,
    pub claim_expires_at_unix_ms: i64,
    pub ledger: &'a PeerKeyPackageClaimLedgerRecord,
    pub applet_device_scope_guard: Option<crate::AppletManagedDeviceScopeGuard>,
}

pub struct PeerClaimTerminalTransition<'a> {
    pub source_id: &'a str,
    pub claim_request_id: &'a str,
    pub request_digest: &'a str,
    pub expected_outcome: &'a Value,
    pub terminal_state: &'a str,
    pub terminal_receipt: &'a Value,
    pub now_unix_ms: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PeerKeyPackageClaimAttemptResult {
    Claimed(Box<MlsKeyPackageRow>),
    Existing(Box<PeerKeyPackageClaimLedgerRecord>),
    KeyPackageUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlsKeyPackageClaimTarget<'a> {
    Group(&'a str),
    Retire,
    Revoke,
}

pub struct MlsKeyPackageClaim<'a> {
    pub id: &'a str,
    pub target: MlsKeyPackageClaimTarget<'a>,
    pub intended_realm_id: Option<&'a str>,
    pub device_authorize_event_id: Option<&'a str>,
    pub agent_key_authorize_event_id: Option<&'a str>,
    pub device_revocation_gate: Option<DeviceRevocationGateSelector>,
    pub claimed_at: i64,
    pub claim_expires_at_unix_ms: Option<i64>,
    pub applet_device_scope_guard: Option<crate::AppletManagedDeviceScopeGuard>,
}

/// Apply the storage-neutral acceptance rules for one KeyPackage claim.
///
/// Adapters remain responsible for revocation-gate reads, row locking and the
/// atomic write. Returning `None` is the CAS-loser/unavailable outcome.
pub fn apply_key_package_claim(
    row: &MlsKeyPackageRow,
    claim: &MlsKeyPackageClaim<'_>,
) -> Option<MlsKeyPackageRow> {
    if row.id != claim.id || row.consumed_at.is_some() {
        return None;
    }
    let (group_id, terminal_without_claim, retiring) = match claim.target {
        MlsKeyPackageClaimTarget::Group(group_id) => (group_id, false, false),
        MlsKeyPackageClaimTarget::Retire => ("retired", true, true),
        MlsKeyPackageClaimTarget::Revoke => ("revoked", true, false),
    };
    if matches!(
        row.claimed_by_mls_group_id.as_deref(),
        Some("revoked" | "retired")
    ) || retiring && (row.last_resort || row.claimed_by_mls_group_id.is_some())
    {
        return None;
    }
    if !terminal_without_claim
        && (claim.claimed_at >= row.lifetime_not_after
            || claim
                .claim_expires_at_unix_ms
                .is_some_and(|expires_at_unix_ms| {
                    expires_at_unix_ms <= claim.claimed_at.saturating_mul(1000)
                        || expires_at_unix_ms > row.lifetime_not_after.saturating_mul(1000)
                }))
    {
        return None;
    }
    if !terminal_without_claim
        && row
            .claimed_by_mls_group_id
            .as_deref()
            .is_some_and(|claimed| claimed != group_id)
        && !(row.last_resort && !terminal_without_claim)
    {
        return None;
    }
    if claim
        .device_authorize_event_id
        .is_some_and(|event_id| row.device_authorize_event_id.as_deref() != Some(event_id))
        || claim
            .agent_key_authorize_event_id
            .is_some_and(|event_id| row.agent_key_authorize_event_id.as_deref() != Some(event_id))
    {
        return None;
    }

    if !terminal_without_claim && let Some(scope) = &row.effective_scope {
        let guard = claim.applet_device_scope_guard.as_ref()?;
        if guard.effective_scope != *scope
            || guard.authority.account_id != row.owner_account_id
            || row.device_id.as_deref() != Some(guard.authority.device_id.as_str())
            || row.device_authorize_event_id.as_deref()
                != Some(guard.authority.selector.authorization_ref.event_id.as_str())
            || claim.device_authorize_event_id != row.device_authorize_event_id.as_deref()
        {
            return None;
        }
        if scope.canonical_mls_group_id().ok()?.as_str() != group_id
            || claim.intended_realm_id != Some(scope.realm_id().as_str())
        {
            return None;
        }
    }

    let mut next = row.clone();
    if row.last_resort && !terminal_without_claim {
        let realm_id = claim.intended_realm_id?;
        if row
            .last_resort_realm_id
            .as_deref()
            .is_some_and(|bound_realm_id| bound_realm_id != realm_id)
        {
            return None;
        }
        if next.last_resort_realm_id.is_none() {
            next.last_resort_realm_id = Some(realm_id.to_owned());
        }
        return Some(next);
    }

    next.claimed_by_mls_group_id = Some(group_id.to_owned());
    next.claimed_at = (!terminal_without_claim).then_some(claim.claimed_at);
    next.claim_expires_at_unix_ms = if terminal_without_claim {
        None
    } else {
        claim.claim_expires_at_unix_ms
    };
    next.consumed_at = None;
    Some(next)
}

#[cfg(test)]
mod key_package_claim_transition_tests {
    use super::*;

    fn row(last_resort: bool) -> MlsKeyPackageRow {
        MlsKeyPackageRow {
            id: "kp-1".to_owned(),
            keypackage_ref: "ak:mls:keypackage:kp-1".to_owned(),
            keypackage_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            owner_account_id: AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:owner.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            ),
            effective_scope: None,
            actor_id: "ak:did_core:web:agent.example".to_owned(),
            device_id: Some("ak:device:01904100-0000-7000-8000-000000000001".to_owned()),
            endpoint_verification_method: None,
            key_package_bytes: vec![1, 2, 3],
            capabilities: vec!["ak.mls.rfc9420".to_owned()],
            capabilities_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            last_resort,
            last_resort_realm_id: None,
            lifetime_not_before: 1,
            lifetime_not_after: 100,
            claimed_by_mls_group_id: None,
            device_authorize_event_id: Some("event-1".to_owned()),
            agent_key_authorize_event_id: None,
            claimed_at: None,
            claim_expires_at_unix_ms: None,
            consumed_at: None,
            created_at: 1,
        }
    }

    fn claim<'a>(target: MlsKeyPackageClaimTarget<'a>) -> MlsKeyPackageClaim<'a> {
        MlsKeyPackageClaim {
            applet_device_scope_guard: None,
            id: "kp-1",
            target,
            intended_realm_id: None,
            device_authorize_event_id: Some("event-1"),
            agent_key_authorize_event_id: None,
            device_revocation_gate: None,
            claimed_at: 10,
            claim_expires_at_unix_ms: Some(20_000),
        }
    }

    #[test]
    fn exact_publication_retry_preserves_lifecycle_and_does_not_rebind_owner_or_scope() {
        let original = row(false);
        let mut claimed = original.clone();
        claimed.claimed_by_mls_group_id =
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        claimed.claimed_at = Some(10);
        claimed.claim_expires_at_unix_ms = Some(20_000);
        assert!(claimed.same_publication(&original));
        let mut changed = original.clone();
        changed.owner_account_id.station_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:another-station.example").unwrap();
        assert!(!claimed.same_publication(&changed));
        changed = original.clone();
        changed.effective_scope = Some(ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [166; 32],
            )),
        });
        assert!(!claimed.same_publication(&changed));
        changed = original.clone();
        changed.device_authorize_event_id = Some(
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [167; 32])
                .to_string(),
        );
        assert!(!claimed.same_publication(&changed));
    }

    #[test]
    fn ordinary_claim_case_table_covers_acceptance_and_cas_losers() {
        let available = row(false);
        let accepted = apply_key_package_claim(
            &available,
            &claim(MlsKeyPackageClaimTarget::Group("group-a")),
        )
        .expect("available ordinary package is claimable");
        assert_eq!(accepted.claimed_by_mls_group_id.as_deref(), Some("group-a"));
        assert_eq!(accepted.claimed_at, Some(10));
        assert_eq!(accepted.claim_expires_at_unix_ms, Some(20_000));

        let renewed = apply_key_package_claim(
            &accepted,
            &claim(MlsKeyPackageClaimTarget::Group("group-a")),
        );
        assert!(renewed.is_some(), "same-group retry is idempotent renewal");
        assert!(
            apply_key_package_claim(
                &accepted,
                &claim(MlsKeyPackageClaimTarget::Group("group-b"))
            )
            .is_none(),
            "different group loses the CAS"
        );

        let mut expired = claim(MlsKeyPackageClaimTarget::Group("group-a"));
        expired.claimed_at = 100;
        assert!(apply_key_package_claim(&available, &expired).is_none());

        let mut wrong_event = claim(MlsKeyPackageClaimTarget::Group("group-a"));
        wrong_event.device_authorize_event_id = Some("event-2");
        assert!(apply_key_package_claim(&available, &wrong_event).is_none());
    }

    #[test]
    fn claimed_packages_revoke_and_consumed_packages_never_rearm() {
        let published = row(false);
        let claimed = apply_key_package_claim(
            &published,
            &claim(MlsKeyPackageClaimTarget::Group("group-a")),
        )
        .unwrap();
        let revoked =
            apply_key_package_claim(&claimed, &claim(MlsKeyPackageClaimTarget::Revoke)).unwrap();
        assert_eq!(revoked.claimed_by_mls_group_id.as_deref(), Some("revoked"));
        assert!(revoked.claimed_at.is_none());
        assert!(revoked.claim_expires_at_unix_ms.is_none());
        assert!(
            apply_key_package_claim(&revoked, &claim(MlsKeyPackageClaimTarget::Group("group-a")))
                .is_none()
        );
        let mut consumed = claimed.clone();
        consumed.consumed_at = Some(11);
        for target in [
            MlsKeyPackageClaimTarget::Group("group-a"),
            MlsKeyPackageClaimTarget::Group("group-b"),
            MlsKeyPackageClaimTarget::Revoke,
            MlsKeyPackageClaimTarget::Retire,
        ] {
            assert!(apply_key_package_claim(&consumed, &claim(target)).is_none());
        }
        assert!(
            apply_key_package_claim(&row(true), &claim(MlsKeyPackageClaimTarget::Revoke)).is_some()
        );
    }

    #[test]
    fn terminal_and_last_resort_transitions_share_one_oracle() {
        let ordinary = row(false);
        let retired = apply_key_package_claim(&ordinary, &claim(MlsKeyPackageClaimTarget::Retire))
            .expect("unused ordinary package may retire");
        assert_eq!(retired.claimed_by_mls_group_id.as_deref(), Some("retired"));
        assert!(
            apply_key_package_claim(&retired, &claim(MlsKeyPackageClaimTarget::Revoke)).is_none()
        );

        let reusable = row(true);
        assert!(
            apply_key_package_claim(
                &reusable,
                &claim(MlsKeyPackageClaimTarget::Group("group-a"))
            )
            .is_none(),
            "last-resort claim requires an intended realm"
        );
        let mut bound_claim = claim(MlsKeyPackageClaimTarget::Group("group-a"));
        bound_claim.intended_realm_id =
            Some("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K");
        let bound = apply_key_package_claim(&reusable, &bound_claim)
            .expect("last-resort package binds on first realm claim");
        assert_eq!(
            bound.last_resort_realm_id,
            bound_claim.intended_realm_id.map(str::to_owned)
        );
        assert!(bound.claimed_by_mls_group_id.is_none());
        assert!(
            apply_key_package_claim(&reusable, &claim(MlsKeyPackageClaimTarget::Retire)).is_none()
        );
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PeerKeyPackageClaimLedgerWriteResult {
    Inserted,
    Existing(Box<PeerKeyPackageClaimLedgerRecord>),
}
/// The accepted public MLS group of one effective scope: the registered
/// `mls_group` typed current (encryption-and-audit.md §2.5) with the covering
/// Commit of its current revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsGroupCurrentRecord {
    pub realm_id: RealmId,
    pub value: arkret_wire::MlsGroupCurrent,
    pub current_commit_id: arkret_wire::RealmCommitId,
    pub current_stream_position: u64,
    /// Station-private public RFC 9420 tracker state at `value.epoch`, the
    /// base the next transition is verified from. Never a wire value.
    pub public_state: Vec<u8>,
}
/// Internal committed result; the outcome is the shared SDK wire DTO.
pub struct MlsKeyPackageRevocation {
    pub outcome: arkret_models_crypto::KeyPackagesRevokeOutcome,
    pub records: Vec<MlsKeyPackageRow>,
}

/// G3.S1 — KeyPackage store. The `try_claim` CAS path is what
/// guarantees at-most-one Welcome per published KeyPackage.
#[async_trait]
pub trait MlsKeyPackageStore: Send + Sync {
    /// Insert a fresh KeyPackage row. Returns `Ok(false)` if the
    /// `id` is already present (re-publishes of the same id are
    /// idempotent — production fixtures sometimes resubmit on retry).
    async fn put(&self, record: &MlsKeyPackageRow) -> PersistenceResult<bool>;
    /// Publish under the same current native Account/PCR/installation cut.
    async fn put_for_applet_device(
        &self,
        _record: &MlsKeyPackageRow,
        _guard: &crate::AppletManagedDeviceScopeGuard,
        _expires_at: chrono::DateTime<chrono::Utc>,
        _body: &arkret_models_crypto::KeyPackagesUploadRequestBody,
    ) -> PersistenceResult<bool> {
        Err(super::PersistenceError::Conflict(
            "capability_denied: native KeyPackage publication is unavailable".into(),
        ))
    }

    /// Revoke original own material under the current PCR Device cut, even
    /// after an installation fence. No new business material is returned.
    async fn revoke_for_applet_device(
        &self,
        _body: &arkret_models_crypto::KeyPackagesRevokeRequestBody,
        _authority: &crate::AppletManagedDeviceAuthority,
        _scope: &ScopeRef,
        _expires_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<MlsKeyPackageRevocation> {
        Err(super::PersistenceError::Conflict(
            "capability_denied: native KeyPackage revocation is unavailable".into(),
        ))
    }
    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRow>>;
    async fn get_by_ref(&self, keypackage_ref: &str)
    -> PersistenceResult<Option<MlsKeyPackageRow>>;
    /// Atomically claim the named KeyPackage for `mls_group_id`. Returns
    /// `Ok(Some(record))` on success (with `claimed_by_mls_group_id` /
    /// claim-window fields filled in), `Ok(None)` if the row is already
    /// claimed or does not exist. The CAS check + update happens
    /// inside the store so two concurrent callers see at-most-one win.
    async fn try_claim(
        &self,
        claim: MlsKeyPackageClaim<'_>,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>>;
    /// Mark an already claimed ordinary KeyPackage consumed by the same MLS
    /// group. A consume at or after the claim deadline fails closed.
    async fn consume_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        now_unix_ms: i64,
        peer_consume_receipt: Option<&Value>,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>>;
    /// Charge an already authenticated original SDK command against the
    /// shared closed requester, target and source/target budgets. Exact
    /// retries recover their first decision without another charge.
    async fn record_peer_claim_attempt(
        &self,
        body: &arkret_models_crypto::PeerKeyPackagesClaimRequestBody,
    ) -> PersistenceResult<PeerKeyPackageClaimRateDecision>;
    /// Reclaim expired private attempt decisions using the database clock.
    async fn prune_peer_claim_attempts(&self) -> PersistenceResult<usize>;
    /// Read a peer claim ledger row without revealing KeyPackage inventory.
    async fn get_peer_claim(
        &self,
        source_id: &str,
        claim_request_id: &str,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    /// Resolve the ledger row whose stored success outcome issued the exact
    /// `KeypackageClaimId` a Welcome names (`keypackage_claim_ref`).
    async fn get_peer_claim_by_claim_id(
        &self,
        claim_id: &str,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    /// The Welcome binding recorded for `claim_id`, if its Welcome was queued.
    async fn get_claim_welcome_binding(
        &self,
        claim_id: &str,
    ) -> PersistenceResult<Option<MlsWelcomeClaimBinding>>;
    /// Resolve the unique durable ordinary single-use peer-claim fact that
    /// owns a KeyPackage. Reusable last-resort packages intentionally have
    /// multiple independent claim audit rows and are excluded.
    async fn get_peer_claim_by_keypackage_id(
        &self,
        keypackage_id: &str,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    /// Atomically claim one eligible KeyPackage and persist its exact terminal
    /// outcome. Reusable last-resort packages remain published and keep an
    /// independent audit for every claim.
    async fn try_claim_peer(
        &self,
        attempt: PeerKeyPackageClaimAttempt<'_>,
    ) -> PersistenceResult<PeerKeyPackageClaimAttemptResult>;
    /// Persist a terminal outcome that does not transition a KeyPackage, such
    /// as the intentionally opaque `claim_failed` result.
    async fn record_peer_claim_terminal(
        &self,
        record: &PeerKeyPackageClaimLedgerRecord,
    ) -> PersistenceResult<PeerKeyPackageClaimLedgerWriteResult>;
    /// Attach a signed receipt to an existing terminal peer-claim fact. This
    /// never creates a ledger row and therefore cannot fabricate a terminal
    /// state without the original durable request/outcome.
    async fn attach_peer_claim_terminal_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        terminal_receipt: &Value,
        updated_at: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    async fn attach_peer_claim_consume_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        consume_receipt: &Value,
        now_unix_ms: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    /// Replicate a destination-accepted consume fact into an existing source
    /// claim mirror. The signed consume time, rather than replication arrival
    /// time, is checked against the original claim deadline.
    async fn transition_peer_claim_consumed(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        expected_outcome: &Value,
        consume_receipt: &Value,
        consumed_at_unix_ms: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    /// Atomically transition an existing source-side successful claim mirror
    /// to its signed terminal state while preserving its use class, claimed
    /// coordinates, and exact outcome. Returns `None` for a missing row,
    /// state/digest/outcome drift, or a non-terminal target.
    async fn transition_peer_claim_terminal(
        &self,
        transition: PeerClaimTerminalTransition<'_>,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>>;
    /// Close expired peer claim audits atomically. Ordinary single-use claims
    /// revoke their KeyPackage and return its id; last-resort claims only move
    /// their independent audit to `expired` and never return the reusable
    /// KeyPackage id.
    async fn revoke_expired_peer_claims(&self, now_unix_ms: i64) -> PersistenceResult<Vec<String>>;
    /// Snapshot all rows. Diagnostics + the integration test rely on it.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRow>>;
    /// All rows claimed by `mls_group_id` (excluding the terminal sentinel
    /// `"revoked"` and `"retired"` states). Ordered by `claimed_at` then `id` so callers
    /// get a stable leaf iteration order. Feeds the minimal-metadata
    /// author-credential admission view (encryption-and-audit.md §2.10.3).
    async fn list_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> PersistenceResult<Vec<MlsKeyPackageRow>>;
}
/// Durable reads of the `mls_group` typed current. Only the accepting
/// transactions of `ak.mls.genesis`, `ak.mls.commit` and the membership
/// changes that advance a key-access revision write it.
#[async_trait]
pub trait MlsGroupCurrentStore: Send + Sync {
    /// The current group of `effective_scope`, if its Genesis is accepted.
    async fn current(
        &self,
        effective_scope: &arkret_wire::ScopeRef,
    ) -> PersistenceResult<Option<MlsGroupCurrentRecord>>;
    /// Every current group of one Realm, Realm scope first.
    async fn realm_currents(
        &self,
        realm_id: &RealmId,
    ) -> PersistenceResult<Vec<MlsGroupCurrentRecord>>;
    /// Install one current group row directly, for fixtures that exercise
    /// its readers without an accepted MLS Event.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    async fn seed_test_current(&self, record: &MlsGroupCurrentRecord) -> PersistenceResult<()>;
}
