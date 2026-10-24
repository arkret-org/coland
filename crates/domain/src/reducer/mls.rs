//! MLS KeyPackage ledger projection helpers.
//!
//! `ak.mls.genesis` and `ak.mls.commit` do not reach the reducer: their
//! `mls_group` current state is written by the guarded authority unit
//! of work at the covering RealmCommit. KeyPackage publication is not an
//! Event: `prepare_keypackage_upload_projection` validates the dedicated
//! KeyPackage ledger projection that `/_arkret/self/keys/keypackages/*`
//! writes through.

use super::{
    KeyPackageLifetimeProjection, MlsEffect, MlsKeyPackageProjection, ProjectionEffect,
    ProjectionState,
};

/// Reason code emitted when a KeyPackage ledger claim targets a KeyPackage that has already been
/// claimed. Routing layer maps to HTTP 409 `cas_conflict`.
pub const REASON_KEYPACKAGE_ALREADY_CLAIMED: &str = "mls_keypackage_already_claimed";
/// Reason code emitted when a KeyPackage ledger claim targets an unknown KeyPackage id.
pub const REASON_KEYPACKAGE_NOT_FOUND: &str = "mls_keypackage_not_found";
/// Reason code emitted when a KeyPackage publish/claim carries a Realm mismatch.
pub const REASON_KEYPACKAGE_REALM_MISMATCH: &str = "mls_keypackage_realm_mismatch";

#[derive(Clone, Debug)]
pub enum MlsKeyPackagePublishTrustAnchor {
    DeviceAuthorize(String),
    AgentKeyAuthorize {
        event_id: String,
        verification_method: String,
    },
}

/// Strongly typed local projection input for a KeyPackage upload.
///
/// This is not an Arkret Event payload. KeyPackage upload is an HTTP/storage
/// workflow, so it must not manufacture a `ProjectedEventOperation` merely to
/// reuse reducer code.
#[derive(Clone, Debug)]
pub struct MlsKeyPackagePublishProjection {
    pub keypackage_id: String,
    pub keypackage_ref: String,
    pub keypackage_digest: String,
    /// Complete Account owner; never a service-local SQL identity.
    pub owner_actor_id: arkret_wire::ActorId,
    pub effective_scope: Option<arkret_wire::ScopeRef>,
    pub actor_id: String,
    pub device_id: Option<String>,
    pub lifetime: KeyPackageLifetimeProjection,
    pub key_package_bytes: Vec<u8>,
    pub capabilities: Vec<String>,
    pub last_resort: bool,
    pub trust_anchor: MlsKeyPackagePublishTrustAnchor,
    pub created_at: i64,
}

pub fn prepare_keypackage_upload_projection(
    projection: &MlsKeyPackagePublishProjection,
) -> Result<MlsKeyPackageProjection, &'static str> {
    if projection.keypackage_id.is_empty() {
        return Err("mls_keypackage_id_missing");
    }
    if projection.actor_id.is_empty() {
        return Err("mls_keypackage_actor_missing");
    }
    if projection.lifetime.not_after <= projection.lifetime.not_before {
        return Err("mls_keypackage_lifetime_invalid");
    }
    if projection.key_package_bytes.is_empty() {
        return Err("mls_keypackage_bytes_empty");
    }
    let computed_keypackage_digest = arkret_canonical::sha256_digest(&projection.key_package_bytes);
    if projection.keypackage_digest != computed_keypackage_digest {
        return Err("mls_keypackage_digest_mismatch");
    }
    let capabilities_digest = match arkret_canonical::canonical_json_bytes(&projection.capabilities)
    {
        Ok(bytes) => arkret_canonical::sha256_digest(bytes),
        Err(_) => return Err("mls_keypackage_capabilities_digest_failed"),
    };
    let (device_authorize_event_id, agent_key_authorize_event_id, endpoint_verification_method) =
        match &projection.trust_anchor {
            MlsKeyPackagePublishTrustAnchor::DeviceAuthorize(event_id) => {
                if projection.device_id.is_none() {
                    return Err("mls_keypackage_device_missing");
                }
                (Some(event_id.clone()), None, None)
            }
            MlsKeyPackagePublishTrustAnchor::AgentKeyAuthorize {
                event_id,
                verification_method,
            } => (
                None,
                Some(event_id.clone()),
                Some(verification_method.clone()),
            ),
        };
    Ok(MlsKeyPackageProjection {
        id: projection.keypackage_id.clone(),
        keypackage_ref: projection.keypackage_ref.clone(),
        keypackage_digest: projection.keypackage_digest.clone(),
        owner_actor_id: projection.owner_actor_id.clone(),
        effective_scope: projection.effective_scope.clone(),
        actor_id: projection.actor_id.clone(),
        device_id: projection.device_id.clone(),
        endpoint_verification_method,
        lifetime: projection.lifetime.clone(),
        key_package_bytes: projection.key_package_bytes.clone(),
        capabilities: projection.capabilities.clone(),
        capabilities_digest,
        last_resort: projection.last_resort,
        last_resort_realm_id: None,
        claimed_by: None,
        device_authorize_event_id,
        agent_key_authorize_event_id,
        claimed_at: None,
        claim_expires_at_unix_ms: None,
        consumed_at: None,
        created_at: projection.created_at,
    })
}

#[cfg(test)]
fn apply_keypackage_upload_projection(
    state: &mut ProjectionState,
    projection: &MlsKeyPackagePublishProjection,
) -> ProjectionEffect {
    let row = match prepare_keypackage_upload_projection(projection) {
        Ok(row) => row,
        Err(reason) => return reject(reason),
    };
    // Insert is structural — duplicates of the same `keypackage_id`
    // replace in place (a republish of the same id by the same device
    // re-arms the row; the device is the sole source-of-truth for the
    // opaque bytes). Production deployments will route duplicate-id
    // detection through the wire validator before reaching here.
    state
        .mls_key_packages
        .insert(projection.keypackage_id.clone(), row);

    ProjectionEffect::Mls(MlsEffect::KeyPackagePublished {
        keypackage_id: projection.keypackage_id.clone(),
        actor_id: projection.actor_id.clone(),
        device_id: projection.device_id.clone(),
    })
}

/// Strongly typed local projection input for a KeyPackage claim.
///
/// Claiming is not an Arkret Event either: it is the compare-and-swap step of
/// the dedicated KeyPackage ledger that `/_arkret/self/keys/keypackages/*`
/// writes through. Keeping it typed is what stops a caller from reaching the
/// CAS with a hand-built `ProjectedEventOperation`.
#[derive(Clone, Debug)]
pub struct MlsKeyPackageClaimProjection {
    pub keypackage_id: String,
    /// MLS group reserving this KeyPackage. Two concurrent claims for
    /// different groups must resolve to exactly one winner.
    pub group_id: String,
    /// Realm a last-resort KeyPackage is bound to on first claim.
    pub intended_realm_id: Option<String>,
    pub trust_binding: KeyPackageTrustBinding,
    /// Reservation deadline. `None` means "as long as the KeyPackage lives".
    pub claim_expires_at_unix_ms: Option<i64>,
    pub claimed_at: i64,
}

/// Atomic compare-and-swap claim of a published KeyPackage.
///
/// Concurrency contract: two concurrent claims against the same
/// `keypackage_id` MUST produce exactly one `KeyPackageClaimed` effect; the
/// loser receives `Rejected { reason: mls_keypackage_already_claimed }`, which
/// the routing layer maps to HTTP 409 `cas_conflict`. Without it two Welcomes
/// could target the same init key.
pub fn apply_keypackage_claim_projection(
    state: &mut ProjectionState,
    projection: &MlsKeyPackageClaimProjection,
) -> ProjectionEffect {
    if projection.keypackage_id.is_empty() {
        return reject("mls_keypackage_id_missing");
    }
    if projection.group_id.is_empty() {
        return reject("mls_keypackage_group_missing");
    }
    let claimed_at = projection.claimed_at;
    let group_id = projection.group_id.as_str();
    let Some(row) = state.mls_key_packages.get_mut(&projection.keypackage_id) else {
        return reject(REASON_KEYPACKAGE_NOT_FOUND);
    };
    if row.claimed_by.as_deref() == Some("revoked") {
        return reject(REASON_KEYPACKAGE_NOT_FOUND);
    }
    // CAS check — refuse if a *different* group has already claimed this row.
    // A repeat claim by the same MLS group is idempotent renewal: a resolver
    // whose materialization was interrupted retries with the same reserved
    // group id after the claim window lapsed. The Welcome target is unchanged,
    // so renewal cannot create cross-group init-key reuse.
    if !row.last_resort
        && row
            .claimed_by
            .as_deref()
            .is_some_and(|claimed| claimed != group_id)
    {
        return reject(REASON_KEYPACKAGE_ALREADY_CLAIMED);
    }
    // Lifetime check — RFC 9420 §10. Stale KeyPackages cannot be claimed.
    if claimed_at >= row.lifetime.not_after {
        return reject(arkret_wire::ReasonCode::KEYPACKAGE_EXPIRED);
    }
    if row.device_authorize_event_id != projection.trust_binding.device_authorize_event_id
        || row.agent_key_authorize_event_id != projection.trust_binding.agent_key_authorize_event_id
    {
        return reject(arkret_wire::ReasonCode::DEVICE_GENERATION_FENCED);
    }
    let intended_realm_id = projection
        .intended_realm_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if row.last_resort {
        // A last-resort KeyPackage is never consumed, so it carries no claim
        // window; it binds to one Realm on first claim and stays there.
        let Some(realm_id) = intended_realm_id.as_deref() else {
            return reject(REASON_KEYPACKAGE_REALM_MISMATCH);
        };
        if row
            .last_resort_realm_id
            .as_deref()
            .is_some_and(|bound_realm_id| bound_realm_id != realm_id)
        {
            return reject(REASON_KEYPACKAGE_REALM_MISMATCH);
        }
        if row.last_resort_realm_id.is_none() {
            row.last_resort_realm_id = Some(realm_id.to_owned());
        }
    } else {
        let claim_expires_at_unix_ms = projection
            .claim_expires_at_unix_ms
            .unwrap_or_else(|| row.lifetime.not_after.saturating_mul(1000));
        if claim_expires_at_unix_ms <= claimed_at.saturating_mul(1000)
            || claim_expires_at_unix_ms > row.lifetime.not_after.saturating_mul(1000)
        {
            return reject(arkret_wire::ReasonCode::KEYPACKAGE_EXPIRED);
        }
        row.claimed_by = Some(group_id.to_owned());
        row.claimed_at = Some(claimed_at);
        row.claim_expires_at_unix_ms = Some(claim_expires_at_unix_ms);
        row.consumed_at = None;
    }

    ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed {
        keypackage_id: projection.keypackage_id.clone(),
        group_id: projection.group_id.clone(),
        intended_realm_id,
        last_resort: row.last_resort,
        claimed_at,
    })
}

fn reject(reason: &str) -> ProjectionEffect {
    ProjectionEffect::Rejected {
        reason: reason.to_owned(),
    }
}

/// Exactly-one-of trust binding carried by every KeyPackage publication and
/// claim: device authorization or Agent key authorization.
///
/// Owned here because the reducer validates it off the wire payload and the
/// `/keys/keypackages/*` routing layer validates the same shape off the stored
/// row; both surfaces must enforce one closed set and one
/// `claim_generation_mismatch` reason code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackageTrustBinding {
    pub device_authorize_event_id: Option<String>,
    pub agent_key_authorize_event_id: Option<String>,
}

impl KeyPackageTrustBinding {
    pub fn device_authorize(device_authorize_event_id: String) -> Self {
        Self {
            device_authorize_event_id: Some(device_authorize_event_id),
            agent_key_authorize_event_id: None,
        }
    }

    pub fn agent_key_authorize(agent_key_authorize_event_id: String) -> Self {
        Self {
            device_authorize_event_id: None,
            agent_key_authorize_event_id: Some(agent_key_authorize_event_id),
        }
    }

    /// Enforce the exactly-one-of rule. Absent, empty and whitespace-only ids
    /// all count as absent; accepted ids are stored trimmed so the reducer and
    /// the routing layer compare identical bytes.
    pub fn from_parts(
        device_authorize_event_id: Option<String>,
        agent_key_authorize_event_id: Option<String>,
    ) -> Result<Self, &'static str> {
        let device_authorize_event_id = non_empty_trimmed(device_authorize_event_id);
        let agent_key_authorize_event_id = non_empty_trimmed(agent_key_authorize_event_id);
        match (device_authorize_event_id, agent_key_authorize_event_id) {
            (Some(event_id), None) => Ok(Self::device_authorize(event_id)),
            (None, Some(event_id)) => Ok(Self::agent_key_authorize(event_id)),
            _ => Err(arkret_wire::ReasonCode::DEVICE_GENERATION_FENCED),
        }
    }
}

fn non_empty_trimmed(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

// ──────────────────────────── tests ───────────────────────────────────

#[cfg(test)]
mod tests;
