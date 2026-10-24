use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;

#[cfg(any(test, feature = "test-support"))]
use arkret_models_identity::HandleClaim;
#[cfg(test)]
use arkret_models_identity::HandleClaimStatus;
pub use coland_storage::{
    HandleClaimEvidenceRecord, MemberIdentityEventRecord, MemberIdentitySubjectKey,
};
#[cfg(any(test, feature = "test-support"))]
use serde_json::Value;

/// Disposable Realm/member identity projection. Hydration rebuilds every
/// assertion from accepted canonical Events joined to their RealmCommits.
/// The accepting domain writer owns the expected-state guard; inner display
/// proofs and replacement edges remain consumer verification semantics.
#[derive(Clone, Debug, Default)]
pub struct MemberIdentityRegistry {
    /// All accepted events, keyed by `event_id`.
    events: BTreeMap<String, MemberIdentityEventRecord>,
    /// Index from `(realm_id, actor_id, segment)` → event_ids that
    /// landed against that cell subject, in arrival order.
    by_subject: BTreeMap<MemberIdentitySubjectKey, Vec<String>>,
    /// Local handle-claim evidence cache keyed by claim `subject`.
    /// Sources are deliberately local-only: directory-issued signed claims
    /// and handle-claim envelopes carried by accepted identity events.
    handle_claims_by_subject: BTreeMap<arkret_wire::DidCoreId, Vec<HandleClaimEvidenceRecord>>,
}

#[cfg(test)]
/// Effective updates used by the accepted-state optimistic concurrency guard:
/// each unreplaced update's Event ID with its exact signed payload.
/// Concurrent unreplaced identity events remain separate entries.
#[derive(Clone, Debug, Default)]
struct MemberIdentitySnapshot {
    effective: Vec<(arkret_identifiers::EventId, Value)>,
}

impl MemberIdentityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an accepted event. Replaces any prior entry under the same
    /// `event_id` (idempotent re-projection on replay).
    pub fn insert(&mut self, record: MemberIdentityEventRecord) {
        let key = record.subject.clone();
        let event_id = record.event_id.clone();
        let bucket = self.by_subject.entry(key).or_default();
        if !bucket.iter().any(|id| id == &event_id) {
            bucket.push(event_id.clone());
        }
        self.events.insert(event_id, record);
    }

    /// Insert one already-digested claim record. The durable write-through
    /// path and startup hydration both land here.
    pub fn restore_handle_claim(&mut self, record: HandleClaimEvidenceRecord) {
        let bucket = self
            .handle_claims_by_subject
            .entry(record.subject_id.clone())
            .or_default();
        if let Some(existing) = bucket
            .iter_mut()
            .find(|existing| existing.digest == record.digest)
        {
            *existing = record;
        } else {
            bucket.push(record);
            bucket.sort_by(|a, b| a.digest.cmp(&b.digest));
        }
    }

    pub fn invalidate_handle_claims_for_subject(
        &mut self,
        subject_id: &arkret_wire::DidCoreId,
    ) -> usize {
        self.handle_claims_by_subject
            .remove(subject_id)
            .map(|claims| claims.len())
            .unwrap_or(0)
    }

    /// Snapshot every locally-cached handle-claim evidence record keyed by
    /// claim `subject`. Drives the operator handles admin surface
    /// (`GET /_coland/admin/handles`). The cache is durable through the
    /// `MemberIdentityStore` write-through; the directory-side handle CRDT
    /// projection is still not wired, so this evidence cache remains the
    /// authoritative read source until it lands.
    pub fn snapshot_handle_claims(
        &self,
    ) -> std::collections::BTreeMap<arkret_wire::DidCoreId, Vec<HandleClaimEvidenceRecord>> {
        self.handle_claims_by_subject.clone()
    }

    #[cfg(test)]
    /// Build a [`MemberIdentitySnapshot`] across all segments under
    /// `(realm_id, actor_id)`. Applies the replacement-edge filter per
    /// MID-2/3, sorts by `(segment, event_id)`, and computes the
    /// projection digest per MID-6.
    fn snapshot_for_actor(&self, realm_id: &str, actor_id: &str) -> Option<MemberIdentitySnapshot> {
        let candidates: Vec<&MemberIdentityEventRecord> = self
            .by_subject
            .iter()
            .filter(|(key, _)| key.realm_id == realm_id && key.actor_id == actor_id)
            .flat_map(|(_, ids)| ids.iter().filter_map(|id| self.events.get(id.as_str())))
            .collect();
        if candidates.is_empty() {
            return None;
        }
        // Drop events that any other valid replacement edge points at —
        // "valid" meaning the edge's `payload_digest` matches the
        // referenced event's stored digest AND the edge sits in the same
        // `(realm_id, actor_id, segment)` cell as the referenced event.
        let by_id: BTreeMap<&str, &MemberIdentityEventRecord> = candidates
            .iter()
            .map(|r| (r.event_id.as_str(), *r))
            .collect();
        let mut replaced = BTreeSet::<String>::new();
        for record in &candidates {
            for edge in &record.replaces {
                let Some(referenced) = by_id.get(edge.event_id.as_str()) else {
                    continue;
                };
                if referenced.subject != record.subject {
                    continue; // cross-cell reference is a no-op edge
                }
                if referenced.payload_digest != edge.payload_digest {
                    continue; // mismatched digest is a no-op edge
                }
                replaced.insert(edge.event_id.clone());
            }
        }
        let mut effective: Vec<&MemberIdentityEventRecord> = candidates
            .into_iter()
            .filter(|r| !replaced.contains(r.event_id.as_str()))
            .collect();
        effective.sort_by(|a, b| {
            a.subject
                .segment
                .cmp(&b.subject.segment)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });

        let effective = effective
            .iter()
            .filter_map(|record| {
                let event_id = match arkret_identifiers::EventId::new(record.event_id.clone()) {
                    Ok(event_id) => event_id,
                    Err(error) => {
                        tracing::warn!(
                            event_id = %record.event_id,
                            %error,
                            "skipping corrupt member-identity record with invalid event id"
                        );
                        return None;
                    }
                };
                let Some(payload) = record.raw_event.get("payload") else {
                    tracing::warn!(
                        event_id = %record.event_id,
                        "skipping corrupt member-identity record without its signed payload"
                    );
                    return None;
                };
                Some((event_id, payload.clone()))
            })
            .collect();

        Some(MemberIdentitySnapshot { effective })
    }
}

/// Build the storable evidence record for one closed HandleClaim status view.
/// The durable key is the stable core `claim_digest`; freshness and revocation
/// state remain explicit mutable status-view fields.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn handle_claim_record_from_envelope(
    envelope: &Value,
) -> Option<HandleClaimEvidenceRecord> {
    let claim: HandleClaim = serde_json::from_value(envelope.clone()).ok()?;
    claim.validate().ok()?;
    let status = serde_json::to_value(claim.status)
        .ok()?
        .as_str()?
        .to_owned();
    let visibility = serde_json::to_value(claim.claim.visibility)
        .ok()?
        .as_str()?
        .to_owned();
    // The status view carries no digest mirrors; both are recomputed from the
    // carried `claim` / `revocation` (`conformance/encoding.md` §4.0.1).
    Some(HandleClaimEvidenceRecord {
        digest: claim.claim_digest().ok()?.to_string(),
        subject_id: claim.claim.subject_account_id.principal_id.clone(),
        issuer_id: claim.claim.issuer_id.clone(),
        audience: claim.claim.audience.clone(),
        status,
        revocation_digest: claim
            .revocation
            .as_ref()
            .and_then(|revocation| revocation.digest().ok())
            .map(|digest| digest.to_string()),
        cache_expires_at: claim.cache_expires_at,
        visibility: Some(visibility),
        expires_at: claim.claim.expires_at,
        envelope: envelope.clone(),
    })
}

#[cfg(test)]
pub(crate) fn test_handle_claim(
    subject_account_id: arkret_wire::AccountId,
    issuer_id: arkret_wire::DidCoreId,
    audience: Option<String>,
    expires_at: chrono::DateTime<chrono::Utc>,
    status: HandleClaimStatus,
    handle_aliases: Vec<String>,
) -> HandleClaim {
    use arkret_models_identity::{
        HANDLE_CLAIM_PROOF_DOMAIN, HANDLE_CLAIM_REVOCATION_DOMAIN, HANDLE_CLAIM_STATUS_DOMAIN,
        Handle, HandleClaimCore, HandleClaimRevocation, HandleClaimRevoker, HandleClaimVariant,
        HandleVisibility,
    };
    use arkret_wire::{DidUrl, Hash, PayloadProof, PayloadProofPurpose};

    let issued_at = expires_at - chrono::Duration::minutes(1);
    let verification_method = DidUrl::new(format!(
        "did:{}#handle-claim-fixture",
        issuer_id
            .as_str()
            .strip_prefix("ak:did_core:")
            .unwrap_or(issuer_id.as_str())
    ))
    .unwrap();
    let placeholder = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    let proof = |purpose, domain: &str, payload_digest| PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: verification_method.clone(),
        payload_digest,
        created_at: issued_at,
        domain: Some(domain.to_owned()),
        audience: None,
        proof_purpose: Some(purpose),
        jws: "eyJhbGciOiJFZERTQSJ9..c2ln".to_owned(),
    };
    let mut core = HandleClaimCore {
        schema: HandleClaimCore::SCHEMA.to_owned(),
        handle: Handle::parse("alice:coland.local").unwrap(),
        handle_aliases,
        subject_account_id: subject_account_id.clone(),
        issuer_id: issuer_id.clone(),
        claim: HandleClaimVariant::HandleBinding,
        visibility: if audience.is_some() {
            HandleVisibility::Restricted
        } else {
            HandleVisibility::Public
        },
        audience,
        issued_at,
        expires_at: Some(expires_at),
        source_refs: Vec::new(),
        proofs: [
            proof(
                PayloadProofPurpose::IssuerAttestation,
                HANDLE_CLAIM_PROOF_DOMAIN,
                placeholder.clone(),
            ),
            proof(
                PayloadProofPurpose::HolderAcceptance,
                HANDLE_CLAIM_PROOF_DOMAIN,
                placeholder.clone(),
            ),
        ],
    };
    let claim_digest = core.claim_digest().unwrap();
    core.proofs[0].payload_digest = claim_digest.clone();
    core.proofs[1].payload_digest = claim_digest.clone();
    let mut revocation = (status == HandleClaimStatus::Revoked).then(|| HandleClaimRevocation {
        schema: HandleClaimRevocation::SCHEMA.to_owned(),
        claim_digest: claim_digest.clone(),
        revoked_at: issued_at,
        revoker: HandleClaimRevoker::Issuer {
            issuer_id: issuer_id.clone(),
        },
        proof: proof(
            PayloadProofPurpose::RevocationAuthorization,
            HANDLE_CLAIM_REVOCATION_DOMAIN,
            placeholder.clone(),
        ),
    });
    if let Some(revocation) = revocation.as_mut() {
        revocation.proof.payload_digest = revocation.digest().unwrap();
    }
    let mut claim = HandleClaim {
        schema: HandleClaim::SCHEMA.to_owned(),
        claim: core,
        status,
        evaluated_at: issued_at,
        verifier_id: issuer_id,
        verified_at: (status == HandleClaimStatus::Verified).then_some(issued_at),
        revocation,
        cache_expires_at: expires_at.min(issued_at + chrono::Duration::seconds(300)),
        status_proof: proof(
            PayloadProofPurpose::StatusAttestation,
            HANDLE_CLAIM_STATUS_DOMAIN,
            placeholder,
        ),
    };
    claim.status_proof.payload_digest = claim.status_digest().unwrap();
    claim.validate().unwrap();
    claim
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn account_actor(station: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new(station).unwrap(),
        ))
    }

    #[test]
    fn corrupt_record_is_skipped_without_hiding_valid_snapshot_entries() {
        let subject = MemberIdentitySubjectKey {
            realm_id: "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
            actor_id: account_actor("ak:did_core:web:station-a.example").to_string(),
            segment: "member_identity".to_owned(),
        };
        let mut registry = MemberIdentityRegistry::new();
        for (event_id, payload_digest) in [
            (
                "not-an-event-id",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ] {
            registry.insert(MemberIdentityEventRecord {
                event_id: event_id.to_owned(),
                subject: subject.clone(),
                payload_digest: payload_digest.to_owned(),
                replaces: Vec::new(),
                raw_event: json!({
                    "payload": {
                        "identity_payload": {
                            "member_identity": {
                                "subject_actor_id": account_actor("ak:did_core:web:station-a.example")
                            }
                        }
                    }
                }),
            });
        }

        let snapshot = registry
            .snapshot_for_actor(&subject.realm_id, &subject.actor_id)
            .expect("the valid record should still produce a snapshot");
        assert_eq!(snapshot.effective.len(), 1);
        assert_eq!(
            snapshot.effective[0].0.as_str(),
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"
        );
        assert!(
            registry
                .snapshot_for_actor(
                    &subject.realm_id,
                    &account_actor("ak:did_core:web:station-b.example").to_string()
                )
                .is_none()
        );
        assert!(
            registry
                .snapshot_for_actor(&subject.realm_id, "ak:did_core:web:alice.example")
                .is_none()
        );
    }

    #[test]
    fn handle_claim_cache_retains_exact_account_evidence_and_rejects_bare_subject() {
        let account = account_actor("ak:did_core:web:station-a.example")
            .as_account_id()
            .unwrap()
            .clone();
        let envelope = serde_json::to_value(test_handle_claim(
            account.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
            None,
            chrono::Utc::now() + chrono::Duration::hours(1),
            HandleClaimStatus::Verified,
            Vec::new(),
        ))
        .unwrap();
        let record = handle_claim_record_from_envelope(&envelope).unwrap();
        assert_eq!(record.subject_id, account.principal_id);
        assert_eq!(
            record.envelope["claim"]["subject_account_id"],
            json!(account)
        );
        assert!(
            handle_claim_record_from_envelope(&json!({
                "subject_id": "ak:did_core:web:alice.example",
                "issuer_id": "ak:did_core:web:station-a.example"
            }))
            .is_none()
        );
    }
}
