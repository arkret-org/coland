//! Signed, complete MLS roster pages over one governing read cut.

use arkret_models_collaboration::mls_roster_authority::{
    MlsRosterAuthorityManifest, MlsRosterAuthorityReadOutcome, MlsRosterAuthorityReadRequestBody,
    MlsRosterRecord,
};
use arkret_models_crypto::KeyOperationSignature;
use arkret_wire::{
    ActorId, Base64UrlString, Did, DidCoreId, DidUrl, EventId, Hash, NonEmptyString,
    project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use coland_storage::{MlsRosterAuthorityFacts, MlsRosterAuthorityRead};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use super::AuthorityCommitApplication;
use crate::{ServiceError, ServiceResult};

const PAGE_SIZE: usize = 8;
const MAX_PAGE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "Preserve the public roster read API and complete signed page outcome."
)]
pub enum MlsRosterAuthorityApplicationRead {
    NotFound,
    CursorInvalid,
    RevisionUnavailable,
    /// The Account Station proved its local member cut. The self route must
    /// forward to governance and verify the signed complete result there.
    ForwardRequired,
    Page(MlsRosterAuthorityReadOutcome),
}

#[derive(Clone, Debug)]
pub enum MlsRosterAuthorityPreflight {
    NotFound,
    RevisionUnavailable,
    ForwardRequired,
    /// The signing read repeats authorization and verifies every frozen
    /// historical resolution before disclosing a page.
    Authorized {
        authority_head_commit_event_ref: EventId,
    },
}

/// Internal page marker. It is not an authorization token: every page reruns
/// the full database authorization, history completeness and digest check.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    request_digest: Hash,
    caller_actor_id: ActorId,
    authority_head_commit_event_ref: EventId,
    records_digest: Hash,
    page_index: u64,
    next_record_offset: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    issued_at: DateTime<Utc>,
}

fn invalid(detail: impl Into<String>) -> ServiceError {
    ServiceError::SchemaViolation(detail.into())
}

fn internal(detail: impl Into<String>) -> ServiceError {
    ServiceError::Internal(detail.into())
}

fn cursor_request_digest(request: &MlsRosterAuthorityReadRequestBody) -> ServiceResult<Hash> {
    let mut selector = request.clone();
    selector.cursor = None;
    Hash::new(
        arkret_canonical::canonical_sha256(&selector)
            .map_err(|error| internal(error.to_string()))?,
    )
    .map_err(|error| internal(error.to_string()))
}

fn decode_cursor(value: &str) -> Option<Cursor> {
    let bytes = arkret_canonical::base64url::base64url_decode(value.as_bytes()).ok()?;
    if arkret_canonical::base64url::base64url_encode(&bytes) != value {
        return None;
    }
    let cursor: Cursor = serde_json::from_slice(&bytes).ok()?;
    (arkret_canonical::canonical_json_bytes(&cursor).ok()? == bytes).then_some(cursor)
}

fn encode_cursor(cursor: &Cursor) -> ServiceResult<String> {
    let bytes = arkret_canonical::canonical_json_bytes(cursor)
        .map_err(|error| internal(error.to_string()))?;
    let value = arkret_canonical::base64url::base64url_encode(&bytes);
    if value.is_empty() || value.len() > 1024 {
        return Err(internal("MLS roster cursor exceeds its closed wire bound"));
    }
    Ok(value)
}

fn signing_method_belongs_to_issuer(method: &DidUrl, issuer: &DidCoreId) -> bool {
    let Some((did, fragment)) = method.as_str().split_once('#') else {
        return false;
    };
    !fragment.is_empty()
        && Did::new(did.to_owned())
            .ok()
            .and_then(|did| project_did_to_core_id(&did).ok())
            .as_ref()
            == Some(issuer)
}

impl AuthorityCommitApplication {
    pub async fn mls_member_roster_selector(
        &self,
        request: &arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody,
        issuer: &DidCoreId,
    ) -> ServiceResult<coland_storage::MlsMemberRosterSelectorRead> {
        request
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        Ok(self
            .store()
            .mls_member_roster_selector(request, issuer)
            .await?)
    }

    pub async fn mls_roster_authority_attestors(
        &self,
        request: &MlsRosterAuthorityReadRequestBody,
        issuer: &DidCoreId,
        source_peer: Option<&DidCoreId>,
    ) -> ServiceResult<MlsRosterAuthorityPreflight> {
        request
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        Ok(
            match self
                .store()
                .mls_roster_authority_read(request, issuer, source_peer)
                .await?
            {
                MlsRosterAuthorityRead::NotFound => MlsRosterAuthorityPreflight::NotFound,
                MlsRosterAuthorityRead::RevisionUnavailable => {
                    MlsRosterAuthorityPreflight::RevisionUnavailable
                }
                MlsRosterAuthorityRead::Authorized { facts: None } => {
                    MlsRosterAuthorityPreflight::ForwardRequired
                }
                MlsRosterAuthorityRead::Authorized { facts: Some(facts) } => {
                    if !verify_historical_proofs(&facts) {
                        return Ok(MlsRosterAuthorityPreflight::RevisionUnavailable);
                    }
                    MlsRosterAuthorityPreflight::Authorized {
                        authority_head_commit_event_ref: facts.authority_head_commit_event_ref,
                    }
                }
            },
        )
    }

    /// Build one signed page from a freshly reauthorized and fully verified
    /// historical set. `now` comes from the serving Station clock; subsequent
    /// pages carry the first page's issuance instant in the opaque cursor.
    #[expect(
        clippy::too_many_arguments,
        reason = "The authenticated roster read binds the request, issuer, signature, station, cursor and current cut."
    )]
    pub async fn mls_roster_authority_read(
        &self,
        request: &MlsRosterAuthorityReadRequestBody,
        issuer: &DidCoreId,
        source_peer: Option<&DidCoreId>,
        preflight_head_commit_event_ref: &EventId,
        verification_method: &DidUrl,
        signing_key: &SigningKey,
        now: DateTime<Utc>,
    ) -> ServiceResult<MlsRosterAuthorityApplicationRead> {
        request
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        if !signing_method_belongs_to_issuer(verification_method, issuer) {
            return Err(invalid(
                "MLS roster signing method belongs to another Station",
            ));
        }
        let facts = match self
            .store()
            .mls_roster_authority_read(request, issuer, source_peer)
            .await?
        {
            MlsRosterAuthorityRead::NotFound => {
                return Ok(MlsRosterAuthorityApplicationRead::NotFound);
            }
            MlsRosterAuthorityRead::RevisionUnavailable => {
                return Ok(MlsRosterAuthorityApplicationRead::RevisionUnavailable);
            }
            MlsRosterAuthorityRead::Authorized { facts: None } => {
                return Ok(MlsRosterAuthorityApplicationRead::ForwardRequired);
            }
            MlsRosterAuthorityRead::Authorized { facts: Some(facts) } => facts,
        };
        if !facts_match_preflight(&facts, preflight_head_commit_event_ref) {
            return Ok(MlsRosterAuthorityApplicationRead::RevisionUnavailable);
        }
        sign_page(
            request,
            issuer,
            verification_method,
            signing_key,
            now,
            facts,
        )
    }
}

fn verify_historical_proofs(facts: &MlsRosterAuthorityFacts) -> bool {
    let mut proofs = facts.historical_add_proofs.iter();
    for record in &facts.records {
        if let MlsRosterRecord::Add {
            attestation,
            claim_issuer_resolution,
            attestor_resolution,
            ..
        } = record
        {
            let Some(proof) = proofs.next() else {
                return false;
            };
            if arkret_canonical::canonical_json_bytes(attestation).ok()
                != arkret_canonical::canonical_json_bytes(&proof.attestation).ok()
                || record.validate_shape().is_err()
                || arkret_identity::verify_authenticated_service_resolution_history(
                    attestor_resolution,
                    &attestation.attestor_station_id,
                    attestation.attested_at,
                )
                .is_err()
                || arkret::verify_mls_attest_add_request(
                    proof,
                    claim_issuer_resolution
                        .as_ref()
                        .unwrap_or(attestor_resolution),
                    attestor_resolution,
                )
                .is_err()
            {
                return false;
            }
        }
    }
    proofs.next().is_none()
}

fn facts_match_preflight(
    facts: &MlsRosterAuthorityFacts,
    preflight_head_commit_event_ref: &EventId,
) -> bool {
    &facts.authority_head_commit_event_ref == preflight_head_commit_event_ref
        && verify_historical_proofs(facts)
}

fn signed_manifest(
    manifest: &mut MlsRosterAuthorityManifest,
    request: &MlsRosterAuthorityReadRequestBody,
    verification_method: &DidUrl,
    signing_key: &SigningKey,
) -> ServiceResult<()> {
    manifest
        .validate_for_request(request)
        .map_err(|error| internal(error.to_string()))?;
    manifest.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &signing_key.to_bytes(),
        verification_method.as_str(),
        &manifest
            .signing_bytes()
            .map_err(|error| internal(error.to_string()))?,
    )
    .map_err(|error| internal(error.to_string()))?;
    Ok(())
}

fn roster_page(
    records: &[MlsRosterRecord],
    manifest: &MlsRosterAuthorityManifest,
    request_digest: &Hash,
    start: usize,
    end: usize,
    page_index: usize,
) -> ServiceResult<MlsRosterAuthorityReadOutcome> {
    let next_cursor = if end < records.len() {
        Some(encode_cursor(&Cursor {
            request_digest: request_digest.clone(),
            caller_actor_id: manifest.caller_actor_id.clone(),
            authority_head_commit_event_ref: manifest.authority_head_commit_event_ref.clone(),
            records_digest: manifest.records_digest.clone(),
            page_index: u64::try_from(page_index + 1)
                .map_err(|_| internal("MLS roster page index exceeds u64"))?,
            next_record_offset: u64::try_from(end)
                .map_err(|_| internal("MLS roster record offset exceeds u64"))?,
            issued_at: manifest.issued_at,
        })?)
    } else {
        None
    };
    Ok(MlsRosterAuthorityReadOutcome {
        manifest: manifest.clone(),
        page_index: u64::try_from(page_index)
            .map_err(|_| internal("MLS roster page index exceeds u64"))?,
        records: records[start..end].to_vec(),
        next_cursor,
    })
}

/// Find the longest complete prefix fitting the signed, canonical response.
/// `None` means even one complete record cannot fit the wire bound.
fn partition_pages(
    records: &[MlsRosterRecord],
    manifest: &MlsRosterAuthorityManifest,
    request_digest: &Hash,
) -> ServiceResult<Option<Vec<(usize, usize)>>> {
    let mut pages = Vec::new();
    let mut start = 0;
    while start < records.len() {
        let mut selected = None;
        for end in (start + 1)..=(start + PAGE_SIZE).min(records.len()) {
            let page = roster_page(records, manifest, request_digest, start, end, pages.len())?;
            let size = arkret_canonical::canonical_json_bytes(&page)
                .map_err(|error| internal(error.to_string()))?
                .len();
            if size > MAX_PAGE_BYTES
                || arkret::mls_self_roster_authority_page_encoded_size(&page)
                    .map_err(|error| internal(error.to_string()))?
                    > MAX_PAGE_BYTES
            {
                break;
            }
            selected = Some(end);
        }
        let Some(end) = selected else {
            return Ok(None);
        };
        pages.push((start, end));
        start = end;
    }
    Ok(Some(pages))
}

fn sign_page(
    request: &MlsRosterAuthorityReadRequestBody,
    issuer: &DidCoreId,
    verification_method: &DidUrl,
    signing_key: &SigningKey,
    now: DateTime<Utc>,
    facts: MlsRosterAuthorityFacts,
) -> ServiceResult<MlsRosterAuthorityApplicationRead> {
    if facts.records.is_empty() {
        return Ok(MlsRosterAuthorityApplicationRead::RevisionUnavailable);
    }
    let records_digest = Hash::new(
        arkret_canonical::canonical_sha256(&facts.records)
            .map_err(|error| internal(error.to_string()))?,
    )
    .map_err(|error| internal(error.to_string()))?;
    let request_digest = cursor_request_digest(request)?;
    let cursor = if let Some(value) = request.cursor.as_deref() {
        let Some(cursor) = decode_cursor(value) else {
            return Ok(MlsRosterAuthorityApplicationRead::CursorInvalid);
        };
        if cursor.request_digest != request_digest
            || cursor.caller_actor_id != request.caller_actor_id
            || cursor.page_index == 0
            || cursor.next_record_offset == 0
            || cursor.issued_at > now
        {
            return Ok(MlsRosterAuthorityApplicationRead::CursorInvalid);
        }
        if cursor.authority_head_commit_event_ref != facts.authority_head_commit_event_ref
            || cursor.records_digest != records_digest
        {
            return Ok(MlsRosterAuthorityApplicationRead::RevisionUnavailable);
        }
        Some(cursor)
    } else {
        None
    };
    let issued_at = cursor.as_ref().map_or(now, |cursor| cursor.issued_at);
    let total_records = facts.records.len();
    let mut manifest = MlsRosterAuthorityManifest {
        governance_station_id: issuer.clone(),
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request.mls_group_id.clone(),
        genesis_event_ref: request.genesis_event_ref.clone(),
        group_info_ref: facts.group_info_ref,
        ratchet_tree_ref: facts.ratchet_tree_ref,
        target_commit_event_ref: request.target_commit_event_ref.clone(),
        target_epoch: request.target_epoch,
        authority_head_commit_event_ref: facts.authority_head_commit_event_ref.clone(),
        caller_actor_id: request.caller_actor_id.clone(),
        total_records: u64::try_from(total_records)
            .map_err(|_| internal("MLS roster record count exceeds u64"))?,
        page_count: u64::try_from(total_records)
            .map_err(|_| internal("MLS roster page count exceeds u64"))?,
        records_digest: records_digest.clone(),
        issued_at,
        signature: KeyOperationSignature {
            kid: NonEmptyString::new(verification_method.as_str().to_owned())
                .map_err(|error| internal(error.to_string()))?,
            signature_algorithm: Some(NonEmptyString::new("Ed25519").expect("non-empty")),
            sig: Base64UrlString::new("AA").expect("canonical placeholder"),
        },
    };
    // `page_count` is included in the signed manifest and therefore in the
    // response size. Start with the upper bound and repeat until it agrees
    // with the deterministic longest-prefix partition.
    let pages = loop {
        signed_manifest(&mut manifest, request, verification_method, signing_key)?;
        let Some(pages) = partition_pages(&facts.records, &manifest, &request_digest)? else {
            return Ok(MlsRosterAuthorityApplicationRead::RevisionUnavailable);
        };
        let actual = u64::try_from(pages.len())
            .map_err(|_| internal("MLS roster page count exceeds u64"))?;
        if actual == manifest.page_count {
            break pages;
        }
        if actual > manifest.page_count {
            return Err(internal("MLS roster page partition did not converge"));
        }
        manifest.page_count = actual;
    };
    let page_index = cursor
        .as_ref()
        .map(|cursor| usize::try_from(cursor.page_index))
        .transpose()
        .map_err(|_| internal("MLS roster cursor page index exceeds usize"))?
        .unwrap_or(0);
    let Some(&(start, end)) = pages.get(page_index) else {
        return Ok(MlsRosterAuthorityApplicationRead::CursorInvalid);
    };
    if cursor
        .as_ref()
        .is_some_and(|cursor| usize::try_from(cursor.next_record_offset).ok() != Some(start))
    {
        return Ok(MlsRosterAuthorityApplicationRead::CursorInvalid);
    }
    let page = roster_page(
        &facts.records,
        &manifest,
        &request_digest,
        start,
        end,
        page_index,
    )?;
    if arkret_canonical::canonical_json_bytes(&page)
        .map_err(|error| internal(error.to_string()))?
        .len()
        > MAX_PAGE_BYTES
        || arkret::mls_self_roster_authority_page_encoded_size(&page)
            .map_err(|error| internal(error.to_string()))?
            > MAX_PAGE_BYTES
    {
        return Ok(MlsRosterAuthorityApplicationRead::RevisionUnavailable);
    }
    Ok(MlsRosterAuthorityApplicationRead::Page(page))
}

#[cfg(test)]
mod tests {
    use arkret_identity::{DidKeyResolver, DidResolver};
    use arkret_models_collaboration::mls_roster_authority::{
        MlsAddAuthorityAttestation, MlsAttestAddRequestBody, MlsRosterRecord,
    };
    use arkret_models_crypto::{
        KeyPackageClaimRecord, PeerKeyPackageClaimReceipt, PeerKeyPackagesClaimOutcome,
        PeerKeyPackagesClaimUnsignedRequest, peer_keypackage_claim_receipt_signing_bytes,
    };
    use arkret_models_identity::{
        AuthenticatedServiceResolution, ResolutionDidBindingEvidenceKind,
        ResolutionDidBindingEvidenceReceipt, ResolutionMethodEvidenceBoundary,
        ResolutionMethodHistoryEvidence,
    };
    use arkret_wire::{
        AccountId, BlobRef, Did, MlsWelcomeRecipientEndpoint, RealmId, ScopeRef,
        project_did_to_core_id,
    };

    use super::*;

    fn event(seed: u8) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
    }

    fn page(result: MlsRosterAuthorityApplicationRead) -> MlsRosterAuthorityReadOutcome {
        match result {
            MlsRosterAuthorityApplicationRead::Page(page) => page,
            _ => panic!("complete historical facts must produce a signed page"),
        }
    }

    fn signed_add_facts() -> MlsRosterAuthorityFacts {
        let seed = [41_u8; 32];
        let signer = SigningKey::from_bytes(&seed);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signer.verifying_key().as_bytes(),
        );
        let did = Did::new(format!("did:key:{multibase}")).unwrap();
        let station = project_did_to_core_id(&did).unwrap();
        let method = DidUrl::new(format!("{}#{multibase}", did.as_str())).unwrap();
        let document = DidKeyResolver::new().resolve_did(&did).unwrap().document;
        let head = arkret_canonical::sha256_digest(did.as_str().as_bytes());
        let version = format!(
            "synthetic-did-sha256:{}",
            head.trim_start_matches("sha256:")
        );
        let resolution = AuthenticatedServiceResolution {
            service_id: station.clone(),
            service_kind: "station".to_owned(),
            method_history_evidence: ResolutionMethodHistoryEvidence::DidKeyExpansion {
                boundary: ResolutionMethodEvidenceBoundary {
                    from_method_history_head: head.clone(),
                    to_method_history_head: head,
                    from_version_id: version.clone(),
                    to_version_id: version,
                },
                evidence: ResolutionDidBindingEvidenceReceipt {
                    kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                    method: "key".to_owned(),
                    document_digest: arkret_models_identity::normalized_did_document_digest(
                        &document,
                    )
                    .unwrap(),
                    method_proofs: vec![],
                },
            },
            normalized_did_document: document,
        };
        let genesis = event(11);
        let commit = event(12);
        let realm_id = RealmId::from_event_id(&event(13));
        let scope = ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let group = scope.canonical_mls_group_id().unwrap();
        let actor = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:member.example".to_owned()).unwrap(),
            station.clone(),
        ));
        let at: DateTime<Utc> = "2026-09-29T00:00:00Z".parse().unwrap();
        let claim_id = arkret_wire::KeypackageClaimId::new(
            "ak:keypackage_claim:01904100-0000-7000-8000-000000000073".to_owned(),
        )
        .unwrap();
        let record = KeyPackageClaimRecord {
            claim_id: claim_id.as_str().to_owned(),
            keypackage_ref: format!("sha256:{}", "1".repeat(64)),
            actor_id: actor.clone(),
            principal_id: actor.signing_principal_id().clone(),
            device_id: None,
            agent_id: None,
            agent_verification_method: Some(method.clone()),
            keypackage: "AQ".to_owned(),
            capabilities: vec!["mls".to_owned()],
            device_authorize_event_id: None,
            agent_key_authorize_event_id: Some(event(14)),
            expires_at: at + chrono::TimeDelta::hours(1),
            revocation_status: None,
            last_resort: None,
        };
        let claim_request: PeerKeyPackagesClaimUnsignedRequest = serde_json::from_value(
            serde_json::json!({
                "claim_request_id": "AQ",
                "intended_realm_id": realm_id,
                "mls_group_id": group,
                "claim_purpose": "realm_membership",
                "required_capabilities": ["mls"],
                "expires_at": arkret_canonical::format_timestamp_canonical(at + chrono::TimeDelta::hours(1)),
            }),
        ).unwrap();
        let placeholder = || KeyOperationSignature {
            kid: NonEmptyString::new(method.as_str().to_owned()).unwrap(),
            signature_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
            sig: Base64UrlString::new("AA").unwrap(),
        };
        let mut receipt = PeerKeyPackageClaimReceipt {
            claim_request_id: claim_request.claim_request_id.clone(),
            request_digest: Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
            claims_digest: Hash::new(arkret_canonical::canonical_sha256(&[&record]).unwrap())
                .unwrap(),
            source_id: station.clone(),
            destination_id: station.clone(),
            request: claim_request,
            claimed_at: at,
            expires_at: at + chrono::TimeDelta::hours(1),
            signature: placeholder(),
        };
        receipt.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
            &seed,
            method.as_str(),
            &peer_keypackage_claim_receipt_signing_bytes(&receipt).unwrap(),
        )
        .unwrap();
        let outcome = PeerKeyPackagesClaimOutcome {
            claim_request_id: receipt.claim_request_id.clone(),
            claims: vec![record],
            claim_receipt: receipt.clone(),
        };
        let welcome_id = arkret_wire::MlsWelcomeDeliveryId::new(
            "ak:mls_welcome_delivery:01904100-0000-7000-8000-000000000074".to_owned(),
        )
        .unwrap();
        let mut attestation = MlsAddAuthorityAttestation {
            attestor_station_id: station.clone(),
            realm_id: realm_id.clone(),
            effective_scope: scope,
            mls_group_id: group,
            genesis_event_ref: genesis.clone(),
            commit_event_ref: commit.clone(),
            commit_stream_position: 2,
            epoch: 1,
            welcome_id,
            claim_id,
            actor_id: actor.clone(),
            endpoint: MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method: method.clone(),
            },
            authorization_event_ref: event(14),
            leaf_signature_key_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
                [7; 32],
            ))
            .unwrap(),
            claim_record_digest: Hash::new(
                arkret_canonical::canonical_sha256(&outcome.claims[0]).unwrap(),
            )
            .unwrap(),
            claim_receipt: receipt,
            attested_at: at,
            signature: placeholder(),
        };
        attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
            &seed,
            method.as_str(),
            &attestation.signing_bytes().unwrap(),
        )
        .unwrap();
        let proof = MlsAttestAddRequestBody {
            attestation: attestation.clone(),
            claim_outcome: outcome,
        };

        MlsRosterAuthorityFacts {
            group_info_ref: BlobRef::new(format!("ak:blob:sha256:{}", "3".repeat(64))).unwrap(),
            ratchet_tree_ref: BlobRef::new(format!("ak:blob:sha256:{}", "4".repeat(64))).unwrap(),
            authority_head_commit_event_ref: commit.clone(),
            records: vec![
                MlsRosterRecord::Genesis {
                    genesis_event_ref: genesis,
                    actor_id: actor.clone(),
                    leaf_signature_key_b64u: Base64UrlString::new(
                        arkret_canonical::base64url_encode([5; 32]),
                    )
                    .unwrap(),
                    endpoint: MlsWelcomeRecipientEndpoint::AgentRuntime {
                        verification_method: method,
                    },
                    authorization_event_ref: event(15),
                },
                MlsRosterRecord::Add {
                    commit_event_ref: commit,
                    consumed_proposal_ordinal: 0,
                    sender_actor_id: actor,
                    proposal_wire_b64u: Base64UrlString::new("AQ").unwrap(),
                    attestation,
                    attestor_resolution: resolution,
                },
            ],
            historical_add_proofs: vec![proof],
        }
    }

    #[test]
    fn roster_signing_requires_original_historical_signatures_and_resolutions() {
        let facts = signed_add_facts();
        assert!(verify_historical_proofs(&facts));
        assert!(facts_match_preflight(
            &facts,
            &facts.authority_head_commit_event_ref,
        ));
        assert!(!facts_match_preflight(&facts, &event(99)));
        let mut absent_resolution = facts.clone();
        if let MlsRosterRecord::Add {
            attestor_resolution,
            ..
        } = &mut absent_resolution.records[1]
        {
            attestor_resolution.service_kind = "other".to_owned();
        }
        assert!(!verify_historical_proofs(&absent_resolution));
        let mut altered_receipt = facts.clone();
        altered_receipt.historical_add_proofs[0]
            .claim_outcome
            .claim_receipt
            .signature
            .sig = Base64UrlString::new("AQ").unwrap();
        altered_receipt.historical_add_proofs[0]
            .attestation
            .claim_receipt
            .signature
            .sig = Base64UrlString::new("AQ").unwrap();
        assert!(!verify_historical_proofs(&altered_receipt));
        let mut altered_attestation = facts.clone();
        altered_attestation.historical_add_proofs[0]
            .attestation
            .signature
            .sig = Base64UrlString::new("AQ").unwrap();
        assert!(!verify_historical_proofs(&altered_attestation));
        let mut missing = facts;
        missing.historical_add_proofs.clear();
        assert!(!verify_historical_proofs(&missing));
    }

    #[test]
    fn signed_roster_pages_bind_the_cut_and_reject_bad_cursors() {
        let genesis = event(1);
        let target = event(2);
        let realm_id = RealmId::from_event_id(&event(3));
        let scope = ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let issuer = DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap();
        let method = DidUrl::new("did:web:station.example#notary-key".to_owned()).unwrap();
        let actor = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            issuer.clone(),
        ));
        let mut request = MlsRosterAuthorityReadRequestBody {
            realm_id,
            mls_group_id: scope.canonical_mls_group_id().unwrap(),
            effective_scope: scope,
            genesis_event_ref: genesis.clone(),
            target_commit_event_ref: target.clone(),
            target_epoch: 1,
            caller_actor_id: actor.clone(),
            cursor: None,
        };
        let facts = MlsRosterAuthorityFacts {
            group_info_ref: BlobRef::new(format!("ak:blob:sha256:{}", "1".repeat(64))).unwrap(),
            ratchet_tree_ref: BlobRef::new(format!("ak:blob:sha256:{}", "2".repeat(64))).unwrap(),
            authority_head_commit_event_ref: target.clone(),
            records: (0..9)
                .map(|_| MlsRosterRecord::Genesis {
                    genesis_event_ref: genesis.clone(),
                    actor_id: actor.clone(),
                    leaf_signature_key_b64u: Base64UrlString::new("AQ".to_owned()).unwrap(),
                    endpoint: MlsWelcomeRecipientEndpoint::AgentRuntime {
                        verification_method: method.clone(),
                    },
                    authorization_event_ref: genesis.clone(),
                })
                .collect(),
            historical_add_proofs: vec![],
        };
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let now = DateTime::parse_from_rfc3339("2026-09-29T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let first = page(sign_page(&request, &issuer, &method, &key, now, facts.clone()).unwrap());
        assert_eq!((first.page_index, first.records.len()), (0, 8));
        assert_eq!(
            (first.manifest.total_records, first.manifest.page_count),
            (9, 2)
        );
        arkret_signatures::keypackages::verify_keypackage_signing_input(
            &key.verifying_key().to_bytes(),
            method.as_str(),
            &first.manifest.signing_bytes().unwrap(),
            &first.manifest.signature,
        )
        .unwrap();
        request.cursor = first.next_cursor.clone();
        let second = page(sign_page(&request, &issuer, &method, &key, now, facts.clone()).unwrap());
        assert_eq!((second.page_index, second.records.len()), (1, 1));
        assert!(second.next_cursor.is_none());
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&first.manifest).unwrap(),
            arkret_canonical::canonical_json_bytes(&second.manifest).unwrap(),
        );
        let original_cursor = request.cursor.clone().unwrap();
        request.cursor = Some(format!("{original_cursor}!"));
        assert!(matches!(
            sign_page(&request, &issuer, &method, &key, now, facts.clone()).unwrap(),
            MlsRosterAuthorityApplicationRead::CursorInvalid
        ));
        request.cursor = Some(original_cursor);
        request.caller_actor_id = ActorId::service(issuer.clone());
        assert!(matches!(
            sign_page(&request, &issuer, &method, &key, now, facts.clone()).unwrap(),
            MlsRosterAuthorityApplicationRead::CursorInvalid
        ));
        request.caller_actor_id = actor;
        let mut changed_head = facts;
        changed_head.authority_head_commit_event_ref = event(4);
        assert!(matches!(
            sign_page(&request, &issuer, &method, &key, now, changed_head).unwrap(),
            MlsRosterAuthorityApplicationRead::RevisionUnavailable
        ));
    }

    #[test]
    fn signed_roster_pages_pack_complete_closures_under_two_mib() {
        let mut facts = signed_add_facts();
        let MlsRosterRecord::Add { attestation, .. } = &facts.records[1] else {
            panic!("fixture has one Add")
        };
        let attestation = attestation.clone();
        let issuer = attestation.attestor_station_id.clone();
        let method = DidUrl::new(attestation.signature.kid.as_str().to_owned()).unwrap();
        let mut request = MlsRosterAuthorityReadRequestBody {
            realm_id: attestation.realm_id.clone(),
            effective_scope: attestation.effective_scope.clone(),
            mls_group_id: attestation.mls_group_id.clone(),
            genesis_event_ref: attestation.genesis_event_ref.clone(),
            target_commit_event_ref: attestation.commit_event_ref.clone(),
            target_epoch: attestation.epoch,
            caller_actor_id: attestation.actor_id.clone(),
            cursor: None,
        };
        let padding = "x".repeat(1_100_000);
        if let MlsRosterRecord::Add {
            attestor_resolution,
            ..
        } = &mut facts.records[1]
        {
            attestor_resolution
                .normalized_did_document
                .raw_properties
                .insert(
                    "roster_padding".to_owned(),
                    serde_json::Value::String(padding),
                );
        }
        assert!(
            arkret_canonical::canonical_json_bytes(&facts.records[1])
                .unwrap()
                .len()
                > 1_000_000
        );
        let second_add = facts.records[1].clone();
        facts.records.push(second_add);
        let key = SigningKey::from_bytes(&[41; 32]);
        let now = attestation.attested_at;
        let first = page(sign_page(&request, &issuer, &method, &key, now, facts.clone()).unwrap());
        assert_eq!((first.records.len(), first.manifest.page_count), (2, 2));
        assert!(
            arkret_canonical::canonical_json_bytes(&first)
                .unwrap()
                .len()
                <= MAX_PAGE_BYTES
        );
        request.cursor = first.next_cursor.clone();
        let second = page(sign_page(&request, &issuer, &method, &key, now, facts.clone()).unwrap());
        assert_eq!((second.page_index, second.records.len()), (1, 1));
        assert!(second.next_cursor.is_none());
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&first.manifest).unwrap(),
            arkret_canonical::canonical_json_bytes(&second.manifest).unwrap()
        );

        let mut changed = facts.clone();
        if let MlsRosterRecord::Add {
            attestor_resolution,
            ..
        } = &mut changed.records[2]
        {
            attestor_resolution
                .normalized_did_document
                .raw_properties
                .insert(
                    "roster_padding".to_owned(),
                    serde_json::Value::String("y".repeat(1_100_000)),
                );
        }
        assert!(matches!(
            sign_page(&request, &issuer, &method, &key, now, changed).unwrap(),
            MlsRosterAuthorityApplicationRead::RevisionUnavailable
        ));

        let mut oversized = facts;
        oversized.records.truncate(2);
        if let MlsRosterRecord::Add {
            attestor_resolution,
            ..
        } = &mut oversized.records[1]
        {
            attestor_resolution
                .normalized_did_document
                .raw_properties
                .insert(
                    "roster_padding".to_owned(),
                    serde_json::Value::String("z".repeat(MAX_PAGE_BYTES)),
                );
        }
        request.cursor = None;
        assert!(matches!(
            sign_page(&request, &issuer, &method, &key, now, oversized).unwrap(),
            MlsRosterAuthorityApplicationRead::RevisionUnavailable
        ));
    }
}
