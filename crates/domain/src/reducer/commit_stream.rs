//! Independent commit-stream head tracking for authority-ordered Events.
//!
//! Producers do not declare predecessors. Ordering is supplied exclusively by
//! a governance Station's [`arkret_wire::RealmCommit`]. Realm, Circle and
//! Sidecar streams are checked independently; this module deliberately has no
//! cross-stream position or merge rule.

use std::collections::BTreeMap;

use arkret_wire::{
    CommitStreamHead, CommitStreamRef, CommittedEventFullView, CurrentState, Event, EventId,
    RealmStateSnapshot,
};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CommitStreamProjection {
    stream_heads: BTreeMap<CommitStreamRef, CommitStreamHead>,
    committed_items: BTreeMap<EventId, CommittedEventFullView>,
    current_state_entries: Vec<CurrentState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitStreamEffect {
    Committed { head: CommitStreamHead },
    Duplicate { head: CommitStreamHead },
}

impl CommitStreamProjection {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_committed(
        &mut self,
        item: CommittedEventFullView,
    ) -> Result<CommitStreamEffect, arkret_wire::WireError> {
        item.validate_shape()?;
        if let Some(existing) = self.committed_items.get(&item.event.event_id) {
            if existing != &item {
                return Err(arkret_wire::WireError::Protocol(
                    "one Event identity resolved to different committed stream items".to_owned(),
                ));
            }
            let head = CommitStreamHead {
                stream_ref: existing.commit.stream_ref.clone(),
                stream_position: existing.commit.stream_position,
                commit_id: existing.commit.commit_id.clone(),
            };
            return Ok(CommitStreamEffect::Duplicate { head });
        }

        match self.stream_heads.get(&item.commit.stream_ref) {
            Some(previous) => {
                if item.commit.stream_position != previous.stream_position.saturating_add(1)
                    || item.commit.previous_commit_ref.as_ref() != Some(&previous.commit_id)
                {
                    return Err(arkret_wire::WireError::Protocol(
                        "RealmCommit does not extend this independent stream head".to_owned(),
                    ));
                }
            }
            None if item.commit.stream_position == 0
                && item.commit.previous_commit_ref.is_none() => {}
            None => {
                return Err(arkret_wire::WireError::Protocol(
                    "first observed RealmCommit for a stream must be position zero".to_owned(),
                ));
            }
        }

        let head = CommitStreamHead {
            stream_ref: item.commit.stream_ref.clone(),
            stream_position: item.commit.stream_position,
            commit_id: item.commit.commit_id.clone(),
        };
        self.committed_items
            .insert(item.event.event_id.clone(), item);
        self.stream_heads
            .insert(head.stream_ref.clone(), head.clone());
        Ok(CommitStreamEffect::Committed { head })
    }

    pub fn install_snapshot(
        &mut self,
        snapshot: RealmStateSnapshot,
    ) -> Result<(), arkret_wire::WireError> {
        if !snapshot
            .visible_stream_heads
            .windows(2)
            .all(|pair| pair[0].stream_ref < pair[1].stream_ref)
            || snapshot
                .visible_stream_heads
                .iter()
                .any(|head| head.stream_ref.realm_id() != &snapshot.realm_id)
        {
            return Err(arkret_wire::WireError::Protocol(
                "snapshot stream heads must be sorted, unique, and belong to its Realm".to_owned(),
            ));
        }
        self.stream_heads = snapshot
            .visible_stream_heads
            .into_iter()
            .map(|head| (head.stream_ref.clone(), head))
            .collect();
        self.current_state_entries = snapshot.current_state_entries;
        self.committed_items.clear();
        Ok(())
    }

    #[must_use]
    pub fn stream_head(&self, stream_ref: &CommitStreamRef) -> Option<&CommitStreamHead> {
        self.stream_heads.get(stream_ref)
    }

    #[must_use]
    pub fn stream_heads(&self) -> &BTreeMap<CommitStreamRef, CommitStreamHead> {
        &self.stream_heads
    }

    #[must_use]
    pub fn committed_event(&self, event_id: &EventId) -> Option<&Event> {
        self.committed_items.get(event_id).map(|item| &item.event)
    }

    #[must_use]
    pub fn current_state_entries(&self) -> &[CurrentState] {
        &self.current_state_entries
    }
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_wire::{
        Base64UrlString, CircleId, DetachedObjectSignature, DetachedSignatureAlgorithm,
        DetachedSignatureContext, DidCoreId, DidUrl, EventKind, RealmCommit,
        RealmCommitAuthorityRef, RealmCommitId, RealmId, ScopeRef, test_support,
    };
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;

    fn realm(seed: u8) -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [seed; 32]))
    }

    fn signature() -> DetachedObjectSignature {
        DetachedObjectSignature {
            context: DetachedSignatureContext::RealmCommit,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: DidUrl::new("did:web:station.example#key-1").unwrap(),
            signed_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "11".repeat(32)))
                .unwrap(),
            created_at: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
            signature: Base64UrlString::new("AQ").unwrap(),
        }
    }

    fn circle_item(realm_id: RealmId, circle_seed: u8, position: u64) -> CommittedEventFullView {
        let circle_id = CircleId::from_event_id(&EventId::from_digest(
            DigestSuite::Sha256,
            [circle_seed; 32],
        ));
        let scope_ref = ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        };
        let event = test_support::raw_event_at(
            EventKind::MessageCreate.as_str(),
            scope_ref,
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            json!({}),
            Utc.timestamp_opt(1_800_000_000 + position as i64, 0)
                .unwrap(),
        )
        .unwrap();
        CommittedEventFullView {
            commit: RealmCommit {
                producer_signer_fact_digest: None,
                commit_id: RealmCommitId::from_digest(
                    [circle_seed.wrapping_add(position as u8); 32],
                ),
                realm_id: realm_id.clone(),
                stream_ref: CommitStreamRef::Circle {
                    realm_id,
                    circle_id,
                },
                stream_position: position,
                previous_commit_ref: (position > 0).then(|| {
                    RealmCommitId::from_digest(
                        [circle_seed.wrapping_add(position as u8).wrapping_sub(1); 32],
                    )
                }),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(EventId::from_digest(
                    DigestSuite::Sha256,
                    [0x55; 32],
                )),
                committed_at: Utc
                    .timestamp_opt(1_800_000_100 + position as i64, 0)
                    .unwrap(),
                signature: signature(),
            },
            event,
        }
    }

    #[test]
    fn independent_circle_streams_each_start_at_zero() {
        let realm_id = realm(0x10);
        let first = circle_item(realm_id.clone(), 0x20, 0);
        let second = circle_item(realm_id, 0x30, 0);
        let first_stream = first.commit.stream_ref.clone();
        let second_stream = second.commit.stream_ref.clone();
        let mut state = CommitStreamProjection::new();

        assert!(matches!(
            state.apply_committed(first),
            Ok(CommitStreamEffect::Committed { .. })
        ));
        assert!(matches!(
            state.apply_committed(second),
            Ok(CommitStreamEffect::Committed { .. })
        ));
        assert_eq!(state.stream_head(&first_stream).unwrap().stream_position, 0);
        assert_eq!(
            state.stream_head(&second_stream).unwrap().stream_position,
            0
        );
    }

    #[test]
    fn duplicate_requires_the_exact_same_commit_binding() {
        let realm_id = realm(0x10);
        let item = circle_item(realm_id, 0x20, 0);
        let mut conflicting = item.clone();
        conflicting.commit.commit_id = RealmCommitId::from_digest([0x77; 32]);
        let mut state = CommitStreamProjection::new();

        state.apply_committed(item.clone()).unwrap();
        assert!(matches!(
            state.apply_committed(item),
            Ok(CommitStreamEffect::Duplicate { .. })
        ));
        assert!(state.apply_committed(conflicting).is_err());
    }

    #[test]
    fn one_stream_must_extend_its_own_predecessor() {
        let realm_id = realm(0x10);
        let first = circle_item(realm_id.clone(), 0x20, 0);
        let second = circle_item(realm_id, 0x20, 1);
        let mut state = CommitStreamProjection::new();

        state.apply_committed(first).unwrap();
        assert!(matches!(
            state.apply_committed(second),
            Ok(CommitStreamEffect::Committed { .. })
        ));
    }
}
