//! Domain coordinates for the Station's local product projection.
//!
//! An accepted Event reaches the reducer already ordered by the current
//! governance Station's `RealmCommit`, and each Realm, Circle and Sidecar
//! stream is linear. A facet therefore holds exactly one settled value: there
//! is no merge function, no conflict value, and no revision lattice to
//! resolve. These coordinates address the Station's own projection cache and
//! never appear on the wire.

use std::fmt;

use serde_json::Value;

/// Facet names. Each one is a product surface the reducer maintains, named by
/// the domain object and field it projects.
pub mod facet {
    pub const AGENT_STATUS: &str = "agent.status";
    pub const CALENDAR_RSVP: &str = "calendar.rsvp";
    pub const CALL_FOCUS: &str = "call.focus";
    pub const CALL_MODERATION: &str = "call.moderation";
    pub const CALL_RECORDING: &str = "call.recording";
    pub const CALL_RECORDING_RESULT: &str = "call.recording_result";
    pub const CALL_ROSTER: &str = "call.roster";
    pub const CALL_STATE: &str = "call.state";
    pub const CALL_TRANSCRIPT: &str = "call.transcript";
    pub const CALL_TRANSCRIPT_RESULT: &str = "call.transcript_result";
    pub const CIRCLE_HISTORY_ACCESS: &str = "circle.history_access";
    pub const CIRCLE_MEMBER: &str = "circle.member";
    pub const CONTAINER_ORDER: &str = "container.order";
    pub const DEVICE_AUTHORIZATION: &str = "device.authorization";
    pub const DEVICE_REANCHOR: &str = "device.reanchor";
    pub const IDENTITY_RESOLUTION: &str = "identity.resolution";
    pub const INVITE_LIVE_TARGET: &str = "invite.live_target";
    pub const MEMBER_IDENTITY: &str = "member.identity";
    pub const MEMBER_STATE: &str = "member.state";
    pub const MLS_EPOCH: &str = "mls.epoch";
    pub const MODERATION_STATE: &str = "moderation.state";
    pub const POLICY: &str = "policy";
    /// Policy-attached approval configuration keyed by `(policy_id, action)`.
    pub const POLICY_ACTION_POLICY_REF: &str = "policy_action.policy_ref";
    /// Realm-local approval configuration keyed by opaque `action_id`.
    pub const POLICY_ACTION_REALM_ACTION: &str = "policy_action.realm_action";
    pub const REALM_ALIAS: &str = "realm.alias";
    pub const REALM_ARCHIVE: &str = "realm.archive";
    pub const REALM_AUTHORITY_ROOT: &str = "realm.authority_root";
    pub const REALM_CREATE: &str = "realm.create";
    pub const REALM_DESTROY: &str = "realm.destroy";
    pub const REALM_DISCOVERY: &str = "realm.discovery";
    pub const REALM_FREEZE: &str = "realm.freeze";
    pub const REALM_GENESIS: &str = "realm.genesis";
    pub const REALM_HISTORY_ACCESS: &str = "realm.history_access";
    pub const REALM_JOIN_RULE: &str = "realm.join_rule";
    pub const REALM_LINK: &str = "realm.link";
    pub const REALM_MEDIA_SERVICE: &str = "realm.media_service";
    pub const REALM_ORGANIZATION: &str = "realm.organization";
    pub const REALM_PLAINTEXT_VISIBLE_SERVICES: &str = "realm.plaintext_visible_services";
    pub const REALM_POLICY_BUNDLE: &str = "realm.policy_bundle";
    pub const REALM_PROFILE: &str = "realm.profile";
    pub const REALM_PREVIEW_POLICY: &str = "realm.preview_policy";
    pub const REALM_ASSET_PRIVACY_POLICY: &str = "realm.asset_privacy_policy";
    pub const SCOPE_READ_RECEIPT_POLICY: &str = "scope.read_receipt_policy";
    pub const REALM_SEARCH_POLICY: &str = "realm.search_policy";
    pub const REALM_TOMBSTONE: &str = "realm.tombstone";
    pub const STRAND_POSITION: &str = "strand.position";
    pub const STRAND_WATCH: &str = "strand.watch";
}

/// One addressable facet of the local projection.
///
/// `subject` is the domain identifier the Event already carries (an actor, an
/// object, a grant). A Realm-singleton facet leaves it empty.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FacetRef {
    facet: String,
    subject: String,
}

impl FacetRef {
    #[must_use]
    pub fn new(facet: &str, subject: impl Into<String>) -> Self {
        Self {
            facet: facet.to_owned(),
            subject: subject.into(),
        }
    }

    /// A facet with exactly one value per Realm.
    #[must_use]
    pub fn singleton(facet: &str) -> Self {
        Self::new(facet, String::new())
    }

    /// A facet whose subject is an ordered tuple of domain identifiers.
    ///
    /// The parts are joined with `/`, which no Arkret identifier contains, so
    /// the encoding stays injective without a length prefix.
    #[must_use]
    pub fn composite(facet: &str, parts: &[&str]) -> Self {
        Self::new(facet, parts.join("/"))
    }

    #[must_use]
    pub fn facet(&self) -> &str {
        &self.facet
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub fn is_singleton(&self) -> bool {
        self.subject.is_empty()
    }
}

impl fmt::Display for FacetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.subject.is_empty() {
            f.write_str(&self.facet)
        } else {
            write!(f, "{}/{}", self.facet, self.subject)
        }
    }
}

/// The settled value of one facet plus the revision the Station has reached
/// for it.
///
/// `revision` counts accepted writes to this facet, starting at 1. A producer
/// that carries an `expected_revision` precondition (for example
/// `ak.moderation.decision.lift`) names exactly this number, so a stale
/// decision is rejected instead of silently overwriting a newer one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettledFacet {
    pub revision: u64,
    pub value: Value,
}
