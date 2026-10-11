//! Signed Event fixtures using the current admission envelope.

use arkret_identifiers::RealmId;
use arkret_wire::{DidUrl, Event, EventAdmissionSubmission, ScopeRef};
use serde_json::Value;

pub const FIXTURE_EVENT_SIGNING_SEED: [u8; 32] = [21_u8; 32];

/// A canonical Event record is a storage fixture, not proof of an accepted Commit.
#[must_use]
pub fn canonical_event_record(
    event: &Event,
    realm_id: Option<&str>,
    received_at: chrono::DateTime<chrono::Utc>,
) -> coland_storage::CanonicalEventRecord {
    let digest_suite = event.event_id.digest_suite_code().digest_suite();
    coland_storage::CanonicalEventRecord {
        event_id: event.event_id.to_string(),
        actor_id: event.actor_id.to_string(),
        realm_id: realm_id.map(str::to_owned),
        kind: event.kind.to_string(),
        schema_id: "ak.schema.event.v1".to_owned(),
        digest_suite,
        canonical_digest: event
            .event_digest_with_digest_suite(digest_suite)
            .expect("fixture Event digest"),
        canonical_bytes: arkret_canonical::canonical_json_bytes(
            &event
                .digest_payload()
                .expect("fixture Event digest payload"),
        )
        .expect("fixture Event canonical digest bytes"),
        envelope: serde_json::to_value(event).expect("fixture Event envelope"),
        received_at,
    }
}

/// Author one caller-signed Event; acceptance requires a separate authority Commit.
#[derive(Clone, Debug)]
pub struct CallerSignedEvent<'a> {
    kind: &'a str,
    actor_id: &'a str,
    device_id: &'a str,
    realm_id: &'a str,
    payload: Value,
    signing_seed: [u8; 32],
    genesis_scope: bool,
}

impl<'a> CallerSignedEvent<'a> {
    #[must_use]
    pub fn new(
        kind: &'a str,
        actor_id: &'a str,
        device_id: &'a str,
        realm_id: &'a str,
        payload: Value,
    ) -> Self {
        Self {
            kind,
            actor_id,
            device_id,
            realm_id,
            payload,
            signing_seed: FIXTURE_EVENT_SIGNING_SEED,
            genesis_scope: false,
        }
    }

    #[must_use]
    pub fn realm_genesis(actor_id: &'a str, device_id: &'a str, payload: Value) -> Self {
        let mut event = Self::new(
            arkret_wire::EventKind::RealmCreate.as_str(),
            actor_id,
            device_id,
            "",
            payload,
        );
        event.genesis_scope = true;
        event
    }

    #[must_use]
    pub fn verification_method(&self) -> DidUrl {
        fixture_verification_method(self.actor_id, self.device_id)
    }

    #[must_use]
    pub fn build(self) -> Event {
        let now = chrono::Utc::now();
        let actor =
            arkret_identifiers::Did::new(self.actor_id.to_owned()).expect("fixture actor DID");
        let actor_id =
            arkret_wire::project_did_to_core_id(&actor).expect("fixture actor projection");
        let verification_method = self.verification_method();
        let event = arkret_wire::test_support::raw_event_at(
            self.kind,
            if self.genesis_scope {
                ScopeRef::RealmGenesis
            } else {
                ScopeRef::Realm {
                    realm_id: RealmId::new(self.realm_id.to_owned()).expect("fixture Realm id"),
                }
            },
            actor_id,
            crate::fixture_station_id(),
            self.payload,
            now,
        )
        .expect("SDK Event builder accepts the fixture envelope");
        let signer =
            arkret_test_kit::seeded_signer_for_seed(self.signing_seed, actor, verification_method);
        arkret_test_kit::sign_verifiable_event(
            event,
            &signer,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("SDK Event signer accepts the fixture envelope")
        .expect_verifiable()
    }

    #[must_use]
    pub fn build_value(self) -> Value {
        serde_json::to_value(self.build()).expect("SDK Event serializes")
    }

    #[must_use]
    pub fn build_submission(self) -> EventAdmissionSubmission {
        EventAdmissionSubmission::new(self.build())
    }
}

#[must_use]
pub fn fixture_verification_method(actor_id: &str, device_id: &str) -> DidUrl {
    let device_id = if device_id.starts_with("ak:device:") {
        device_id.to_owned()
    } else {
        format!("ak:device:{device_id}")
    };
    DidUrl::new(format!("{actor_id}#{device_id}"))
        .expect("fixture verification method is a DID URL")
}

pub async fn sign_accepted_fixture_event(
    _state: &coland_http::state::AppState,
    event: Event,
    actor_id: &str,
    device_id: &str,
    signing_seed: [u8; 32],
) -> Event {
    sign_fixture_event(event, actor_id, device_id, signing_seed)
}

pub fn sign_fixture_event(
    event: Event,
    actor_id: &str,
    device_id: &str,
    signing_seed: [u8; 32],
) -> Event {
    let signer = arkret_test_kit::seeded_signer_for_seed(
        signing_seed,
        arkret_identifiers::Did::new(actor_id.to_owned()).expect("fixture signer DID"),
        fixture_verification_method(actor_id, device_id),
    );
    arkret_test_kit::sign_verifiable_event(event, &signer, arkret_canonical::DigestSuite::Sha256)
        .expect("fixture Event signs")
        .expect_verifiable()
}
