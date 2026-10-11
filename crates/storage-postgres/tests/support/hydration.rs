use coland_services::hydration::HydrationProjectionAdapter;
use sha2::{Digest as _, Sha256};

pub struct BootstrapHydrationAdapter;

impl HydrationProjectionAdapter for BootstrapHydrationAdapter {
    fn operation_from_canonical_record(
        &self,
        record: &coland_services::events::AcceptedEvent,
    ) -> Option<arkret_event_draft::ProjectedEventOperation> {
        let event = serde_json::from_value::<arkret_wire::Event>(record.envelope.clone()).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(b"ak:operation:coland-event-projection:v1:");
        hasher.update(record.event_id.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let operation_id = arkret_identifiers::OperationId::new(format!(
            "ak:operation:{}",
            uuid::Uuid::from_bytes(bytes)
        ))
        .ok()?;
        arkret_event_draft::ProjectedEventOperation::from_accepted_event(
            operation_id,
            arkret_wire::OperationKind::Create,
            None,
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .ok()
    }
}
