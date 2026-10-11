use super::{AgentSessionRecord, PersistenceResult, SessionRecord, Value, async_trait};
/// Trait for session storage operations.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>>;
    async fn put(&self, record: &SessionRecord) -> PersistenceResult<()>;
    async fn device_authorization(
        &self,
        token: &str,
    ) -> PersistenceResult<Option<crate::DeviceRevocationGateSelector>>;
    async fn delete(&self, token: &str) -> PersistenceResult<()>;
    async fn cleanup_expired(&self) -> PersistenceResult<usize>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>>;
}
#[doc(hidden)]
pub fn encode_session_payload(record: &SessionRecord) -> Value {
    let mut payload = serde_json::Map::new();
    if let Some(agent_session) = &record.agent_session
        && let Ok(value) = serde_json::to_value(agent_session)
    {
        payload.insert("agent_session".to_owned(), value);
    }
    Value::Object(payload)
}
#[doc(hidden)]
pub fn decode_session_agent_payload(payload: &Value) -> Option<AgentSessionRecord> {
    payload
        .get("agent_session")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}
#[cfg(test)]
mod tests {
    use arkret_wire::FreshnessState;

    use super::{
        AgentSessionRecord, SessionRecord, decode_session_agent_payload, encode_session_payload,
    };
    use crate::AccountPk;

    #[test]
    fn session_payload_round_trips_agent_session() {
        let record = SessionRecord {
            token_hash: "grant".to_owned(),
            account_pk: AccountPk(1),
            actor: "did:web:alice.example".to_owned(),
            device_id: "ak:device:0196419b-0000-7000-8000-000000000001".to_owned(),
            audience: "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:coland.local:webvh:service".to_owned(),
            session_public_key: Some("{}".to_owned()),
            agent_session: Some(AgentSessionRecord {
                granted_scope: vec![
                    "ak.self.committed_event.stream.subscribe.v1".to_owned(),
                    "ak.self.committed_event.read.scan.v1".to_owned(),
                ],
                scope_details: serde_json::json!({
                    "agent_id": "ak:did_core:web:agent.example",
                    "applet_id": "ak:applet:01904100-0000-7000-8000-000000000001"
                }),
                freshness_state: FreshnessState::Fresh,
            }),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };

        let payload = encode_session_payload(&record);
        let restored = decode_session_agent_payload(&payload).expect("agent session decodes");

        assert_eq!(restored.freshness_state, FreshnessState::Fresh);
        assert_eq!(
            restored.granted_scope,
            vec![
                "ak.self.committed_event.stream.subscribe.v1".to_owned(),
                "ak.self.committed_event.read.scan.v1".to_owned()
            ]
        );
        assert_eq!(
            restored.scope_details["applet_id"],
            "ak:applet:01904100-0000-7000-8000-000000000001"
        );
    }
}
