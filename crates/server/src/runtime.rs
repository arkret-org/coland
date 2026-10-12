use std::sync::Arc;
use std::time::Duration;

use coland_http::config::AppConfig;
use coland_http::state::{
    AppState, AppStateRuntime, EventBroadcast, EventNotification, EventNotificationRelay,
};
use coland_services::governance::RuntimeSettingsPort;
use coland_services::jobs::RuntimeHealthPort;
use coland_services::persistence::PersistenceHandle;
use coland_storage_postgres::{Db, PgPool};
use futures_util::future::poll_fn;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_postgres::{AsyncMessage, NoTls};

use crate::object_storage::build_object_storage;

const EVENT_NOTIFICATION_CHANNEL: &str = "coland_event_notifications";

pub fn build_app_state(
    config: AppConfig,
    db: Db,
    persistence: PersistenceHandle,
    service_identity: arkret_identity::service_identity::DidCoreIdentityState,
    service_resolution_commitment: arkret_models_identity::ResolutionCommitment,
    resolved_signing_seed: [u8; 32],
) -> anyhow::Result<AppState> {
    let serving_identity = service_identity
        .identity()
        .ok_or_else(|| anyhow::anyhow!("runtime requires a serving service identity"))?;
    let service_id = serving_identity.service_id.to_string();
    let projections = coland_services::projection::ProjectionService::new(&service_id);
    let realm_directory = coland_http::state::build_realm_directory(
        &config,
        &serving_identity.did,
        &serving_identity.service_id,
        resolved_signing_seed,
    );
    let object_storage = build_object_storage(&config.object_storage)?;
    // `AppConfig::from_env_and_args` already resolved `DATABASE_URL`, and it
    // dropped a blank value to `None`. Re-reading the environment here only
    // reintroduced the blank case as `Some("")`.
    let event_broadcast = event_broadcast(db.pool.clone(), config.database_url.clone(), 1024);
    let storage_mode = db.mode();
    let pool = db.pool.clone();

    Ok(AppState::from_runtime(
        config,
        AppStateRuntime {
            persistence,
            projections,
            realm_directory,
            object_storage,
            settings_persistence: Arc::new(RuntimeSettingsPersistence { pool: pool.clone() }),
            runtime_health: Arc::new(RuntimeDatabaseHealth(db)),
            event_broadcast,
            storage_mode,
        },
        service_identity,
        service_resolution_commitment,
        resolved_signing_seed,
    ))
}

struct RuntimeSettingsPersistence {
    pool: Option<PgPool>,
}

struct RuntimeDatabaseHealth(Db);
#[async_trait::async_trait]
impl RuntimeSettingsPort for RuntimeSettingsPersistence {
    async fn load_overrides(&self) -> coland_services::ServiceResult<Vec<(String, Value)>> {
        let Some(pool) = self.pool.as_ref() else {
            return Ok(Vec::new());
        };
        coland_storage_postgres::load_settings_overrides(pool)
            .await
            .map_err(Into::into)
    }

    async fn store_override(
        &self,
        key: &str,
        value: &Value,
        updated_by: &str,
    ) -> coland_services::ServiceResult<()> {
        let Some(pool) = self.pool.as_ref() else {
            return Ok(());
        };
        coland_storage_postgres::store_settings_override(pool, key, value, updated_by)
            .await
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl RuntimeHealthPort for RuntimeDatabaseHealth {
    async fn database_ready(&self) -> bool {
        coland_storage_postgres::database_ready(self.0.pool.as_ref()).await
    }

    fn storage_mode(&self) -> &'static str {
        self.0.mode()
    }

    fn migrations_applied(&self) -> bool {
        self.0.migrations_applied()
    }

    fn database_configured(&self) -> bool {
        self.0.pool.is_some()
    }

    fn database_pool_in_use(&self) -> u32 {
        self.0.pool_in_use()
    }
}

fn event_broadcast(
    pool: Option<PgPool>,
    database_url: Option<String>,
    capacity: usize,
) -> EventBroadcast {
    let Some((pool, database_url)) =
        pool.zip(database_url.filter(|value| !value.trim().is_empty()))
    else {
        return EventBroadcast::new(capacity);
    };
    EventBroadcast::new_with_relay(capacity, move |local| {
        PgEventNotificationRelay::start(pool, database_url, local, capacity)
    })
}

struct PgEventNotificationRelay {
    relay_tx: mpsc::Sender<EventNotification>,
}

#[derive(Clone)]
struct PgEventNotificationWorker {
    pool: PgPool,
    database_url: String,
    origin: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PgEventNotificationEnvelope {
    origin: String,
    notification: EventNotification,
}

impl PgEventNotificationRelay {
    fn start(
        pool: PgPool,
        database_url: String,
        local: EventBroadcast,
        capacity: usize,
    ) -> Arc<dyn EventNotificationRelay> {
        let worker = Arc::new(PgEventNotificationWorker {
            pool,
            database_url,
            origin: uuid::Uuid::now_v7().to_string(),
        });
        let (relay_tx, mut relay_rx) = mpsc::channel(capacity.max(1));
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let listener = worker.clone();
            handle.spawn(async move {
                listener.listen_forever(local).await;
            });
            handle.spawn(async move {
                while let Some(notification) = relay_rx.recv().await {
                    if let Err(error) = worker.publish(notification).await {
                        tracing::warn!(%error, "failed to publish event notification over PostgreSQL");
                    }
                }
            });
        }
        Arc::new(Self { relay_tx })
    }
}

impl EventNotificationRelay for PgEventNotificationRelay {
    fn publish(&self, notification: EventNotification) {
        match self.relay_tx.try_send(notification) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("PostgreSQL event notification queue is full");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!("PostgreSQL event notification publisher stopped");
            }
        }
    }
}

impl PgEventNotificationWorker {
    async fn publish(&self, notification: EventNotification) -> anyhow::Result<()> {
        let payload = serde_json::to_string(&PgEventNotificationEnvelope {
            origin: self.origin.clone(),
            notification,
        })?;
        coland_storage_postgres::publish_event_notification(&self.pool, &payload).await?;
        Ok(())
    }

    async fn listen_forever(self: Arc<Self>, local: EventBroadcast) {
        loop {
            if let Err(error) = self.listen_once(&local).await {
                tracing::warn!(%error, "PostgreSQL event notification listener stopped");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn listen_once(&self, local: &EventBroadcast) -> anyhow::Result<()> {
        let (client, mut connection) = tokio_postgres::connect(&self.database_url, NoTls).await?;
        let (sender, mut receiver) = mpsc::channel::<String>(128);
        // Drive the connection while issuing LISTEN. Awaiting the command before
        // polling Connection deadlocks its own request/response transport.
        let drive = async {
            loop {
                match poll_fn(|cx| connection.poll_message(cx)).await {
                    Some(Ok(AsyncMessage::Notification(notification))) => {
                        if notification.channel() == EVENT_NOTIFICATION_CHANNEL {
                            sender.send(notification.payload().to_owned()).await?;
                        }
                    }
                    Some(Ok(AsyncMessage::Notice(notice))) => {
                        tracing::debug!(message = %notice.message(), "PostgreSQL listener notice");
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err::<(), _>(anyhow::Error::from(error)),
                    None => return Err(anyhow::anyhow!("PostgreSQL listener connection closed")),
                }
            }
        };
        let consume = async {
            client
                .batch_execute(&format!("LISTEN {EVENT_NOTIFICATION_CHANNEL}"))
                .await?;
            while let Some(reference) = receiver.recv().await {
                let Ok(id) = uuid::Uuid::parse_str(&reference) else {
                    tracing::warn!("ignored malformed PostgreSQL event notification reference");
                    continue;
                };
                let Some(payload) =
                    coland_storage_postgres::load_event_notification(&self.pool, id).await?
                else {
                    tracing::warn!(%id, "PostgreSQL event notification reference expired");
                    continue;
                };
                let Ok(envelope) = serde_json::from_str::<PgEventNotificationEnvelope>(&payload)
                else {
                    tracing::warn!("ignored malformed PostgreSQL event notification payload");
                    continue;
                };
                if envelope.origin != self.origin {
                    let _ = local.send_local(envelope.notification);
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(drive, consume)?;
        Ok(())
    }
}

#[cfg(test)]
mod notification_tests {
    use super::*;

    #[tokio::test]
    async fn independent_listeners_forward_large_events_without_origin_echo() {
        let database = coland_storage_postgres::TestDatabase::lease().await;
        let make_worker = |origin: &str| {
            Arc::new(PgEventNotificationWorker {
                pool: database.pool(),
                database_url: database.url().to_owned(),
                origin: origin.to_owned(),
            })
        };
        let first = make_worker("first");
        let second = make_worker("second");
        let first_local = EventBroadcast::new(32);
        let second_local = EventBroadcast::new(32);
        let mut first_rx = first_local.subscribe();
        let mut second_rx = second_local.subscribe();
        let first_listener = first.clone();
        let second_listener = second.clone();
        let first_task =
            tokio::spawn(async move { first_listener.listen_once(&first_local).await });
        let second_task =
            tokio::spawn(async move { second_listener.listen_once(&second_local).await });
        let large_body = serde_json::json!({"ciphertext": "x".repeat(32_768)});
        let exchange = async {
            let mut received_first = false;
            let mut received_second = false;
            while !received_first || !received_second {
                first
                    .publish(EventNotification::event(
                        "from-first".into(),
                        "cursor".into(),
                        large_body.clone(),
                    ))
                    .await
                    .unwrap();
                second
                    .publish(EventNotification::event(
                        "from-second".into(),
                        "cursor".into(),
                        large_body.clone(),
                    ))
                    .await
                    .unwrap();
                if !received_first
                    && let Ok(Ok(notification)) =
                        tokio::time::timeout(Duration::from_millis(100), first_rx.recv()).await
                {
                    assert_eq!(notification.realm_id, "from-second");
                    let coland_http::state::EventNotificationKind::Event { event_payload, .. } =
                        notification.kind
                    else {
                        panic!("expected event");
                    };
                    assert_eq!(event_payload, large_body);
                    received_first = true;
                }
                if !received_second
                    && let Ok(Ok(notification)) =
                        tokio::time::timeout(Duration::from_millis(100), second_rx.recv()).await
                {
                    assert_eq!(notification.realm_id, "from-first");
                    let coland_http::state::EventNotificationKind::Event { event_payload, .. } =
                        notification.kind
                    else {
                        panic!("expected event");
                    };
                    assert_eq!(event_payload, large_body);
                    received_second = true;
                }
            }
        };
        let result = tokio::time::timeout(Duration::from_secs(5), exchange).await;
        first_task.abort();
        second_task.abort();
        result.expect("both independent LISTEN connections must become ready and deliver");
    }
}

/// Mount the fixed native consumer using the existing normally paired runtime home.
pub async fn start_native_arkret_public_replies(
    state: AppState,
    home: Option<&str>,
) -> anyhow::Result<Option<savfox_gateway_server::NativePublicReplyHandle>> {
    let Some(home) = home else {
        return Ok(None);
    };
    anyhow::ensure!(
        !home.trim().is_empty(),
        "native Agent runtime home is empty"
    );
    let path = std::path::PathBuf::from(home);
    anyhow::ensure!(
        path.is_absolute(),
        "native Agent runtime home must be absolute"
    );
    let host = Arc::new(ColandNativePublicReplyHost { state });
    savfox_gateway_server::start_native_arkret_public_replies(path, host)
        .await
        .map(Some)
}

struct ColandNativePublicReplyHost {
    state: AppState,
}

#[async_trait::async_trait]
impl savfox_gateway_server::NativePublicReplyHost for ColandNativePublicReplyHost {
    async fn acquire_reply_cut(
        &self,
        source: &savfox_gateway_server::NativeReplySource,
        frozen: &savfox_gateway_server::FrozenNativeProviderRequest,
    ) -> anyhow::Result<Box<dyn savfox_gateway_server::NativePublicReplyGuard>> {
        // Credentials remain untrusted until the original Station gates accept them.
        let credentials = &source.credentials;
        let mut request = salvo::Request::default();
        *request.method_mut() = credentials
            .method
            .parse()
            .map_err(|_| anyhow::anyhow!("native source request method is invalid"))?;
        *request.uri_mut() = credentials
            .canonical_url
            .parse()
            .map_err(|_| anyhow::anyhow!("native source request URI is invalid"))?;
        *request.headers_mut() = credentials.headers.clone();
        let grant = request
            .headers()
            .get(salvo::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("DPoP "))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("native source credentials are unavailable"))?
            .to_owned();
        let guard = coland_http::routing::acquire_native_message_reply_cut(
            &self.state,
            &mut request,
            &grant,
            &source.agent,
            &source.controller,
            &source.caller,
            &source.accepted,
            &source.scope,
            &source.strand,
            credentials.operation,
        )
        .await
        .map_err(|_| anyhow::anyhow!("native current reply preparation refused"))?;
        Ok(Box::new(ColandNativePublicReplyGuard {
            guard,
            exact_digest: frozen.digest().clone(),
        }))
    }
}

struct ColandNativePublicReplyGuard {
    guard: Box<dyn coland_storage::AccountContentDeliveryGuard>,
    exact_digest: arkret_wire::Hash,
}

impl ColandNativePublicReplyGuard {
    fn require_handoff(&self, digest: &arkret_wire::Hash) -> anyhow::Result<()> {
        anyhow::ensure!(
            digest == &self.exact_digest && self.guard.permits_handoff(),
            "native reply current handoff refused",
        );
        Ok(())
    }
}

#[async_trait::async_trait]
impl savfox_gateway_server::NativePublicReplyGuard for ColandNativePublicReplyGuard {
    fn permits_model_handoff(&mut self, digest: &arkret_wire::Hash) -> anyhow::Result<()> {
        self.require_handoff(digest)
    }

    fn permits_response_chunk(&mut self, digest: &arkret_wire::Hash) -> anyhow::Result<()> {
        self.require_handoff(digest)
    }

    async fn finish(self: Box<Self>) -> anyhow::Result<()> {
        self.guard
            .finish()
            .await
            .map_err(|_| anyhow::anyhow!("native reply current guard release failed"))
    }
}
