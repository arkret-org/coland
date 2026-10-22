// The production Savfox consumer uses real Realm Device reads and publication.
#[allow(clippy::too_many_arguments, reason = "The fixture keeps independent signed originals, accepted references and source-time coordinates explicit.")]
async fn verify_bot_consumer(
    fixture: &Fixture,
    edge: Arc<arkret_bridge_runtime::ArkretEdge>,
    devices: &arkret_bridge_runtime::managed_device::ManagedDeviceRuntime,
    device: &arkret_bridge_runtime::managed_device::ManagedDevice,
    _reader: &arkret_bridge_runtime::managed_device::ManagedDeviceReader,
    group: &mut arkret_mls::ArkretMlsGroup,
    actor: &ActorId,
    scope: &ScopeRef,
    rotate_during_reply: bool,
) {
    use arkret_bridge_runtime::managed_device::{
        NativeContent, NativeContentRecipient, NativeContentSink,
    };
    use diesel_async::RunQueryDsl as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    struct ModelServer(tokio::task::JoinHandle<()>);
    impl Drop for ModelServer {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let received = calls.clone();
    let release = Arc::new(tokio::sync::Notify::new());
    let model_release = release.clone();
    let _server = ModelServer(tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let (headers_end, length) = loop {
                let mut buffer = [0u8; 8192];
                let size = socket.read(&mut buffer).await.unwrap();
                assert_ne!(size, 0);
                bytes.extend_from_slice(&buffer[..size]);
                assert!(bytes.len() < 131_072);
                if let Some(at) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&bytes[..at]).unwrap();
                    assert!(headers.starts_with("POST /responses HTTP/1.1"));
                    let length = headers
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                        .unwrap()
                        .1
                        .trim()
                        .parse::<usize>()
                        .unwrap();
                    break (at + 4, length);
                }
            };
            while bytes.len() < headers_end + length {
                let mut buffer = [0u8; 8192];
                let size = socket.read(&mut buffer).await.unwrap();
                assert_ne!(size, 0);
                bytes.extend_from_slice(&buffer[..size]);
            }
            let request: Value =
                serde_json::from_slice(&bytes[headers_end..headers_end + length]).unwrap();
            assert_eq!(request["model"], "gpt-5.1");
            assert_eq!(request["store"], false);
            assert!(
                request
                    .get("tools")
                    .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
            );
            assert!(!request["input"].as_array().unwrap().is_empty());
            received.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if rotate_during_reply {
                model_release.notified().await;
            }
            let events = [
                json!({"type":"response.created","response":{"id":"bot-response","status":"in_progress"}}),
                json!({"type":"response.completed","response":{"id":"bot-response","status":"completed","output":[{"type":"message","id":"bot-message","role":"assistant","content":[{"type":"output_text","text":"Native Bot reply"}]}]}}),
            ];
            let body = events
                .into_iter()
                .map(|value| format!("data: {value}\n\n"))
                .collect::<String>();
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(reply.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        }
    }));
    let home = std::env::temp_dir().join(format!("realm-bot-consumer-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        format!(
            r#"model = {{ slug = "gpt-5.1", provider = "native_fixture" }}
[model_providers.native_fixture]
name = "Native fixture"
base_url = "http://{address}"
wire_api = "responses"
requires_openai_auth = false
"#
        ),
    )
    .unwrap();
    let make_sink = || {
        savfox_gateway_server::NativeRealmBotReplies::from_home(
            Arc::new(
                arkret_bridge_runtime::managed_device::ManagedDeviceRuntime::new(edge.clone())
                    .unwrap(),
            ),
            actor.clone(),
            "native-bot-fixture".into(),
            home.clone(),
        )
    };
    struct CrashBeforeAck {
        inner: savfox_gateway_server::NativeRealmBotReplies,
        original: std::sync::Mutex<Option<(NativeContentRecipient, NativeContent)>>,
    }
    #[async_trait::async_trait]
    impl NativeContentSink for CrashBeforeAck {
        async fn deliver(
            &self,
            recipient: &NativeContentRecipient,
            content: &NativeContent,
        ) -> arkret_bridge_runtime::Result<()> {
            self.inner.deliver(recipient, content).await?;
            *self.original.lock().unwrap() = Some((recipient.clone(), content.clone()));
            Err(arkret_bridge_runtime::BridgeError::App(
                "crash after reply before stream ACK".into(),
            ))
        }
    }
    let sink = Arc::new(CrashBeforeAck {
        inner: make_sink().await.unwrap(),
        original: Default::default(),
    });
    let mut workers =
        arkret_bridge_runtime::managed_device::ManagedDeviceWorkers::new(edge.clone())
            .unwrap()
            .with_content_sink(sink.clone());
    workers.tick().await.unwrap();
    if rotate_during_reply {
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            while calls.as_ref().load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("model must receive the original input");
        eprintln!("native Bot restart: submit the intervening MLS update");
        realm_actor_mls_fixture::human_updates_group(fixture, scope, group).await;
        eprintln!("native Bot restart: inspect the durable pre-update epoch");
        assert_eq!(devices.installed_mls_epoch(device).await.unwrap(), Some(1));
        eprintln!("native Bot restart: release the model response");
        release.notify_one();
    }
    tokio::time::timeout(std::time::Duration::from_secs(300), async {
        loop {
            if sink.original.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("actual worker must publish the model reply");
    eprintln!("native Bot restart: stop the first worker after its durable reply");
    workers.shutdown().await;
    assert_eq!(calls.as_ref().load(std::sync::atomic::Ordering::SeqCst), 1);
    #[derive(diesel::QueryableByName)]
    struct Published {
        #[diesel(sql_type=diesel::sql_types::Text)]
        id: String,
    }
    let ids = diesel::sql_query("SELECT envelope->>'event_id' AS id FROM canonical_events WHERE envelope->'actor_id'=$1 AND envelope->>'kind'='ak.message.create'")
        .bind::<diesel::sql_types::Jsonb,_>(json!(actor)).load::<Published>(&mut fixture.pool.get().await.unwrap()).await.unwrap();
    assert_eq!(ids.len(), usize::from(!rotate_during_reply));
    if !rotate_during_reply {
        realm_actor_mls_fixture::verify_runtime_message(
            fixture,
            group,
            &ids[0].id,
            actor,
            &arkret::ContentBlock::text("Native Bot reply"),
        )
        .await;
    }
    let (recipient, content) = sink.original.lock().unwrap().take().unwrap();
    assert_eq!(recipient.actor_id(), actor);
    assert_eq!(recipient.scope(), scope);
    sink.inner.retire();
    assert!(sink.inner.deliver(&recipient, &content).await.is_err());
    drop(sink);
    assert!(
        recipient.check_incarnation().is_err(),
        "retired worker must invalidate retained source authority"
    );
    eprintln!("native Bot restart: open the retained consumer");
    let restarted = Arc::new(make_sink().await.unwrap());
    let mut workers =
        arkret_bridge_runtime::managed_device::ManagedDeviceWorkers::new(edge.clone())
            .unwrap()
            .with_content_sink(restarted.clone());
    eprintln!("native Bot restart: start the replacement worker");
    workers.tick().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            let published = diesel::sql_query("SELECT envelope->>'event_id' AS id FROM canonical_events WHERE envelope->'actor_id'=$1 AND envelope->>'kind'='ak.message.create'")
                .bind::<diesel::sql_types::Jsonb,_>(json!(actor)).load::<Published>(&mut fixture.pool.get().await.unwrap()).await.unwrap();
            if published.len() == 1 && devices
                .durable_stream_progress(device)
                .await
                .unwrap()
                .pending_events
                == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("restarted worker must acknowledge the original input");
    workers.shutdown().await;
    assert_eq!(calls.as_ref().load(std::sync::atomic::Ordering::SeqCst), 1);
    let ids_after = diesel::sql_query("SELECT envelope->>'event_id' AS id FROM canonical_events WHERE envelope->'actor_id'=$1 AND envelope->>'kind'='ak.message.create'")
        .bind::<diesel::sql_types::Jsonb,_>(json!(actor)).load::<Published>(&mut fixture.pool.get().await.unwrap()).await.unwrap();
    assert_eq!(ids_after.len(), 1);
    if rotate_during_reply {
        assert_eq!(devices.installed_mls_epoch(device).await.unwrap(), Some(2));
        realm_actor_mls_fixture::verify_runtime_message(
            fixture,
            group,
            &ids_after[0].id,
            actor,
            &arkret::ContentBlock::text("Native Bot reply"),
        )
        .await;
    } else {
        assert_eq!(ids_after[0].id, ids[0].id);
    }
}
