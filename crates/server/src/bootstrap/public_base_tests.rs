struct InterruptedBundleBackend {
    inner: FileIdentityBundleBackend,
    fail_target: std::sync::atomic::AtomicBool,
    target: CanonicalServiceUrl,
}

impl IdentityBundleBackend for InterruptedBundleBackend {
    fn probe(&self) -> IdentityBundleBackendAvailability {
        self.inner.probe()
    }
    fn load(
        &self,
        key: &ServiceRegistrationKey,
    ) -> arkret_identity::Result<Option<DidCoreIdentityBundle>> {
        self.inner.load(key)
    }
    fn store(&self, bundle: &DidCoreIdentityBundle) -> arkret_identity::Result<()> {
        if self.fail_target.load(std::sync::atomic::Ordering::SeqCst)
            && bundle.identity.identity.registration_key.public_base_url() == &self.target
        {
            return Err(arkret_identity::IdentityError::Protocol(
                "injected post-cut bundle failure".into(),
            ));
        }
        self.inner.store(bundle)
    }
    fn delete(&self, key: &ServiceRegistrationKey) -> arkret_identity::Result<()> {
        self.inner.delete(key)
    }
}

#[tokio::test]
async fn explicit_public_base_migration_rolls_back_or_recovers_without_identity_loss() {
    use diesel_async::RunQueryDsl;
    let database = Arc::new(TestDatabase::lease().await);
    let pool = database.pool();
    let store = Arc::new(PgPersistenceStore::leased(database.clone()));
    let persistence = PersistenceHandle::new(store.clone());
    let keys = TestKeyStore::default();
    let root =
        std::env::temp_dir().join(format!("coland-migration-bundle-{}", uuid::Uuid::now_v7()));
    let target = "https://migration-target.example/";
    let backend = InterruptedBundleBackend {
        inner: FileIdentityBundleBackend::new(root),
        fail_target: std::sync::atomic::AtomicBool::new(false),
        target: CanonicalServiceUrl::canonicalize(target).unwrap(),
    };
    let config = bootstrap_config();
    resolve_service_identity(&persistence, &config, Some(&keys), Some(&backend), true)
        .await
        .unwrap();
    let original = store.service_identity().get().await.unwrap().unwrap();
    let original_bundle =
        IdentityBundleBackend::load(&backend, &original.identity.registration_key)
            .unwrap()
            .unwrap();
    let plan = public_base::migrate_with_storage(
        &persistence,
        &config,
        &keys,
        Some(&backend),
        &config.public_base_url,
        target,
        public_base::MigrationOptions {
            preflight: true,
            preserve_did_host: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(plan["status"], "preflight");
    assert_eq!(
        store.service_identity().get().await.unwrap().unwrap(),
        original
    );
    assert_eq!(
        persistence
            .webvh_history(original.identity.did.as_str())
            .await
            .unwrap()
            .len(),
        1
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("CREATE OR REPLACE FUNCTION fail_migration_mapping() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.public_base_url='https://migration-target.example/' THEN RAISE EXCEPTION 'injected registration mapping failure'; END IF; RETURN NEW; END $$").execute(&mut *conn).await.unwrap();
    diesel::sql_query("CREATE TRIGGER fail_migration_mapping BEFORE INSERT OR UPDATE ON service_identity_registrations FOR EACH ROW EXECUTE FUNCTION fail_migration_mapping()").execute(&mut *conn).await.unwrap();
    drop(conn);
    assert!(
        public_base::migrate_with_storage(
            &persistence,
            &config,
            &keys,
            Some(&backend),
            &config.public_base_url,
            target,
            public_base::MigrationOptions {
                preflight: false,
                preserve_did_host: false
            },
        )
        .await
        .is_err()
    );
    assert_eq!(
        store.service_identity().get().await.unwrap().unwrap(),
        original
    );
    assert_eq!(
        persistence
            .webvh_history(original.identity.did.as_str())
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        persistence
            .service_registration_receipts(&original.identity.service_id)
            .await
            .unwrap()
            .len(),
        1
    );
    let target_key =
        ServiceRegistrationKey::new(ServiceKind::Station, backend.target.clone()).unwrap();
    assert!(
        persistence
            .service_registration(&target_key)
            .await
            .unwrap()
            .is_none()
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("DROP TRIGGER fail_migration_mapping ON service_identity_registrations")
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    backend
        .fail_target
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        public_base::migrate_with_storage(
            &persistence,
            &config,
            &keys,
            Some(&backend),
            &config.public_base_url,
            target,
            public_base::MigrationOptions {
                preflight: false,
                preserve_did_host: false
            },
        )
        .await
        .is_err()
    );
    let accepted = store.service_identity().get().await.unwrap().unwrap();
    assert_eq!(accepted.identity.service_id, original.identity.service_id);
    assert_eq!(accepted.identity.registration_key, target_key);
    assert_ne!(accepted.identity.did, original.identity.did);
    assert_eq!(
        persistence
            .webvh_history(original.identity.did.as_str())
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        persistence
            .service_registration(&target_key)
            .await
            .unwrap()
            .unwrap()
            .registration_receipt,
        accepted.registration_receipt
    );
    backend
        .fail_target
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let retry = public_base::migrate_with_storage(
        &persistence,
        &config,
        &keys,
        Some(&backend),
        &config.public_base_url,
        target,
        public_base::MigrationOptions {
            preflight: false,
            preserve_did_host: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(retry["status"], "already_current");
    assert_eq!(
        persistence
            .webvh_history(original.identity.did.as_str())
            .await
            .unwrap()
            .len(),
        2
    );
    let bundle = IdentityBundleBackend::load(&backend, &target_key)
        .unwrap()
        .unwrap();
    bundle.validate().unwrap();
    assert_eq!(bundle.receipt_chains.len(), 2);
    let empty = leased_store().await;
    let empty_persistence = PersistenceHandle::new(empty.clone());
    assert!(
        restore_identity_bundle(
            &empty_persistence,
            &config,
            Some(&keys),
            original.identity.registration_key.clone(),
            original_bundle
        )
        .await
        .is_err(),
        "an old origin bundle cannot roll back the accepted control-key floor"
    );
    assert!(empty.service_identity().get().await.unwrap().is_none());
    let changed = AppConfig {
        public_base_url: target.into(),
        ..bootstrap_config()
    };
    let restored = restore_identity_bundle(
        &empty_persistence,
        &changed,
        Some(&keys),
        target_key.clone(),
        bundle,
    )
    .await
    .unwrap();
    assert_eq!(restored, accepted);
    assert_eq!(
        empty_persistence
            .service_registration(&target_key)
            .await
            .unwrap()
            .unwrap()
            .registration_receipt,
        accepted.registration_receipt
    );
    assert_eq!(
        empty_persistence
            .service_registration_receipts(&accepted.identity.service_id)
            .await
            .unwrap()
            .len(),
        2
    );
    let state = resolve_service_identity(&persistence, &config, Some(&keys), Some(&backend), false)
        .await
        .unwrap();
    assert!(matches!(
        state,
        DidCoreIdentityState::RegistrationKeyDrift { .. }
    ));
    assert_eq!(
        persistence
            .webvh_history(original.identity.did.as_str())
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn explicit_endpoint_migration_preserves_independent_did_host() {
    let database = Arc::new(TestDatabase::lease().await);
    let store = Arc::new(PgPersistenceStore::leased(database.clone()));
    let persistence = PersistenceHandle::new(store.clone());
    let keys = TestKeyStore::default();
    let config = bootstrap_config();
    resolve_service_identity(&persistence, &config, Some(&keys), None, true)
        .await
        .unwrap();
    let original = store.service_identity().get().await.unwrap().unwrap();
    let target = "https://independent-endpoint.example/";
    let plan = public_base::migrate_with_storage(
        &persistence,
        &config,
        &keys,
        None,
        &config.public_base_url,
        target,
        public_base::MigrationOptions {
            preflight: true,
            preserve_did_host: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(plan["target_did"], original.identity.did.as_str());
    assert_eq!(
        store.service_identity().get().await.unwrap().unwrap(),
        original
    );
    public_base::migrate_with_storage(
        &persistence,
        &config,
        &keys,
        None,
        &config.public_base_url,
        target,
        public_base::MigrationOptions {
            preflight: false,
            preserve_did_host: true,
        },
    )
    .await
    .unwrap();
    let updated = store.service_identity().get().await.unwrap().unwrap();
    assert_eq!(updated.identity.did, original.identity.did);
    assert_eq!(updated.identity.service_id, original.identity.service_id);
    assert_eq!(
        updated.identity.registration_key.public_base_url().as_str(),
        target
    );
    assert_ne!(updated.identity.version_id, original.identity.version_id);
    let entries = persistence
        .webvh_history(updated.identity.did.as_str())
        .await
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0].operation["state"]["id"],
        entries[1].operation["state"]["id"]
    );
    let receipt_count = persistence
        .service_registration_receipts(&updated.identity.service_id)
        .await
        .unwrap()
        .len();
    assert_eq!(receipt_count, 2);
    let retry = public_base::migrate_with_storage(
        &persistence,
        &config,
        &keys,
        None,
        &config.public_base_url,
        target,
        public_base::MigrationOptions {
            preflight: false,
            preserve_did_host: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(retry["status"], "already_current");
    assert_eq!(
        store.service_identity().get().await.unwrap().unwrap(),
        updated
    );
}
