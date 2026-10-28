# Deploying coland

Production guidance for running coland as a single-process Arkret v1 reference
server. coland is pre-1.0 — the push outbound bridge, the MIMI provider
directory and most of the directory surface are still scaffold endpoints that
return placeholder shapes. Review them before serving real users.

## Prerequisites

| Component | Recommended | Notes |
| --- | --- | --- |
| OS | Linux (Debian/Ubuntu LTS) | Other targets are CI-tested but less battle-hardened |
| PostgreSQL | 16+ | `pq-src` builds libpq inline; the runtime image only needs the network reachability |
| Reverse proxy | nginx, Caddy, or Traefik | TLS termination is **expected** to live in the reverse proxy, not coland itself |
| Object storage | local volume or S3-compatible bucket | Local disk is fine for one node; production should prefer S3/MinIO/R2-style object storage |
| Key custody | encrypted file + external 32-byte master key | Ciphertext and master key must have separate backup and access-control boundaries |
| Container runtime | Docker / containerd / Podman | Build or load the image locally; this readiness workflow does not push registry images or tags |

## 1. Provision PostgreSQL

```sql
CREATE ROLE coland WITH LOGIN PASSWORD '<strong-random-password>';
CREATE DATABASE coland OWNER coland;
GRANT ALL PRIVILEGES ON DATABASE coland TO coland;
```

coland runs Diesel migrations on startup; no manual DDL is required.

## 2. Configure environment

### Provision the KeyStore master key

Generate the encrypted-file KeyStore master key exactly once, outside the
server startup path. `coland-keystore-keygen` obtains 32 bytes from the
operating-system CSPRNG, writes the Base64 value with create-new semantics,
validates the result, and refuses to overwrite an existing file. The
`--if-missing` option is reserved for idempotent automation such as
`just init-dev`; it still rejects malformed existing files.

Installed-binary usage:

```text
coland-keystore-keygen --output <path>
```

From a source checkout, the command is cross-platform:

```text
cargo run --locked --release -p coland-keystore-keygen -- --output <path>
```

For a Linux Docker host, the release image contains the helper. Create a
host directory writable by the image's UID `10001`, run the helper as an
explicit one-shot operation, and then make the result read-only:

```bash
sudo install -d -m 0700 -o 10001 -g 10001 /secure/coland
docker run --rm \
  --entrypoint /usr/local/bin/coland-keystore-keygen \
  --mount type=bind,source=/secure/coland,target=/secrets \
  ghcr.io/arkret-org/coland:<tag> \
  --output /secrets/coland-keystore-master-key
sudo chmod 0400 /secure/coland/coland-keystore-master-key
```

On Windows or Windows Docker Desktop, use the same image and protect the host
file with an ACL. Run these commands from PowerShell:

```powershell
$keyDir = 'D:\coland\secrets'
New-Item -ItemType Directory -Force -Path $keyDir | Out-Null
$keyDir = (Resolve-Path -LiteralPath $keyDir).Path

docker run --rm `
  --entrypoint /usr/local/bin/coland-keystore-keygen `
  --mount "type=bind,source=$keyDir,target=/secrets" `
  ghcr.io/arkret-org/coland:<tag> `
  --output /secrets/coland-keystore-master-key

$keyFile = Join-Path $keyDir 'coland-keystore-master-key'
$account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $keyFile /inheritance:r /grant:r "${account}:(R)"
```

If Docker runs under a dedicated Windows service account, grant that account
read access instead of the interactive user. Do not place the key in the image,
the source tree, an environment file committed to Git, or the same backup as
`COLAND_KEYSTORE_PATH`. Preserve the original key for every restart and
restore; losing or replacing it makes the encrypted KeyStore unreadable.

### Configure runtime values

Create a deploy-time `.env` (or a Kubernetes Secret / systemd EnvironmentFile):

```dotenv
COLAND_BIND=0.0.0.0:8698
COLAND_PUBLIC_BASE_URL=https://coland.example
COLAND_TLS_CERT_PATH=/etc/coland/tls/fullchain.pem
COLAND_TLS_KEY_PATH=/etc/coland/tls/privkey.pem
COLAND_PQ_TLS_DEPLOYMENT_PROBE=verified
# One-time only on the first production boot; remove after identity creation.
COLAND_FIRST_PROVISIONING=true
COLAND_KEYSTORE_BACKEND=encrypted_file
COLAND_KEYSTORE_PATH=/var/lib/coland/keystore/coland.v1
COLAND_KEYSTORE_MASTER_KEY_FILE=/run/secrets/coland-keystore-master-key
COLAND_SERVICE_IDENTITY_BUNDLE_DIR=/var/lib/coland/identity-bundle
COLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED=true
COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER=<shared-secret-configured-in-coauth>
# Optional: use a standalone webvh provider instead of, or alongside, the embedded provider.
# COLAND_EXTERNAL_WEBVH_PROVIDER_URL=https://webvh.example
# COLAND_EXTERNAL_WEBVH_REGISTRATION_BEARER=<provider-registration-secret>
# With both values set, Coland's own identity is Provider-backed (class A), so
# COLAND_FIRST_PROVISIONING is not required.
# COLAND_DEFAULT_WEBVH_PROVIDER_ID=coland.embedded
COLAND_ACCOUNT_AUTHORITY_URL=https://coauth.example
COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN=ak:trust_domain:coauth.example
COLAND_SESSION_GRANT_INTROSPECTION_URL=https://coauth.example/_coauth/internal/session-grants/introspect
COLAND_AUTH_SESSION_LOGOUT_URL=https://coauth.example/_coauth/internal/auth-sessions/logout
COLAND_INTERNAL_AUTHORITY_SHARED_SECRET=<shared-secret-configured-in-coauth>
COLAND_OBJECT_STORAGE_BACKEND=s3-compatible
COLAND_OBJECT_STORAGE_S3_BUCKET=coland
COLAND_OBJECT_STORAGE_S3_REGION=us-east-1
COLAND_OBJECT_STORAGE_S3_ENDPOINT=https://s3.example.com
COLAND_OBJECT_STORAGE_S3_ACCESS_KEY_ID=<access-key>
COLAND_OBJECT_STORAGE_S3_SECRET_ACCESS_KEY=<secret-key>
COLAND_OBJECT_STORAGE_S3_FORCE_PATH_STYLE=true
COLAND_OBJECT_STORAGE_PREFIX=prod
COLAND_CORS_ALLOW_ORIGIN=https://app.example
COLAND_MAX_REQUEST_SIZE=1048576
DATABASE_URL=postgres://coland:<password>@db.internal:5432/coland?sslmode=verify-full

# `COLAND_DEVELOPMENT_MODE` is unset (defaults to false). Enabling it in
# production permits local network egress and development diagnostics; it never
# relaxes formal signature/DID validation. Synthetic login/admin credentials
# exist only in explicitly compiled conformance-harness builds, not default binaries.

RUST_LOG=coland=info,salvo=info,warn
```

`COLAND_MAX_REQUEST_SIZE` is parsed as bytes. Leave it unset for the default
1 MiB body cap; requests above the cap return `413 Payload Too Large` before
the route handler reads JSON or form data.

### Embedded webvh provider: deployment-profile gate

The embedded webvh provider (`COLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED=true`)
is only suitable for `ak.profile.personal_node.v1` and
`ak.profile.small_team.v1` deployments. Those profiles accept a single
witness proof with no distinct-controlling-organization requirement, so a
self-hosted provider is a conformant — though explicitly degraded —
identity bootstrap for them.

`ak.profile.organization.v1` and every higher profile MUST NOT bootstrap the
service identity from the embedded (local) provider. The spec witness
baseline (arkret-spec `spec/v1/zh/identity/identity-did.md` §3.4.2) requires
at least 2 valid witness proofs from at least 2 distinct controlling
organizations for those profiles, and forbids host self-witnessing as the
sole basis for high-risk control decisions. coland's local/embedded provider
path performs no witness verification at all (see the trust-root layering
note below), so it can never satisfy that baseline. For `organization` and
above, provision the service identity through an external webvh provider
(`COLAND_EXTERNAL_WEBVH_PROVIDER_URL` +
`COLAND_EXTERNAL_WEBVH_REGISTRATION_BEARER`) whose DID log carries the
required independent witness proofs.

### Witness verification is layered by trust root

The describe payload advertises `"webvh_witness_quorum": "unsupported"` only
under the `coland.local_identity_store` trust root
(`crates/http/src/routing/identity/did/webvh.rs`). The flag is scoped, not
global — coland has two distinct did:webvh paths:

- **Local / embedded provider path — always rejects (fail-closed).** DID
  logs handled through the local identity store are validated by
  `webvh_validation::validate_witness_policy_for_log`
  (`crates/http/src/routing/identity/webvh_validation.rs`), which rejects
  any log entry that declares a witness policy with `WitnessQuorumNotMet`.
  No witness proof is ever evaluated on this path. The rejection is
  intentional fail-closed behavior matching the advertised `"unsupported"`;
  it must not be relaxed into unconditional acceptance.
- **External resolution path — real witness verification.**
  Pinned/historical did:webvh resolution
  (`crates/http/src/did_resolver_chain.rs`, `fetch_verified_webvh_history`)
  fetches `did-witness.json` whenever the log declares a witness policy and
  calls the SDK `verify_did_webvh_v1_chain_and_witness_bytes`, performing
  full chain + witness verification. The spec §3.4 requirement that every
  v1 core station MUST support did:webvh witness verification is
  satisfied by this external resolution path, not by the local store.

### Advanced environment reference

Most deployments only need the variables in the sample above. The table below
lists the remaining runtime variables coland reads, including security-sensitive
and rollout-only switches that should be managed deliberately.

| Variable | Default | Purpose |
| --- | --- | --- |
| `COLAND_ADMIN_PRINCIPAL_IDS` | empty | Comma-separated typed principal ID allowlist (`ak:did_core:…`) for production admin APIs. An empty value closes the admin API outside development mode; browser sessions additionally require `COLAND_SESSION_GRANT_INTROSPECTION_URL`. |
| `COLAND_ADMIN_PAGE_LIMIT` | `100` | Default admin API page size. |
| `COLAND_ADMIN_MAX_PAGE_LIMIT` | `1000` | Maximum admin API page size; clamped above the default. |
| `COLAND_AGENT_PARTICIPATION_CEILING` | all five bits `true` | Closed JSON object with required boolean fields `message_creation_allowed`, `reaction_addition_allowed`, `reaction_removal_allowed`, `third_party_mention_delivery_allowed`, and `acting_on_behalf_allowed`. This deployment ceiling only narrows participation; it does not grant permissions or override management restrictions. Invalid JSON or unknown fields fail startup. |
| `COLAND_APPLET_TRANSACTION_INFLIGHT_CAPACITY` | `64` | Maximum concurrent applet transactions retained in memory. |
| `COLAND_ARKRET_RUNTIME_HOME` | unset | Absolute path to an existing normally paired native Agent runtime home. Enables the embedded Savfox public reply consumer; unset leaves the consumer inactive. Empty or relative paths fail startup. |
| `COLAND_CONFORMANCE_CURSOR_EMISSION_PAUSE_FILE` | unset | Development-only Account WebSocket cursor delivery probe path for builds with `conformance-harness`. The file selects input cursor digests; a sibling `.pause` file pauses delivery for at most 15 seconds and `.reached.json` records the pending frame. Unset disables the probe; production mode ignores it. |
| `COLAND_CONFORMANCE_SIGNAL_EMISSION_PAUSE_FILE` | unset | Development-only Signal frame scheduling probe path for builds with `conformance-harness`. Unset disables the probe; production mode ignores it. |
| `COLAND_CONFORMANCE_INVITE_DELIVERY_PAUSE_FILE` | unset | Development-only final invite delivery probe. A JSON file selects the holder Account and Invite; `.reached` marks arrival. Removing the file resumes delivery; a 15-second deadline fails the probe. Production mode ignores it. |
| `COLAND_CONFORMANCE_MEDIA_TOKEN_RELEASE_PAUSE_FILE` | unset | Development-only media token final-cut probe. A JSON request digest selects the exchange; `.reached` marks arrival. Removing the file resumes release; a 15-second deadline fails the probe. Production mode ignores it. |
| `COLAND_CONFORMANCE_PRIVATE_EFFECTS_PAUSE_FILE` | unset | Development-only Consent private-effects scheduler pause. An existing file pauses publication without changing admission or durable state. Remove it to resume; production mode ignores it. |
| `COLAND_DB_POOL_ACQUIRE_TIMEOUT_SECS` | deadpool default | Positive database-pool acquisition timeout; unset means no explicit wait timeout. |
| `COLAND_DB_POOL_MAX_SIZE` | CPU count × 4 | Positive database-pool size override. |
| `COLAND_DID_RESOLVER_ALLOW_METHODS` | `web,key,uuid` | Comma-separated DID methods accepted by outbound DID resolution. |
| `COLAND_DEACTIVATION_PROPAGATION_WINDOW_MS` | `86400000` | Positive acknowledgement window for exact account-deactivation propagation; expiry with pending destinations sets the durable admin projection to incomplete while retries continue. |
| `COLAND_EGRESS_ALLOW_PRIVATE_NETWORKS` | development mode | Authoritative override for private/link-local outbound destinations. Keep `false` in production unless the network path has been explicitly reviewed. |
| `COLAND_EGRESS_ALLOWED_HOSTS` | empty | Optional comma-separated exact/wildcard outbound host allowlist. |
| `COLAND_EGRESS_DENYLIST` | empty | Comma-separated outbound host denylist; evaluated in addition to the private-network guard. |
| `COLAND_EXTERNAL_WEBVH_PROVIDER_TRUST_DOMAIN` | derived trust domain | Expected trust domain for the external webvh provider probe. |
| `COLAND_FEDERATION_DENYLIST` | empty | Comma-separated federation host/service denylist. |
| `COLAND_FEDERATION_FANOUT_TOPOLOGY` | `mesh` | Federation fanout topology (`mesh` or `hub`). |
| `COLAND_FEDERATION_PEER_DENYLIST` | empty | Additional comma-separated peer denylist. |
| `COLAND_HEALTHCHECK_URL` | derived from `COLAND_BIND` | URL used by the built-in healthcheck command. |
| `COLAND_ICE_STUN_URLS` | `stun:stun.l.google.com:19302` | Comma-separated STUN URLs advertised in signed ICE configs. |
| `COLAND_ICE_TTL_SECONDS` | `300` | Lifetime of an issued ICE config / TURN credential before refresh; non-positive falls back to default. |
| `COLAND_ICE_REFRESH_LEAD_SECONDS` | `75` | Lead time before TTL at which clients should refresh the ICE config. |
| `COLAND_INTERNAL_AUTHORITY_SHARED_SECRET_FILE` | unset | Path to a non-empty UTF-8 file containing the per-edge internal authority secret; surrounding whitespace is trimmed. It replaces the direct secret value, not the channel's URL or trust-domain bindings. Setting both forms, even to the same secret, fails startup. |
| `COLAND_KEY_BACKUP_DAILY_DOWNLOAD_LIMIT` | spec default | Per-principal daily key-backup download limit. |
| `COLAND_NOTARY_SIGNING_KEY` | unset | Base64 (standard or url-safe-no-pad) 32-byte NotaryWorker signing seed. Required outside development mode unless a durable `COLAND_KEYSTORE_BACKEND` is configured; an ephemeral notary key breaks the Seal signature chain across restarts. |
| `COLAND_OBJECT_STORAGE_S3_SESSION_TOKEN` | unset | Optional S3 session token for temporary credentials. |
| `COLAND_OBJECT_STORAGE_S3_SKIP_SIGNATURE` | `false` | Skip S3 request signing for test-only object stores; do not enable for production S3. |
| `COLAND_SECURITY_ROTATION_WORKER_INTERVAL_SECONDS` | `5` | Durable SecurityRotation worker sweep interval, an integer in `1..=3600` seconds. An invalid value fails startup. |
| `COLAND_TRUSTED_PUSH_GATEWAYS` | empty registry | Closed JSON array of entries containing `canonical_origin`, `service_did`, `receipt_verification_method`, and `receipt_public_key_multibase`. Each explicitly onboarded HTTPS origin binds its Gateway DID and canonical Ed25519 receipt key; malformed or duplicate bindings fail startup. Federation peers and user-supplied Gateway URLs do not establish this trust. |
| `COLAND_WEBSOCKET_MAX_LIFETIME_SECS` | `600` | Physical WebSocket lifetime before bounded drain. Must parse as an unsigned integer and is clamped to `1..=600` seconds; malformed values fail startup. |
| `COLAND_RECEIVE_POLICY_*` | unset | Optional ServiceDescribe receive-policy constraints. See `.env.example` for exact names and accepted values. |
| `COLAND_RATE_LIMIT_TRUST_X_FORWARDED_FOR` | `false` | Trust `X-Forwarded-For` for rate limiting when behind a trusted proxy. |
| `COLAND_SEED_DEMO_DATA` | `false` | Seed deterministic demo data. Test/development only; never enable in production. |
| `COLAND_SERVICE_IDENTITY_BUNDLE` | unset | Identity-bundle input used only by `coland-keystore-snapshot`; the server uses `COLAND_SERVICE_IDENTITY_BUNDLE_DIR`. |
| `COLAND_SHUTDOWN_GRACE_SECS` | `0` | Graceful-drain bound in seconds; `0` waits indefinitely. |
| `COLAND_TO_DEVICE_QUEUE_CAPACITY` | `10000` | Per-device in-memory to-device queue capacity. Overflow advances the lost watermark. |
| `COLAND_TURN_URLS` | `turn:turn.coland.local:3478?transport=udp` | Comma-separated TURN URLs advertised in signed ICE configs. |
| `COLAND_TURN_SECRET_ROTATION_WINDOW_SECS` | `86400` | Rotation window for the TURN shared secret used in credential derivation. |
| `COLAND_TURN_SHARED_SECRET` | unset | Optional shared secret folded into derived TURN credentials (`*_FILE` form supported); when unset, credential material is unchanged. |
| `COLAND_LIVEKIT_API_KEY` | unset | LiveKit API Key. In the LiveKit binding (`bindings/livekit.md` §2) this is the focus `issuer_kid`; the `livekit` focus token issuer fails closed unless the realm focus `issuer_kid` matches this value. |
| `COLAND_LIVEKIT_API_SECRET` | unset | LiveKit API Secret (`*_FILE` form supported). HMAC-SHA256 signing key for the LiveKit JWT; never exposed in any cell, `/health`, or describe payload. Required together with `COLAND_LIVEKIT_API_KEY` to mint LiveKit backend tokens. |
| `COLAND_RESUMABLE_UPLOAD_DIR` | `./coland-resumable-uploads` | Directory for resumable-upload staging files. |
| `COLAND_RESUMABLE_UPLOAD_TTL_SECS` | `86400` | Incomplete resumable-upload TTL; minimum 60 seconds. |
| `COLAND_SOVEREIGN_ENCLAVE` | `false` | Enables the sovereign-enclave startup and egress security posture; it does not advertise a conformance profile. |
| `COLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS` | empty | Comma-separated outbound host allow-list for sovereign-enclave deployments. |
| `COLAND_VERIFIED_PROFILES_ARTIFACT` | unset | Path to a cotest `verified-profiles.json` artifact to advertise verified profiles. |

Validate the env block on the target host once:

```bash
coland --bind "${COLAND_BIND}" --help    # cheap startup sanity check
```

## 3. Run the binary

### systemd unit

```ini
[Unit]
Description=coland — Arkret v1 Station
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=coland
Group=coland
EnvironmentFile=/etc/coland/coland.env
ExecStart=/usr/local/bin/coland
WorkingDirectory=/var/lib/coland
StateDirectory=coland
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/coland
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

coland traps `SIGINT` / `SIGTERM` and runs Salvo's graceful shutdown, so
`systemctl stop` (or `docker stop` / Kubernetes pod termination) drains
in-flight requests before exiting.

### Docker

```bash
docker run --name coland --restart=always -d \
  -p 127.0.0.1:8698:8698 \
  -e COLAND_BIND=0.0.0.0:8698 \
  -e COLAND_PUBLIC_BASE_URL=https://coland.example \
  -e COLAND_FIRST_PROVISIONING=true \
  -e COLAND_KEYSTORE_BACKEND=encrypted_file \
  -e COLAND_KEYSTORE_PATH=/var/lib/coland/keystore/coland.v1 \
  -e COLAND_KEYSTORE_MASTER_KEY_FILE=/run/secrets/coland-keystore-master-key \
  -e COLAND_SERVICE_IDENTITY_BUNDLE_DIR=/var/lib/coland/identity-bundle \
  -e COLAND_ACCOUNT_AUTHORITY_URL=https://coauth.example \
  -e COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN=ak:trust_domain:coauth.example \
  -e COLAND_SESSION_GRANT_INTROSPECTION_URL=https://coauth.example/_coauth/internal/session-grants/introspect \
  -e COLAND_AUTH_SESSION_LOGOUT_URL=https://coauth.example/_coauth/internal/auth-sessions/logout \
  -e COLAND_INTERNAL_AUTHORITY_SHARED_SECRET=<shared-secret-configured-in-coauth> \
  -e DATABASE_URL=postgres://coland:<password>@db:5432/coland?sslmode=verify-full \
  -e COLAND_OBJECT_STORAGE_BACKEND=filesystem \
  -e COLAND_OBJECT_STORAGE_LOCAL_ROOT=/var/lib/coland/objects \
  -e RUST_LOG=coland=info \
  --mount type=volume,source=coland-data,target=/var/lib/coland \
  --mount type=bind,source=/secure/coland/coland-keystore-master-key,target=/run/secrets/coland-keystore-master-key,readonly \
  ghcr.io/arkret-org/coland:<tag>
```

The image runs as UID `10001`. Mounted volumes for
`COLAND_OBJECT_STORAGE_LOCAL_ROOT` must be chowned to that UID (or use a named
Docker volume so Docker handles it). The mounted KeyStore master-key file must
be readable by UID `10001`; generate and back it up separately from the named
ciphertext volume. After the first successful identity creation, recreate the
container without `COLAND_FIRST_PROVISIONING`; it is a one-time authorization,
not a permanent runtime setting. S3-compatible backends do not need a media
volume.

### Helm

The production chart lives at `deploy/helm/coland`. Render it before applying
so secrets and network ranges are explicit in the release artifact:

```bash
helm template coland ./deploy/helm/coland \
  --namespace arkret \
  --set image.tag=<tag> \
  --set existingSecret=coland-runtime \
  --set env.COLAND_PUBLIC_BASE_URL=https://coland.example \
  --set env.COLAND_FIRST_PROVISIONING=true \
  --set env.COLAND_KEYSTORE_BACKEND=encrypted_file \
  --set env.COLAND_KEYSTORE_PATH=/var/lib/coland/keystore/coland.v1 \
  --set env.COLAND_ACCOUNT_AUTHORITY_URL=https://coauth.example
```

Create `coland-runtime` through the cluster's secret-management path before
rendering or installing the chart. It must provide every key listed under
`secretEnv` in `values.yaml`, including `COLAND_KEYSTORE_MASTER_KEY`. Prefer an
external secret controller or encrypted GitOps secret; do not pass secret
values through Helm `--set`, where they can leak into shell history and release
metadata.

Install the same values with:

```bash
helm upgrade --install coland ./deploy/helm/coland \
  --namespace arkret --create-namespace \
  -f production-values.yaml
```

For production, set `networkPolicy.enabled=true` and provide
`networkPolicy.egress.databaseCidrs`, `objectStorageCidrs`, and `oauthCidrs`
for the actual PostgreSQL, S3-compatible object storage, and coauth
introspection endpoints. Leave `COLAND_DEVELOPMENT_MODE` unset; the chart
does not set it by default.

## 4. Front with TLS

coland speaks plaintext HTTP — terminate TLS in the reverse proxy.
The Arkret v1 transport baseline requires TLS 1.3 connections to negotiate
`X25519MLKEM768` and fail closed when the peer cannot offer it. Run that
handshake probe against the externally reachable client-service and
service-to-service listener, then set `COLAND_PQ_TLS_DEPLOYMENT_PROBE=verified`
only for a passing deployment. Production `/readyz` returns 503 until that
machine-verifiable probe evidence is present.

Caddy example:

```caddyfile
coland.example {
    encode zstd gzip

    @api {
        path /api/* /.well-known/* /health
    }
    handle @api {
        reverse_proxy 127.0.0.1:8698 {
            header_up X-Forwarded-Proto {scheme}
            header_up X-Forwarded-For {remote_host}
        }
    }
}
```

Make sure the proxy passes the `Authorization`, `X-Arkret-Wait-For`,
`X-Arkret-SHA256`, and `Range` request headers; coland sends back
`Retry-After`, `X-Arkret-Wait-For-Satisfied`, `Content-Range`, and
`Accept-Ranges`.

## 5. Health checks

The `/health` endpoint returns a small JSON envelope plus
`200 OK` (or `503 Service Unavailable` when the database / persistence probe
fails).

Docker:

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:8698/health || exit 1
```

Kubernetes:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8698
  initialDelaySeconds: 10
  periodSeconds: 30
readinessProbe:
  httpGet:
    path: /readyz
    port: 8698
  initialDelaySeconds: 5
  periodSeconds: 10
```

`/readyz` returns `503` until the database probe succeeds, boot migrations have
completed, configured introspection bearers are present, and any configured
external webvh provider has passed the startup `/describe` probe.

## 6. Backups

| Object | What to back up | How |
| --- | --- | --- |
| PostgreSQL | All tables | `pg_dump` daily, plus continuous WAL archiving for point-in-time recovery |
| Object storage bucket/volume | Uploaded media | enable bucket versioning or snapshot the local volume on the same cadence as the database; align so blob references in the DB stay resolvable |
| Service identity database rows + identity bundle | Stable DID, WebVH history, and public recovery evidence | Back up the database and `COLAND_SERVICE_IDENTITY_BUNDLE_DIR`; keep private keys in the configured secret store |
| Encrypted KeyStore | Service signing and WebVH control seeds | Back up `COLAND_KEYSTORE_PATH` and its master key through separate systems; neither artifact is recoverable from the other |

Restore order: stop coland → restore DB, identity bundle, and encrypted KeyStore → restore the master key through its secret-management path → restore object storage bucket/volume → start coland.
The startup migrations are idempotent.

## 7. Observability

coland emits structured `tracing` events with stable `event` and `worker`
fields for process lifecycle and background tasks. It also exposes
Prometheus text metrics on a separate listener:

```dotenv
COLAND_METRICS_BIND=127.0.0.1:9090
```

Scrape `http://127.0.0.1:9090/metrics` for:

- `coland_request_total{op,status}`
- `coland_request_duration_seconds` histogram buckets
- `coland_db_pool_in_use`
- `coland_federation_outbox_depth` (rows still owed to a peer: `pending` +
  `leased`)
- `coland_federation_outbox_state_depth{state,peer}` — per-peer breakdown
  across the full lifecycle, including `policy_suppressed`
- `coland_federation_outbox_oldest_pending_age_seconds`
- `coland_federation_retry_delay_seconds` histogram
- `coland_federation_outbox_lease_takeover_total`
- `coland_federation_outbox_dead_letter_total{reason}` (P5 — counter; alert on
  any non-zero rate over 5m via `examples/prometheus-alerts.yml`)
- `coland_audit_append_failures_total` (alert on any non-zero rate over
  5m — see `examples/prometheus-alerts.yml`)

A copy-pasteable `prometheus-alerts.yml` lives under `examples/`; load
it via Prometheus' `rule_files:` directive.

### Structured JSON logging

Production deployments default to **JSON logs** when
`COLAND_DEVELOPMENT_MODE=false` (the default). One log line per event,
keyed by the standard `tracing` span / field set, ready for ingestion
by Loki / OpenSearch / Cloud Logging without a bespoke parser. Force
the format explicitly with `COLAND_LOG_FORMAT=json|plain`. The
runbook log-search recipes in `docs/runbook.md` assume the JSON shape.

OpenTelemetry tracing is build-time opt-in so ordinary local runs do not pull
an exporter:

```powershell
cargo run --features otel -- --bind 127.0.0.1:8698
```

Enable OTLP export at runtime:

```dotenv
COLAND_OTEL_EXPORTER=otlp
COLAND_OTEL_ENDPOINT=http://otel-collector:4317
COLAND_OTEL_SERVICE_NAME=coland
COLAND_OTEL_SAMPLE_RATIO=1.0
COLAND_OTEL_TIMEOUT_SECS=3
```

Remaining roadmap before 1.0:

- per-handler `instrument` spans carrying `actor / space / event_kind`

Set `RUST_LOG=coland=debug,salvo=info,warn` in production-like environments
while closing 1.0 readiness. Keep `COLAND_LOG_FILE` pointed at a durable path
when running under a supervisor that buffers stdout.

Alert on:

- `200 /health` request rate dropping below the configured threshold
- 5xx error rate over rolling 5-minute windows
- `auth.dev_login` audit events outside the development environment (this
  should be impossible with `COLAND_DEVELOPMENT_MODE=false`, but alert
  belt-and-braces)

### Local observability and rate-limit examples

Minimal local metrics-only run:

```dotenv
COLAND_BIND=127.0.0.1:8698
COLAND_METRICS_BIND=127.0.0.1:9090
RUST_LOG=coland=info,salvo=warn
```

OTLP trace export run:

```powershell
$env:COLAND_OTEL_EXPORTER="otlp"
$env:COLAND_OTEL_ENDPOINT="http://127.0.0.1:4317"
$env:COLAND_OTEL_SAMPLE_RATIO="0.25"
cargo run --features otel -- --bind 127.0.0.1:8698
```

Single-process local reverse-proxy rate-limit sketch:

```nginx
limit_req_zone $binary_remote_addr zone=coland_api:10m rate=600r/m;

server {
  listen 443 ssl;
  server_name coland.example;

  location / {
    limit_req zone=coland_api burst=120 nodelay;
    proxy_pass http://127.0.0.1:8698;
  }
}
```

For multi-replica deployments, enforce the quota at the shared gateway or
load balancer. coland's in-process limiter remains useful as a last-resort
guard, but it is not a distributed budget.

## 8. Local supply-chain artifacts

The CI, release and local image builds use the same dependency layout:
`arkret-org/{coland,arkret-rust-sdk,arkret-spec,floria,garth,bridges}` alongside
`savfox-ai/savfox`. Cargo paths are checked out in that layout; image builds
provide all six dependency repositories as named BuildKit contexts.

The supply-chain gate rejects reported vulnerabilities. `deny.toml` records
four reviewed INFO Unmaintained notices retained by upstream dependencies:

| Advisory | Dependency | Review scope |
| --- | --- | --- |
| [RUSTSEC-2024-0388](https://rustsec.org/advisories/RUSTSEC-2024-0388.html) | `derivative` via Starlark | Compile-time derive macro; no patched upstream release. |
| [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html) | `paste` via Starlark | Compile-time token macro; no patched upstream release. |
| [RUSTSEC-2025-0057](https://rustsec.org/advisories/RUSTSEC-2025-0057.html) | `fxhash` via Starlark | Internal evaluator maps; the notice reports maintenance status. |
| [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173.html) | `proc-macro-error2` via Teloxide/Aquamarine | Documentation macro diagnostics; no patched upstream release. |

These dependencies remain in the reviewed graph. Other advisories, including
future vulnerability reports for these crates, remain subject to the gate.
Revisit the exceptions when the owning upstream dependencies change. Starlark
0.14.2 pins BLAKE3 1.8.2 and cannot resolve alongside the SDK's BLAKE3 1.8.7
requirement; the compatible Starlark/allocative family stays pinned.

Generate local image metadata and an SPDX JSON SBOM without pushing an image or
creating a release tag:

```powershell
pwsh ./scripts/local-supply-chain.ps1 -ImageTag coland:local
```

The script writes:

- `target/supply-chain/coland-build-metadata.json` from `docker buildx`
- `target/supply-chain/coland.spdx.json` from `syft`

For local provenance evidence, sign or attest the generated metadata with an
operator-owned key:

```bash
cosign attest-blob \
  --key cosign.key \
  --type slsaprovenance \
  --predicate target/supply-chain/coland-build-metadata.json \
  target/supply-chain/coland-build-metadata.json
```

## 9. Upgrade procedure

1. Read the changelog / release notes for the target tag.
2. `pg_dump` the database.
3. Pull / install the new binary or container image.
4. Restart coland; embedded migrations run on boot.
5. Tail logs for at least one request cycle (`/health`, `/_arkret/describe`).

Downgrades are **not** supported once a migration has run; restore from the
pre-upgrade backup if you need to roll back.

### Registered audit units and planned handoff

A database recovery must restore the complete frozen private state, including
canonical Event/Commit originals and signer facts, `registered_audit_units`,
`watch_audit_read_results`, `event_approval_private_audit`,
`registered_audit_forward_units`, `registered_audit_replica_units`, current
projections, nonce fences and outbox. A member Snapshot or a readable scan suffix
is not a private backup. Restore into an isolated database before serving it;
keep Station identity and key custody under the destination deployment's own
configuration rather than deriving identity from imported Realm rows.

For a planned Realm handoff, first accept the governance change to freeze the
outgoing streams, then privately import the consistent frozen state. The
registered handoff HTTP operation activates that pre-imported state; it is not
an alternative bulk-data carrier. Activation checks complete originals, final
heads, signer inventory, pair request/outcome fences, frozen Watch observations
and their private approval digests. Missing or changed audit material returns
`revision_unavailable` without activation. Exact handoff replay repeats the
private archive checks.

An origin retains the complete signed pair before forwarding and its verified
original acknowledgement afterwards. After response loss, retry the same unit;
refresh only transport producer evidence. Never recreate either Event or accept
a surviving fragment separately. Historical pair acknowledgements remain
original acceptance facts after a verified handoff; an old frozen audited Watch
read cannot establish the new generation's current state and needs a new audit
Event for a new observation.

## 10. Hardening checklist

- `COLAND_DEVELOPMENT_MODE` is unset (or explicitly `false`).
- `COLAND_ACCOUNT_AUTHORITY_URL` points at coauth's public account authority,
  and `COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN` is its explicit source trust
  domain. It is never inferred from the URL.
- The Account Authority signs as this Station with a delegated assertion method, even when it runs at a separate origin.
- `COLAND_SESSION_GRANT_INTROSPECTION_URL` points at coauth's
  `/_coauth/internal/session-grants/introspect`, and
  `COLAND_INTERNAL_AUTHORITY_SHARED_SECRET` matches the shared
  server-to-server secret configured there (coauth's
  `stations[].internal_authority_shared_secret` for this Station).
- Before registering the channel, Coland canonicalizes
  `COLAND_ACCOUNT_AUTHORITY_URL` and requires every configured bearer target to
  use its exact origin (same scheme, host and effective port). Introspection and
  Auth-side logout must use their exact operation paths; credentials, query and
  fragment are forbidden. The controller-gate target is derived as its exact
  path on that same origin. Any conflict aborts startup before the bearer can be
  sent.
- Setting that bearer together with the Authority URL/trust domain registers a
  deployment-internal authenticated channel between this Station and that
  Account Authority. Current-device admission enters Coland only through the
  product-private `POST /_coland/account-authority/current-device/check`
  adapter. It is not an Arkret Operation and is never advertised through
  Service Describe. Nothing on `/_arkret/peer/*` accepts this bearer; every
  peer operation keeps its RFC 9421 service signature.
  Every plaintext proxy on this internal link is a trusted member of the same
  deployment TCB; Coland does not model or inspect the proxy chain.
- Account Authority calls to `GET /_arkret/self/agents/{id}` and
  `POST /_arkret/gate/account/agent-key-pair` are outside that four-operation
  bearer channel. They require an RFC 9421 signature whose source and
  destination service ids both equal this Station, whose trust-domain headers
  match the explicitly configured Authority and Station domains, and whose
  `keyid` is exactly this Station DID's delegated `#account-authority`
  assertion method. The shared bearer does not authorize these routes.
- `COLAND_AUTH_SESSION_LOGOUT_URL` independently points at coauth's exact
  `/_coauth/internal/auth-sessions/logout` private adapter; it is never
  inferred from the introspection URL.
- `DATABASE_URL` uses `sslmode=verify-full` and a password kept out of source
  control (Vault / Kubernetes Secret / systemd `LoadCredential`).
- `COLAND_CORS_ALLOW_ORIGIN` is the **single** browser origin you trust;
  never `*` while coland sets `Access-Control-Allow-Credentials: true`.
- Object storage uses a dedicated bucket/prefix or a dedicated local volume
  with quota enforcement.
- Reverse proxy enforces TLS 1.2+ and the security headers you require.
- Reverse proxy / gateway TLS 1.3 probe verifies `X25519MLKEM768` negotiation
  and sets `COLAND_PQ_TLS_DEPLOYMENT_PROBE=verified`; classical fallback is not
  accepted.
- Reverse proxy, API gateway, or load balancer enforces a shared rate-limit
  budget when more than one coland replica is running. coland's built-in
  limiter is per-process and must not be treated as a distributed quota.
- `cargo deny check` runs in CI on every dependabot bump.
- coland process runs as a non-root user (UID 10001 in the local container image).
- Rate-limit configuration matches your anticipated traffic and is enforced
  at the shared gateway when more than one coland replica is running.

## 11. Service-identity signing-key custody

The active signing key is bound to the WebVH DID document and persisted
service-identity bundle. Coland does not expose an online key-only rotation
endpoint: changing only the runtime or KeyStore seed would split those
authorities. A future rotation workflow must commit the KeyStore write,
WebVH update, DID document, identity bundle and recovery material as one
recoverable transition before an admin route is added.

Use `coland-keystore-snapshot --export-only` and `--import-only` only for
backup/restore of the already-bound key. They do not rotate identity material.

## 12. Known limits

- **Rate limiting**: the built-in limiter is per-process. Multi-replica
  deployments **MUST** enforce a shared rate-limit budget at the reverse
  proxy or API gateway (see SECURITY.md and `docs/architecture.md` §4).
  Until an external Redis (or equivalent) backend is wired in, treat the
  per-process quota as a single-instance soft floor; production fleets MUST
  front coland with nginx/Caddy/Traefik `limit_req` or an API gateway that
  shares state across replicas.

### AKP-0007 (Circle primitive) — migration & sizing notes

- **Schema**: the `projection_circles` / `projection_circle_members` mirror
  tables and the `scope_circle_id` / `default_scope_circle_id` /
  `child_scope_policy` / `effective_scope` columns on the Strand / Morph /
  Space / Events mirrors are part of the squashed
  `00000000000000_initial` migration; there is no separate Circle upgrade
  step.
- **Disk sizing**: `effective_scope` adds one nullable `TEXT` column per
  projected Event. A complete `ak:circle:<44-char event token>` value is 54
  bytes on the wire; PostgreSQL's short `TEXT` header and tuple alignment put
  the stored cost around 55–60 bytes per row, plus the BTREE index entry on
  `projection_events_effective_scope_idx`. A 100M-event projection grows
  by ~7 GiB total (table + index). Drop the index if your deployment never
  filters projection reads by Circle scope.
- **Multi-replica + Circle membership**: the Circle membership FSM lives
  on the durable event log, so cross-replica consistency comes for free
  once the underlying Postgres replication is healthy. The
  `circle_member_must_be_realm_member` invariant is checked in-reducer; a
  replica that hasn't replayed the parent Realm's latest `ak.member.state`
  events will fail-closed on Circle membership writes — the canonical fix
  is to gate writes behind the federation outbox acknowledgement.
- **Metrics**: Prometheus text metrics are exposed on the separate
  `COLAND_METRICS_BIND` listener (default `127.0.0.1:9090`) at `/metrics`.
- **OpenTelemetry**: OTLP trace export is disabled unless the binary is built
  with `--features otel` and `COLAND_OTEL_EXPORTER=otlp` is set.
- **Scaffold endpoints**: push outbound bridge, the MIMI provider directory,
  and most of the directory surface return placeholder shapes.
- **Pre-1.0 schema drift**: protocol field renames may require client updates
  between releases.

## Pre-1.0 schema initialization

Coland keeps the current pre-1.0 schema in
`crates/storage-postgres/migrations/00000000000000_initial`. New deployments
run that migration as a unit; the historical per-feature R3 migration list is
no longer part of this repository.

### `ak.realm.media_service.foci[]` shape

R3 uses a `foci[]` array so that a realm can advertise multiple
media foci (e.g. one LiveKit pool and one Mediasoup pool, or
geo-distributed pools):

```json
{
  "media_service": {
    "foci": [
      {
        "focus_id": "livekit_eu-west-1",
        "backend": "livekit",
        "connect_url": "https://sfu.eu-west-1.example.org",
        "issuer_kid": "ak.media-issuer/example/2026-05"
      }
    ]
  }
}
```

A `media_service` cell without a non-empty `foci[]` array is outside the
canonical shape — capture the row and escalate; do not delete.

### ICE / TURN vs. media-service foci — two distinct config layers

Media connectivity is configured in two independent layers:

- **Per-deployment ICE/STUN/TURN (P2P NAT traversal)** — set via the
  `COLAND_ICE_*` / `COLAND_TURN_*` env vars above. These feed the signed
  `POST /_arkret/self/rtc/ice-config` response. Defaults reproduce the
  historical hardcoded `stun.l.google.com` / `turn.coland.local` values so
  existing deployments behave identically until overridden. Point
  `COLAND_TURN_URLS` at your own coturn/eturnal pool for production.
- **Per-realm SFU foci (LiveKit / Mediasoup conferencing)** — declared in the
  realm `ak.component.realm.media_service.v1` cell as the `foci[]` array shown
  above, consumed by the AKP-0010 token exchange at
  `POST /_arkret/self/rtc/token`. This is where a LiveKit pool's
  `connect_url` / `issuer_kid` / `audience` are bound; it is realm-scoped
  config, not a deployment env var.
  - **LiveKit API Key/Secret** are the one piece of the LiveKit binding that
    *is* a deployment env var: set `COLAND_LIVEKIT_API_KEY` +
    `COLAND_LIVEKIT_API_SECRET` so the `livekit` focus mints a standard
    LiveKit JWT (`HS256` over `header.payload`, signed with the API Secret —
    `bindings/livekit.md` §2). The realm focus `issuer_kid` MUST equal
    `COLAND_LIVEKIT_API_KEY`; a mismatch (or unset credentials) fails the
    token exchange closed instead of issuing a token LiveKit would reject.
    v1 supports a single API Key/Secret pair; mapping multiple LiveKit
    deployments (one pair per cluster, keyed by focus `issuer_kid`) is
    follow-up work.

### Recovery persistence

The initial schema contains `recovery_policies`, `recovery_sessions`,
`security_transactions`, their step outcomes/attempts, and durable terminal
artifacts. There is deliberately no standalone `recovery_receipts` table or
write path: a terminal recovery receipt is accepted only as the signed final
artifact of its `RecoveryTransaction`, and exact replay is served from that
transaction's durable first outcome.

### Agent FSM cell

The agent FSM is owned by a cell (`ak.component.agent_state.v1`) with
`lattice = fsm, bottom = reject`. Agent operations `pause`, `resume` and
`deactivate` (`POST /agents/{id}/deactivate`) transition it.
