# coland

Reference Arkret v1 Station, built with Salvo, Diesel, and
PostgreSQL. The HTTP surface mirrors `arkret-spec/spec/v1/artifacts/openapi/arkret-service-api.openapi.yaml`;
in-memory mode keeps the same API for fast local iteration.

> See [DEPLOYMENT.md](DEPLOYMENT.md) for production guidance, [SECURITY.md](SECURITY.md)
> for vulnerability disclosure. Operator-facing internals:
>
> - [`docs/architecture.md`](docs/architecture.md) — reducer / projection
>   pipeline, federation outbox, MLS lifecycle, multi-replica notes.
> - [`docs/runbook.md`](docs/runbook.md) — common error codes, log-search
>   recipes, restart strategy, fault-injection drills.
> - [`docs/federation-s2s.md`](docs/federation-s2s.md) — peer onboarding,
>   signed trust-domain headers, canonical `Content-Digest`, and trust-domain
>   immutability.
> - [`examples/prometheus-alerts.yml`](examples/prometheus-alerts.yml) —
>   ready-made alert rules (audit-append failures, federation DLQ rate,
>   /readyz outages).

## Realm vs Space

- **Realm:** security boundary — membership, capability, E2EE, federation.
  Reducer cells live under `ak.realm.*`; admin routes use `/realms/:id/...`.
- **Space:** navigation container — board, list, section, calendar bucket
  inside a Realm.

`ak.realm.link` relationship metadata and local `ak.capability.grant`
are the typed edges that wire boundaries together (governed_by /
discoverable_from / mirror_of). Container lifecycle events use `ak.space.*`;
security-boundary lifecycle and policy events use `ak.realm.*`.

## Round R4 (protocol review closures)

Spec round 4 (`arkret-spec` range `2a4d39b..a77b995`, 8 commits) lands
on top of R2/R3. See [`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]` for
the canonical wire-breaking list.
Operator-visible highlights:

- **`trust_domain` is now immutable on a Realm** — captured by
  `ak.realm.create` and locked thereafter. Cross-domain replays reject
  with `cross_domain_replay_rejected`.
- **`ServiceDescribe` v2** — `ak.server.read.describe.v1` / `ak.self.account.read.describe.v1` /
  `ak.edge.applet.read.describe.v1` returns the 17-field
  canonical envelope, including `trust_domain` / `plaintext_visibility` /
  `verified_profiles` / `development_mode` and a `rate_limit` oneOf.
- **`/events/frontier` split by role** — `peer_role` query param routes
  to `account_client` / `federation_peer` / `anonymous_health`. The
  anonymous shape strips `receipts` and `actor_seq_upper_bounds`.
- **`/events/subscribe` typed frames** — NDJSON now emits typed
  `EventsSubscribeFrame{event|frontier|heartbeat|catchup_complete|
  epoch_rotation|dropped|resync_required|unauthorized}`. `dropped`
  MUST carry `cursor`.
- **Federation S2S transport signs trust-domain and body bindings** —
  `Source-Trust-Domain`, `Destination-Trust-Domain`, and the single RFC 9530
  `Content-Digest` are verified through the signature transcript.
- **Federation idempotency** — current peer signature and origin binding
  are checked before replay cache lookup; a revoked key returns
  `signature_invalid` with no new side effects.

## Round R2/R3 deployment requirements

Spec rounds 2+3 (2026-05-20) introduced wire-breaking changes that the
operator must address at boot — see
[`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]` and the `arkret-spec`
`spec/v1/zh/` normative source. The key operational hooks:

- **`COLAND_TRUST_DOMAIN`** — required `ak:trust_domain:<scope>` value
  (defaults to a value derived from the configured `service_id`) and binds
  peer authorization and recovery transcripts to this deployment.
- **Ephemeral kinds rejected on `POST /_arkret/self/events`** — producers
  must route the ephemeral kinds (`ak.call.signal`, `ak.presence`,
  `ak.typing`, `ak.receipt.read`) through the ephemeral envelope
  channel; no compatibility shim.
- **Realm terminal-state, presign blob fail-closed, federation
  idempotency cache, relaxed window ≤ 300 s** — see CHANGELOG for
  the full operator checklist.

## Quick start

coland depends on the `arkret-*` crates under `../arkret-rust-sdk/crates/`
via path dependencies. Clone both repos side by side:

```bash
git clone https://github.com/arkret-org/arkret-rust-sdk.git
git clone https://github.com/arkret-org/coland.git
cd coland
```

The shortest local workflow uses [`just`](https://github.com/casey/just).
Install it if needed:

```bash
cargo install just
```

Run `just` to see every available recipe.

### Run the local persistent profile

```bash
just start
```

`just start` (an alias of `just dev`) loads the checked-in local `.env`,
idempotently provisions the encrypted-file KeyStore master key, and then starts
Coland against the configured PostgreSQL database. Local custody artifacts are
kept outside Git:

```text
.local/secrets/coland-keystore-master-key  # separately stored master key
.local/keystore/coland.v1                  # encrypted private-key material
.local/identity-bundle/                    # public recovery evidence + KeyRefs
```

Realm, Event, account, and other application rows remain in PostgreSQL; Coland
does not currently provide a file-backed relational database under `.local`.
`COLAND_DEVELOPMENT_MODE` defaults to `false` in the server, while the `just`
development recipes set it to `true` unless overridden.

### Let Docker provide PostgreSQL

```bash
just start-db
```

`just start-db` starts a local `postgres:16` container named `coland-postgres`,
idempotently provisions `./.local/secrets/coland-keystore-master-key` with the
cross-platform `coland-keystore-keygen` helper, waits for PostgreSQL to accept
connections, then starts coland with the connection string below. Existing
valid keys are retained and malformed files fail closed. This path requires
Docker:

```dotenv
DATABASE_URL=postgres://coland:coland@localhost:5432/coland
```

Embedded Diesel migrations run on every startup; the tables are created
idempotently. To stop the local database container:

```bash
just db-down
```

If `.env` is absent, create it from the example, enable the encrypted-file
KeyStore settings and `DATABASE_URL`, and provision the local key:

```bash
just init-env
just init-dev
```

Then `just start` will use the durable configuration in that file. Calling
`just init-dev` again validates and retains the existing key.

Manual equivalent:

```bash
DATABASE_URL=postgres://coland:coland@localhost:5432/coland \
  COLAND_KEYSTORE_BACKEND=encrypted_file \
  COLAND_KEYSTORE_PATH=./.local/keystore/coland.v1 \
  COLAND_KEYSTORE_MASTER_KEY_FILE=./.local/secrets/coland-keystore-master-key \
  COLAND_DEVELOPMENT_MODE=true \
  cargo run -- --bind 127.0.0.1:8698
```

### Run with Docker

Provision the master key explicitly before the first container start. The
release image includes the same cross-platform helper used by `just init-dev`;
this Linux example creates the host directory for the image's UID `10001` and
never overwrites an existing key:

```bash
sudo install -d -m 0700 -o 10001 -g 10001 /secure/coland
docker run --rm \
  --entrypoint /usr/local/bin/coland-keystore-keygen \
  --mount type=bind,source=/secure/coland,target=/secrets \
  ghcr.io/arkret/coland:<tag> \
  --output /secrets/coland-keystore-master-key
sudo chmod 0400 /secure/coland/coland-keystore-master-key
```

Then mount that file read-only while keeping the encrypted KeyStore on a
persistent volume:

```bash
docker run --rm -p 8698:8698 \
  -e COLAND_PUBLIC_BASE_URL=https://coland.example \
  -e COLAND_FIRST_PROVISIONING=1 \
  -e COLAND_KEYSTORE_BACKEND=encrypted_file \
  -e COLAND_KEYSTORE_PATH=/var/lib/coland/keystore/coland.v1 \
  -e COLAND_KEYSTORE_MASTER_KEY_FILE=/run/secrets/coland-keystore-master-key \
  -e COLAND_SERVICE_IDENTITY_BUNDLE_DIR=/var/lib/coland/identity-bundle \
  -e COLAND_ACCOUNT_AUTHORITY_URL=https://coauth.example \
  -e COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN=ak:trust_domain:coauth.example \
  -e COLAND_SESSION_GRANT_INTROSPECTION_URL=https://coauth.example/_coauth/internal/session-grants/introspect \
  -e COLAND_AUTH_SESSION_LOGOUT_URL=https://coauth.example/_coauth/internal/auth-sessions/logout \
  -e COLAND_INTERNAL_AUTHORITY_SHARED_SECRET=shared-secret-known-by-coauth \
  -e DATABASE_URL=postgres://coland:coland@db:5432/coland \
  -e COLAND_OBJECT_STORAGE_BACKEND=filesystem \
  -e COLAND_OBJECT_STORAGE_LOCAL_ROOT=/var/lib/coland/objects \
  --mount type=volume,source=coland-data,target=/var/lib/coland \
  --mount type=bind,source=/secure/coland/coland-keystore-master-key,target=/run/secrets/coland-keystore-master-key,readonly \
  ghcr.io/arkret/coland:<tag>
```

Back up the mounted master key separately from the ciphertext volume. Remove
`COLAND_FIRST_PROVISIONING` after the first successful identity creation. The
identity bundle contains only public recovery evidence and KeyRefs; it is not a
substitute for control-key custody. Coland fails closed instead of writing
control seeds to PostgreSQL. Windows ACL and Docker Desktop examples are in
[DEPLOYMENT.md](DEPLOYMENT.md#provision-the-keystore-master-key).

See [DEPLOYMENT.md](DEPLOYMENT.md) for a full Docker / PostgreSQL / TLS guide.

## Configuration

All settings can be supplied via environment variables (preferred) or a
`.env` file at the working directory.

| Variable | Default | Purpose |
| --- | --- | --- |
| `COLAND_BIND` (or `--bind`) | `127.0.0.1:8698` | Listen address |
| `COLAND_PUBLIC_BASE_URL` | `http://<bind>` | Advertised base URL (`/_arkret/describe`) |
| `COLAND_TLS_CERT_PATH` | unset | TLS certificate PEM path; when paired with `COLAND_TLS_KEY_PATH`, coland serves HTTPS via rustls |
| `COLAND_TLS_KEY_PATH` | unset | TLS private-key PEM path paired with `COLAND_TLS_CERT_PATH` |
| `COLAND_PQ_TLS_DEPLOYMENT_PROBE` | unset | Set to `verified` only after an external TLS 1.3 probe proves `X25519MLKEM768` negotiation and fail-closed classical fallback |
| `COLAND_FIRST_PROVISIONING` | unset | One-time class-B production authorization to create a new service identity when no stored identity, local registration, or bundle exists |
| `COLAND_SERVICE_IDENTITY_BUNDLE_DIR` | unset | SDK identity-bundle backend used to recover the same service DID after database loss; contains public evidence and KeyRefs, never private keys |
| `COLAND_KEYSTORE_BACKEND` | unset | Durable key custody: `platform` for the current user's native credential store, or `encrypted_file`; required for runtime startup together with `DATABASE_URL` |
| `COLAND_KEYSTORE_PATH` | unset | Ciphertext file used by the `encrypted_file` backend; it may hold multiple isolated Coland namespaces |
| `COLAND_KEYSTORE_MASTER_KEY` / `_FILE` | unset | Base64-encoded, random 32-byte master key for `encrypted_file`; custody and backup must be separate from `COLAND_KEYSTORE_PATH` |
| `COLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED` | `true` | Enable coland's built-in `did:webvh` provider for coauth registration |
| `COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER` | unset | Shared bearer token coauth must present to write embedded `did:webvh` registrations |
| `COLAND_EXTERNAL_WEBVH_PROVIDER_URL` | unset | Optional external `did:webvh` provider; any standalone registrar implementing the `did:webvh` provider surface |
| `COLAND_EXTERNAL_WEBVH_REGISTRATION_BEARER` / `_FILE` | unset | When set with the external Provider URL, stores Coland's own service identity there (class A); no first-provisioning flag or configured DID is used |
| `COLAND_DEFAULT_WEBVH_PROVIDER_ID` | unset | Optional coauth default provider id: `coland.embedded` or `external.webvh` |
| `COLAND_ACCOUNT_AUTHORITY_URL` | unset | Canonical public Account Authority base URL advertised at `/_arkret/describe.auth_metadata.account_authority`; internal bearer targets must use this exact origin |
| `COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN` | unset | Explicit source trust domain of the configured Account Authority; required to register the unsigned §2.2.3 internal channel and never derived from its URL |
| `COLAND_SESSION_GRANT_INTROSPECTION_URL` | unset | Exact `/_coauth/internal/session-grants/introspect` endpoint used for `ak.session.grant + DPoP`; when the internal channel is registered it must match the Account Authority scheme, host and effective port and contain no credentials/query/fragment |
| `COLAND_AUTH_SESSION_LOGOUT_URL` | unset | Exact Account Authority process S2S `/_coauth/internal/auth-sessions/logout` endpoint; never derived from the introspection URL and subject to the same origin/URL restrictions |
| `COLAND_INTERNAL_AUTHORITY_SHARED_SECRET` | unset | Shared per-edge secret for this Station ↔ its Account Authority, presented as an HTTP Bearer token. Together with the Authority URL/trust domain it registers the trusted-proxy §2.2.3 channel, confined to exact-token introspection, Auth-side logout, controller-gate issue, and device-revocation gate check. Agent projection GET and Agent key pairing instead require the Station DID's delegated `#account-authority` RFC 9421 signature; this secret never authorizes them |
| `DATABASE_URL` | unset | Required for runtime startup; enables PostgreSQL and runs migrations. In-memory persistence is test-only, and a durable `COLAND_KEYSTORE_BACKEND` is mandatory |
| `COLAND_OBJECT_STORAGE_BACKEND` | `filesystem` | Blob object backend: `filesystem`/`local` or `s3-compatible` |
| `COLAND_OBJECT_STORAGE_LOCAL_ROOT` | system temp + `/coland-objects` | Local filesystem root when using `filesystem`/`local` |
| `COLAND_OBJECT_STORAGE_PREFIX` | unset | Optional object key prefix shared by local and S3-compatible backends |
| `COLAND_OBJECT_STORAGE_S3_BUCKET` | required for S3 | S3-compatible bucket name |
| `COLAND_OBJECT_STORAGE_S3_ENDPOINT` | region endpoint | Optional custom endpoint for MinIO/R2/etc. |
| `COLAND_CORS_ALLOW_ORIGIN` | unset | Comma-separated explicit browser origin allowlist; wildcards rejected; opt-in in every mode |
| `COLAND_DEVELOPMENT_MODE` | `false` | Enable the global development posture: dev-only endpoints (`dev_login`, admin snapshots, relaxed DID validation), private error diagnostics in server logs and `error.details.reason_detail`, and a default `debug` log filter when `RUST_LOG` is unset. Production responses continue to redact private diagnostics. |
| `COLAND_MAX_REQUEST_SIZE` | `16777216` | Maximum request body bytes Salvo will read before returning `413 Payload Too Large` (values below the protocol 16 MiB floor are clamped) |
| `COLAND_METRICS_BIND` | `127.0.0.1:9090` | Separate Prometheus listener; scrape `/metrics` |
| `COLAND_OTEL_EXPORTER` | unset | Set to `otlp` when built with `--features otel` to export traces |
| `COLAND_OTEL_ENDPOINT` | `http://127.0.0.1:4317` | OTLP gRPC collector endpoint when OTEL export is enabled |
| `COLAND_LOG_FORMAT` | `json` in prod, `plain` in dev | Tracing output format. Production deployments default to JSON for structured log aggregation; development defaults to ANSI-decorated text. Force either via `json` / `plain`. |
| `RUST_LOG` | unset | Tracing subscriber filter, e.g. `coland=info,salvo=warn` |

### OpenTelemetry tracing

OTLP trace export is a build-time opt-in to keep the default binary
free of the OpenTelemetry SDK. Build with `--features otel`, then set
`COLAND_OTEL_EXPORTER=otlp` at runtime to export spans to your
collector. The recommended local collector setup is the
[OpenTelemetry Collector Contrib](https://github.com/open-telemetry/opentelemetry-collector-contrib)
distribution with an `otlp` receiver on `:4317` and your preferred
backend (Tempo, Jaeger, Honeycomb, ...) as the exporter. See
[DEPLOYMENT.md §7](DEPLOYMENT.md) for the production env-var matrix and
sample collector config.

## Local TLS

For local HTTPS development, use `mkcert`. It installs a local CA into your
OS/browser trust store and produces PEM files that coland can hand directly to
Salvo's rustls listener.

The embedded `did:webvh` provider needs a dotted host, so plain `localhost` is
not enough. The examples below use `local.host`, matching the checked-in `.env`
and the `local.host.pem` / `local.host-key.pem` file names.

1. Install `mkcert` and trust its local CA:

   ```bash
   mkcert -install
   ```

2. Generate a certificate for the local hostname:

   ```bash
   mkcert local.host
   ```

3. If `local.host` does not already resolve to loopback on your machine, add a
   hosts entry pointing it at `127.0.0.1`.

4. Configure coland to use the generated files:

   ```dotenv
    COLAND_BIND=127.0.0.1:443
    COLAND_PUBLIC_BASE_URL=https://local.host:443
   COLAND_KEYSTORE_BACKEND=encrypted_file
   COLAND_KEYSTORE_PATH=./.local/keystore/coland.v1
   COLAND_KEYSTORE_MASTER_KEY_FILE=./.local/secrets/coland-keystore-master-key
    COLAND_SERVICE_IDENTITY_BUNDLE_DIR=./identity-bundle
   COLAND_TLS_CERT_PATH=./local.host.pem
   COLAND_TLS_KEY_PATH=./local.host-key.pem
   COLAND_OBJECT_STORAGE_BACKEND=filesystem
   COLAND_OBJECT_STORAGE_LOCAL_ROOT=../testdata
   COLAND_DEVELOPMENT_MODE=true
   ```

5. Start the server:

   ```bash
   just init-dev
   cargo run
   ```

If you choose a different hostname, update `COLAND_PUBLIC_BASE_URL` and the TLS
file paths together. Use a host name that
contains a dot so embedded `did:webvh` URLs remain valid.

### Run local Caddy for coauth integration

For local coauth + coland testing, the checked-in `Caddyfile` terminates HTTPS
on port 443 and proxies:

```text
https://local.host      -> 127.0.0.1:8698
https://auth.local.host -> 127.0.0.1:7080
```

Start coauth on `127.0.0.1:7080` first so its OIDC discovery and public JWKS
are available, then start coland on `127.0.0.1:8698`. Coauth keeps its business
routes unavailable until it has verified the running Station.

```dotenv
COLAND_BIND=127.0.0.1:8698
COLAND_PUBLIC_BASE_URL=https://local.host
COLAND_KEYSTORE_BACKEND=encrypted_file
COLAND_KEYSTORE_PATH=./.local/keystore/coland.v1
COLAND_KEYSTORE_MASTER_KEY_FILE=./.local/secrets/coland-keystore-master-key
COLAND_SERVICE_IDENTITY_BUNDLE_DIR=./identity-bundle
COLAND_DEVELOPMENT_MODE=true
COLAND_ACCOUNT_AUTHORITY_URL=https://auth.local.host
COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN=ak:trust_domain:auth.local.host
COLAND_OAUTH_CLIENT_ID=01GFWR28C4KNE04WG3HKXB7C9R
COLAND_SESSION_GRANT_INTROSPECTION_URL=https://auth.local.host/_coauth/internal/session-grants/introspect
COLAND_AUTH_SESSION_LOGOUT_URL=https://auth.local.host/_coauth/internal/auth-sessions/logout
COLAND_INTERNAL_AUTHORITY_SHARED_SECRET=local-coauth-session-grant-introspection
COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER=local-coland-webvh-registration
```

Those bearer values must match coauth's
`arkret.stations[]` entry for `https://local.host/`; otherwise
coauth will reject coland's introspection call and browser sign-in will end
with `unauthenticated: invalid bearer token`.

Run `just init-dev` once before starting this encrypted-file configuration;
subsequent runs validate and retain the existing local master key.

```bash
just caddy
```

If either host does not resolve to loopback on your machine, add both names to
your hosts file:

```text
127.0.0.1 local.host auth.local.host
```

When `COLAND_DEVELOPMENT_MODE=false` (the default), submitted commits must use
production proof material — no `alg: none` or `dev-proof`, proof `payload_digest`
must match the canonical commit digest, the verification method must be rooted
in the commit author DID, and proof `domain`/`audience` must bind to the
service DID resolved from the durable service identity record.

`GET /_arkret/root/identity/describe` exposes `did_webvh.providers[]` for coauth.
When the embedded provider is enabled, coauth can register through
`POST /_coland/root/identity/webvh/register` with `Authorization: Bearer
<COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER>`; coland then serves the DID
document and webvh log from `/webvh/{local_id}/did.json` and `.jsonl`. The
embedded DID uses the public `did:webvh:<scid>:<host>:webvh:<local_id>` path
rather than the internal registration API path.

Production authentication presents the coauth-issued `ak.session.grant`
directly to coland as `Authorization: DPoP <ak.session.grant>` plus a matching
`DPoP` proof. coland validates the grant through session-grant introspection
and maps its typed holder/device binding into the local request-scoped
account/device view. Device identity is not encoded as a sentinel scope.
coland no longer exposes a Principal-local credential issuance endpoint for
production grants.

Account subscribe and Events API cursors are structured `ak:cursor:` tokens
bound to the principal, device, service DID, filter hash, stream positions, and
expiry. `/_arkret/self/account/subscribe` resumes with `after`; `/_arkret/self/events`
paginates with `before` / `after`. Expired cursors fail with `cursor_expired`.

Development bearer sessions are stored server-side by service-bound SHA-256
token hash, not plaintext token. Logout records `revoked_at` and revoked
sessions are rejected on later requests. To-device messages remain deliverable
across duplicate syncs until the client presents a cursor with the acknowledged
to-device position. Blob downloads require a bearer session plus a `purpose`
query parameter; blobs are visible to the uploader or to members of the bound
Space.

The v1 primary write path is the signed Event Envelope API: `GET /_arkret/self/events/describe`
declares the active event registry, schema/reducer profiles, and limits, and
`POST /_arkret/self/events` accepts one canonical Event Envelope.

Federation transaction IDs are recorded per origin with canonical request
digests. Replaying the same `(origin, txn_id)` and body returns the stored
response; reusing the transaction ID with different content returns a
conflict. PostgreSQL mode persists these replay records. Blob uploads
normalize MIME types and filenames, enforce per-upload/account/Space quotas,
and reject plaintext blobs in private Spaces unless this service is listed in
`plaintext_visible_services`.

## API surface

coland exposes the canonical Arkret v1 routes from the operation registry; local
operator/product surfaces live under `/_coland/...`. Highlights:

- `GET  /health` — liveness + DB / persistence probe (used as the Docker healthcheck)
- `GET  /readyz` — readiness probe for DB, boot migrations, introspection bearer config, and external webvh boot probe state
- `GET  /.well-known/arkret/openapi.json` and `.../openapi.yaml` — the
  generated OpenAPI 3.1 document from coland's Salvo route wiring
- `GET  /.well-known/mimi-protocol-directory`
- `POST /_arkret/self/events`, `GET /_arkret/self/events/describe`, …
- `GET /_arkret/sync`, `GET /_arkret/root/identity/*`, `GET /_arkret/find/directory/*`
- `POST /_coland/gate/auth/dev-login` (development_mode only)

A complete list lives in the OpenAPI document above; `/_coland/admin/{resource}`
and `/_coland/gate/auth/dev-login` are gated behind `COLAND_DEVELOPMENT_MODE=true`.

## Development

Workspace layout (the CI checkout assumes the same):

```
arkret/
├── arkret-rust-sdk/       # https://github.com/arkret-org/arkret-rust-sdk
│   └── crates/
└── coland/                 # this repo
    ├── crates/
    ├── xtask/
    └── Cargo.toml
```

```bash
just fmt-check     # respects .rustfmt.toml
just check
just test
```

The OpenAPI tests in `crates/server/tests/http_api/openapi.rs`
(`served_openapi_is_generated_from_the_router`,
`artifact_only_path_is_not_treated_as_a_registered_route`) lock the served
operation-id surface to the live router; `crates/server/tests/http_api/` covers protocol behaviors.

## Status & roadmap

The current implementation has product-shaped auth/session, identity, events
log, device key, to-device, blob, directory, sync, and index surfaces.
PostgreSQL migrations and the persistence adapters are wired; in-memory mode is
the development fallback. Current changes and remaining production work are recorded
in [`CHANGELOG.md`](CHANGELOG.md) and repository issues.

## Production Deployment Checklist

Before exposing coland to the public internet, walk every item below.
The same list is computed at runtime and surfaced on
`/health.hardening` (and `/_arkret/describe.hardening`) so codmin's
`/hardening` dashboard can flag failing checks across the whole fleet.

- [ ] `COLAND_DEVELOPMENT_MODE=false` (default — only flip to true on a loopback dev bind)
- [ ] TLS enabled (`COLAND_TLS_CERT_PATH` / `COLAND_TLS_KEY_PATH`, or terminated at the reverse proxy)
- [ ] PQ-hybrid TLS deployment probe verified (`COLAND_PQ_TLS_DEPLOYMENT_PROBE=verified` after `X25519MLKEM768` is negotiated)
- [ ] CSP header configured at the reverse proxy
- [ ] CORS limited to the configured allowed origins (`COLAND_CORS_ALLOW_ORIGIN`)
- [ ] Secrets in a secret manager (`COLAND_NOTARY_SIGNING_KEY`, internal-authority shared secret)
- [ ] Log redaction enabled (default outside dev mode)
- [ ] Admin auth in production mode (`COLAND_ADMIN_PRINCIPAL_DIDS`, with browser sessions backed by `COLAND_SESSION_GRANT_INTROSPECTION_URL`)
- [ ] Rate limit enabled (default; do not disable in production)
- [ ] Service signing-key rotation remains disabled until the deployment can atomically commit the KeyStore key, WebVH history, DID document, durable identity, and recovery bundle; the current admin route fails closed with `unsupported_feature`
- [ ] `COLAND_SEED_DEMO_DATA=false` (default — never on a federated production deployment)

## License

Apache-2.0 — see [LICENSE](LICENSE).
