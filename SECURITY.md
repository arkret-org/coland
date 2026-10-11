# Security policy

coland is a reference Arkret v1 server. Several scaffold endpoints (push
outbound bridge, MIMI provider directory, parts of directory discovery, ...)
return placeholder shapes today; production deployments must keep `_todos.md`
in mind when assessing security posture.

## Supported versions

coland is pre-1.0. The local readiness branch is supported for this workspace;
remote release tags are not part of this development campaign.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security reports.

- Preferred: open a private vulnerability report via GitHub Security Advisories
  (`Security` tab → `Report a vulnerability`).
- Alternate: email **security@arkret.dev** with the details. PGP fingerprint
  and a backup contact will be added here once available.

Please include:

1. coland version (git SHA or release tag).
2. Affected endpoint(s) or component(s).
3. Reproduction steps and (where possible) a minimal proof of concept.
4. Impact assessment — what an attacker can read, modify, or escalate.
5. Suggested remediation if you have one.

We aim to:

- Acknowledge a report within **3 business days**.
- Provide an initial triage and severity assessment within **7 days**.
- Ship a fix or mitigation, and publish an advisory, within **90 days** of the
  initial report. We will coordinate disclosure with the reporter.

## In scope

- All HTTP routes mounted by `coland::router`.
- Authentication, session, token-handling, and DID validation paths.
- The reducer + projection pipeline (event ingestion, state computation,
  redaction handling).
- Federation transaction ingestion and signature verification.
- Persistence layer (Diesel + PostgreSQL at runtime; in-memory test adapter).
- Locally built Docker images, SBOM/provenance artifacts, and local binaries.

## Out of scope

- Vulnerabilities in upstream dependencies that have not yet been advised by
  RustSec. Run `cargo deny check advisories` to see what we already track.
- Any path explicitly behind `COLAND_DEVELOPMENT_MODE=true` (`dev_login`, the
  admin snapshot endpoints, relaxed DID validation). These are dev-only and
  must be disabled in production.
- Denial-of-service issues that require flooding from the same authenticated
  principal (rate-limit hardening is tracked as `_todos.md` Q6 / Cfg-1).
  The built-in limiter is intentionally per-process for 1.0 local readiness:
  every coland replica keeps its own IP bucket in memory, so horizontal
  deployments must enforce a shared quota at the reverse proxy, API gateway, or
  load-balancer layer.

## Known weaknesses

- Many endpoints still scaffold-respond and persist state in process memory.
  See `_todos.md` Stream-D, Stream-F-2/F-8, F2 for the concrete TODOs.
- The directory surface is backed by demo data, exposing pseudo-real handles
  during development (`_todos.md` Stream-E).
- The built-in rate limiter is per-instance. Multi-replica production
  deployments **MUST** enforce shared quotas at the reverse proxy or API
  gateway layer; the built-in limiter is per-process only. Without an
  external shared limiter an attacker can multiply the advertised
  per-minute quota by the replica count. See `docs/architecture.md` §4
  ("Multi-replica deployment notes") and `DEPLOYMENT.md` §10 — both
  surfaces restate the MUST so the deployment audit trail is
  cross-linked.

If you find an issue overlapping a `_todos.md` item, the report is still
welcome — exploitable severity often differs from the planned scope.
