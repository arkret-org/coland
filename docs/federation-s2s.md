# Federation server-to-server (S2S) onboarding

This document covers what an operator needs to wire two coland (or
coland-compatible) deployments together. The wire contract is the
canonical Arkret v1 federation surface; this file restates the
operator-visible pieces — header semantics, trust-domain binding, and
peer onboarding.

## Required headers

Every outbound federation POST signs two trust-domain headers together with
the canonical RFC 9530 body digest. The receiver verifies each component
inside the signature transcript; any mismatch rejects the request.

| Header | Source | Verified into |
| --- | --- | --- |
| `Source-Trust-Domain` | The sender's `COLAND_TRUST_DOMAIN` | Signature transcript + `cross_domain_replay_rejected` guard on receive |
| `Destination-Trust-Domain` | The intended peer's published `trust_domain` (from the peer's `/_arkret/describe`) | Signature transcript — protects against on-path mis-routing |
| `Content-Digest` | RFC 9530 `sha-256` over the exact canonical JSON bytes | Signature transcript — pins the body the signature covered |

The receiver verifies `Content-Digest` against the exact HTTP content before
JSON parsing, rejects non-canonical JSON bytes, and computes any Arkret
`sha256:<hex>` request digest internally for replay, idempotency, and audit.

## Trust-domain immutability

A Realm's `trust_domain` is locked at creation (`ak.realm.create`) and
cannot change. Wire events whose `trust_domain` does not match the
locked value reject with `cross_domain_replay_rejected`. This means:

- An operator who renames `COLAND_TRUST_DOMAIN` mid-lifetime invalidates
  peer header pins and previously assembled federated device-signing evidence.
  A receiver accepts a remote signer only after replaying the complete accepted
  PCR device-control chain from its signed genesis receipt through a covering
  Seal, current device projection, and range-completeness evidence. Do not
  rename without a planned peer-pinning and key-rotation ceremony.
- Federation peers see the trust domain on `/_arkret/describe`
  and pin it into the `Destination-Trust-Domain` header on every
  outbound request. Cross-deployment renames need a coordinated
  cutover.

## Peer onboarding checklist

1. **Exchange describe documents.** Both operators fetch each other's
   `/_arkret/describe` and confirm:
   - `trust_domain` matches what each side will pin into
     `Destination-Trust-Domain`.
   - `protocol_version` is mutually supported.
   - The peer's signing key (advertised via the canonical DID method
     listed in `did_resolver_allow_methods`) resolves successfully.
2. **Add the peer to `COLAND_FEDERATION_PEERS`.** Mesh deployments
   list every peer; hub deployments list only the upstream. Restart
   each side (or hot-reload via `routing::admin::federation` once it
   lands).
3. **Smoke-test a low-impact event.** Send a `ak.directory.refresh`
   (or any other read-side event) and confirm it lands on the peer.
   Watch the peer's `coland_federation_outbox_depth` gauge return to
   zero and the per-peer trace span close cleanly.
4. **Configure backpressure budgets.** Confirm the peer's reverse
   proxy / API gateway is not stricter than your outbox dispatcher's
   send rate. If the peer rate-limits at 60 r/m and the dispatcher
   sends 200 r/m, every burst will land in the dead-letter ledger
   after `MAX_ATTEMPTS` retries. The dispatcher honours the peer's
   `Retry-After` (header, or `retry_after_ms` in the error envelope) as
   a floor, so a peer that paces us explicitly is respected.
5. **Wire alerts.** Subscribe to
   `coland_federation_outbox_dead_letter_total` on your side — any
   non-zero rate against a freshly-onboarded peer typically means the
   `Source-Trust-Domain` / `Destination-Trust-Domain` pair is
   misconfigured.

## Idempotency

Every outbound POST carries an `Idempotency-Key` header. The receiver first
verifies the current peer service signature and Realm origin binding. A
revoked signing key fails with `signature_invalid` before cache lookup; a
current key whose origin binding was removed fails with `capability_denied`.
Only a currently authorized, byte-identical retry under the same authorization
basis can return its cached outcome without a second reducer write.

## Operator references

- `crates/http/src/routing/federation/outbox.rs` — dispatcher loop, lease claim,
  transport-retry vs semantic-resubmission classification, dead-letter
  ledger entry.
- `crates/http/src/routing/federation/outbox_operator.rs` — list / inspect / requeue,
  driven by the `coland-federation-outbox` binary.
- `crates/http/src/routing/federation/federation/mod.rs` — receive-side header
  verification, idempotency cache, trust-domain guard.
- `docs/architecture.md` §2 — outbox enqueue / dispatch pipeline.
- DEPLOYMENT.md §10 — production hardening checklist (includes shared
  rate limit, TLS, secret management).
