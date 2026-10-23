# syntax=docker/dockerfile:1.7

FROM rust:bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends jq \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_TARGET_DIR=/workspace/cargo-target

WORKDIR /workspace/arkret-org

COPY --from=arkret-rust-sdk . ./arkret-rust-sdk
COPY --from=arkret-spec . ./arkret-spec
COPY --from=floria . ./floria
COPY --from=garth . ./garth
COPY --from=bridges . ./bridges
COPY --from=savfox . /workspace/savfox-ai/savfox
COPY . ./coland

WORKDIR /workspace/arkret-org/coland

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/cargo-target \
    cargo build --locked --release --bin coland && \
    cargo build --locked --release -p coland-keystore-keygen && \
    target_dir="$(cargo metadata --locked --no-deps --format-version 1 | jq -er '.target_directory')" && \
    cp "$target_dir/release/coland" /usr/local/bin/coland && \
    cp "$target_dir/release/coland-keystore-keygen" /usr/local/bin/coland-keystore-keygen

FROM debian:bookworm-slim AS runtime

# `tini` provides a minimal PID-1 init so coland's tokio runtime sees
# SIGTERM/SIGINT cleanly and child reaping works (the bare Rust binary
# would otherwise need to handle signal forwarding for any subprocess
# tooling). `ca-certificates` keeps outbound `https://` (e.g. did:web
# resolution) working. We dropped the `curl` runtime dependency in P5
# (5.5) — the HEALTHCHECK now invokes the bundled `coland healthcheck`
# subcommand, which keeps the image distroless-compatible.
RUN apt-get update \
    && apt-get upgrade --yes \
    && apt-get install -y --no-install-recommends tini ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/coland /usr/local/bin/coland
COPY --from=builder /usr/local/bin/coland-keystore-keygen /usr/local/bin/coland-keystore-keygen

RUN install -d -o 10001 -g 10001 /var/lib/coland

USER 10001:10001
WORKDIR /var/lib/coland

ENV COLAND_BIND=0.0.0.0:8698
ENV COLAND_METRICS_BIND=0.0.0.0:9698
ENV COLAND_OBJECT_STORAGE_BACKEND=local
ENV COLAND_OBJECT_STORAGE_LOCAL_ROOT=/var/lib/coland/objects
EXPOSE 8698 9698

# P5 (5.5) — liveness probe via the bundled `coland healthcheck`
# subcommand. The probe reads `COLAND_BIND` (or `COLAND_HEALTHCHECK_URL`)
# and HTTPs `/health`. Eliminates the runtime `curl` dependency that
# previously blocked migrating this image to a distroless base.
# `--start-period` covers the diesel migration window on first boot.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/coland", "healthcheck"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/coland"]
