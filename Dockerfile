# OKS-169 — aws-sdk-bedrockruntime (added for the LLM check's Bedrock
# provider) requires rustc >=1.94.1; 1.88 no longer builds this crate .
#
# Pinned to -bookworm explicitly, not the bare `rust:1.97` tag: that tag
# floats to whatever Debian release is current on Docker Hub, and it moved
# to trixie (glibc 2.39+) while the runtime stage below is still
# debian:bookworm-slim (glibc 2.36). A binary built against the newer glibc
# refuses to start on the older one — "GLIBC_2.38/2.39 not found" — which is
# exactly what shipped in 0.23.2. Keep this pin in lockstep with the
# `debian:bookworm-slim` runtime base below if either ever changes.
FROM rust:1.97-bookworm AS builder
# OKS-355 — the image is tagged with the repo VERSION file (CI passes it as
# APP_VERSION) but the binary reported Cargo.toml's own `version` (stuck at
# 0.5.x) in its banner, tracing "Starting uptime-agent" line and heartbeat,
# so logs and the Private-agents tab showed a stale number. Stamp the Cargo
# package version from the build arg so CARGO_PKG_VERSION == image tag, and
# also export APP_VERSION at runtime (main.rs prefers it when set).
ARG APP_VERSION=""
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src/ ./src/
RUN if [ -n "$APP_VERSION" ]; then \
      sed -i "0,/^version = \".*\"/s//version = \"$APP_VERSION\"/" Cargo.toml; \
    fi && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r agent && useradd -r -g agent -u 1001 agent
COPY --from=builder /app/target/release/okstatus-agent /usr/local/bin/
ARG APP_VERSION=""
ENV APP_VERSION=$APP_VERSION
USER 1001
EXPOSE 8081
CMD ["okstatus-agent"]
