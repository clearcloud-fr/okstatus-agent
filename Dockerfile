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

# OKS-689 — runtime is distroless, not debian:bookworm-slim.
#
# The Debian base contributed all 56 of this image's CVE findings, including
# every one of its 4 criticals (perl-base x3, zlib1g) — and none of those has a
# fix: not in bookworm, and not in trixie either, which was scanned and carries
# the very same perl CVEs. They were also for packages the agent never touches;
# perl, ncurses, gzip and coreutils were only ever there because a Debian base
# ships them. gcr.io/distroless/cc-debian12 is 11 packages and scans clean.
#
# It is still bookworm underneath (glibc 2.36), so it stays in lockstep with the
# rust:1.97-bookworm builder above — see that stage's comment about the 0.23.2
# "GLIBC_2.38 not found" release. Keep both on the same Debian generation.
#
# What the binary actually needs, from `ldd`: libssl.so.3, libcrypto.so.3,
# libgcc_s.so.1, libm.so.6, libc.so.6. distroless/cc-debian12 provides all of
# them, plus /etc/ssl/certs/ca-certificates.crt for TLS verification,
# /etc/nsswitch.conf with the libnss_dns/libnss_files modules for DNS (an agent
# that cannot resolve hostnames is useless), and netbase's /etc/protocols, which
# surge-ping needs to look up the ICMP protocol number.
#
# The `libz.so.1` that used to be in that ldd list is gone on purpose: it came
# from mysql_async's `minimal` feature, which despite its name selects flate2's
# C zlib backend. Cargo.toml now asks for `minimal-rust` (miniz_oxide, pure
# Rust) instead. That is what makes distroless viable — it ships no zlib, and
# the alternative was copying libz.so.1 in by hand, which would have hidden the
# package from the scanner rather than removed it.
#
# Verified by running this exact binary in a distroless container under the
# runtime's own conditions (uid 1001, no /etc/passwd entry for it): banner and
# health server up, DNS resolved, TLS handshake to backend.okstatus.eu
# completed and returned a real HTTP 401 for the bogus secret, clean shutdown.
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/okstatus-agent /usr/local/bin/okstatus-agent
ARG APP_VERSION=""
ENV APP_VERSION=$APP_VERSION
# Numeric form: distroless has no useradd, and no passwd entry is needed — the
# previous `groupadd`/`useradd` existed only to give this uid a name.
USER 1001:1001
EXPOSE 8081
# Absolute path rather than a PATH lookup: distroless has no shell to fall back
# on. Github/sync.sh rewrites this path for the public repo's binary name.
CMD ["/usr/local/bin/okstatus-agent"]
