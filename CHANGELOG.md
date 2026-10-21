# Changelog

All notable changes to the OKStatus agent are documented here. Versions
follow the GitHub release tags (`vX.Y.Z`).

## v1.1.0 — 2026-10-20

- Sealed task secrets: monitor credentials (headers, body, Basic auth,
  authentication settings, LLM API key) now reach the agent encrypted for
  it alone (X25519 + ChaCha20-Poly1305). The key is derived from
  `OKSTATUS_AGENT_SECRET`, so there is nothing new to configure; the agent
  publishes the public half with its heartbeat. A task it cannot open is
  skipped and counted in `uptime_agent_sealed_tasks_unreadable_total`,
  never run without its credentials.
- Monitor authentication (API key, bearer token…) for HTTP checks.
- SMTP, IMAP and Redis checks.
- The heartbeat reports where the agent runs (hostname, private IP,
  platform), shown on the Private Agents page.
- Private-agent mode still refuses the cloud metadata endpoints
  (`169.254.169.254` and equivalents); `OKSTATUS_ALLOW_CLOUD_METADATA=true`
  lifts it.
- Image: `/var/lib/okstatus-agent` now exists and belongs to uid 1001, so a
  Docker named volume mounted there is writable in token mode.
- `install.sh` verifies the binary against `SHA256SUMS`, accepts
  `--version`, and keeps its env file readable by root only.

## v1.0.0 — 2026-09-04

First public release.

- Private-agent mode: stateless credentials (`OKSTATUS_AGENT_ID` /
  `OKSTATUS_AGENT_SECRET`, nothing written to disk) or a single-use
  enrollment token exchanged on first start.
- Checks: HTTP/HTTPS (status code, body keyword, JSON path, TLS expiry),
  TCP, DNS, ICMP ping, gRPC health, LLM canaries.
- HTTP content check accepts `$` as the JSON path to compare the raw
  (trimmed) body as a string, for plain-text endpoints (`OK`, `pong`…);
  a leading `$.` on a real path is accepted and ignored.
- Prometheus metrics and health endpoint on `:9091`.
- linux/amd64 and linux/arm64 binaries, systemd packaging, and the
  multi-arch `ghcr.io/clearcloud-fr/okstatus-agent` image.
