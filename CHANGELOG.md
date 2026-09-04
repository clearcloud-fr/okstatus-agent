# Changelog

All notable changes to the OKStatus agent are documented here. Versions
follow the GitHub release tags (`vX.Y.Z`).

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
