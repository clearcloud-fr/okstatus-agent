# OKStatus agent

The monitoring agent behind [OKStatus](https://okstatus.eu). Run it inside
your own network as a **private agent** to monitor services that are not
reachable from the public internet — intranet APIs, databases behind a VPN,
on-prem hosts. Outbound HTTPS only, no inbound port, no VPN.

- Single static binary (Rust), ~20 MB, runs on 64 MB of RAM
- linux/amd64 and linux/arm64 — bare-metal, VM, Docker or Kubernetes
- Checks: HTTP/HTTPS (status, body, TLS expiry), TCP, DNS, ping, gRPC health, LLM canaries
- Pull model: the agent polls `backend.okstatus.eu` for tasks and pushes results back
- Prometheus metrics on `:9091/metrics`, health on `:9091/health`

## Install

Generate an enrollment token from **Dashboard → Private Agents → Add agent**
(Max/Enterprise plans), then pick one of:

### Linux (systemd)

```sh
curl -fsSL https://get.okstatus.eu/agent/install.sh | sudo bash -s -- \
  --token oksa_live_xxxx --name dc-paris-01
```

Installs `/usr/local/bin/okstatus-agent`, a hardened `okstatus-agent`
systemd unit and `/etc/okstatus-agent/okstatus-agent.env`. Logs:
`journalctl -u okstatus-agent -f`.

### Docker

```sh
docker run -d --name okstatus-agent --restart unless-stopped \
  -e OKSTATUS_AGENT_ID=<id> -e OKSTATUS_AGENT_SECRET=<secret> \
  -e OKSTATUS_AGENT_NAME=dc-paris-01 \
  ghcr.io/clearcloud-fr/okstatus-agent:latest
```

### Kubernetes (Helm)

```sh
helm repo add okstatus https://charts.okstatus.eu
helm install okstatus-agent okstatus/private-agent \
  --set credentials.agentId=<id> --set credentials.agentSecret=<secret> \
  --set name=k8s-private-agent
```

Chart source: [Clearcloud-Fr/okstatus-helm-charts](https://github.com/Clearcloud-Fr/okstatus-helm-charts).

### Binary

Download from [Releases](https://github.com/Clearcloud-Fr/okstatus-agent/releases/latest)
(`okstatus-agent-linux-amd64`, `okstatus-agent-linux-arm64`, `SHA256SUMS`).

## Configuration

| Variable | Default | Description |
|---|---|---|
| `AGGREGATOR_URL` | `https://backend.okstatus.eu` | OKStatus endpoint the agent pulls from |
| `OKSTATUS_AGENT_NAME` | hostname | Name shown on the dashboard |
| `OKSTATUS_AGENT_ID` / `OKSTATUS_AGENT_SECRET` | — | Stateless identity (recommended) |
| `OKSTATUS_TOKEN` | — | Single-use enrollment token (alternative to the pair above) |
| `OKSTATUS_CREDENTIALS_FILE` | — | Where token mode persists the exchanged credentials |
| `MAX_CONCURRENT_CHECKS` | `100` | Parallel checks |
| `POLL_INTERVAL_MS` | `2000` | Task polling interval |
| `CHECK_TIMEOUT_MS` | `5000` | Per-check timeout |
| `HEALTH_PORT` | `9091` | `/health` + `/metrics` port |
| `RUST_LOG` | `info` | Log level |
| `HTTPS_PROXY` | — | Egress proxy |

Identity: either the stateless pair (survives any restart, nothing written
to disk) or a token exchanged on first start. One identity = one running
instance; deploy more agents from the dashboard for HA.

## Security model

- The agent only ever opens outbound connections to `AGGREGATOR_URL`.
- It can only run checks for the organisation that enrolled it, and only
  targets you configured on the dashboard.
- Private IP ranges are allowed as targets **only** in private-agent mode
  (the public fleet refuses them).
- systemd unit runs unprivileged with `ProtectSystem=strict`,
  `NoNewPrivileges`, capability set empty.

## Build from source

```sh
cargo build --release          # needs Rust 1.94+, libssl-dev, pkg-config
docker build -t okstatus-agent .
```

Releases are cut by tagging: `git tag v1.2.3 && git push origin v1.2.3`
(see `.github/workflows/release.yml`).

## License

Apache-2.0 — see [LICENSE](LICENSE).
