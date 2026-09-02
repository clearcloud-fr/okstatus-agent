#!/bin/sh
# OKStatus private agent installer (OKS-401) — customer-facing.
# Hosted at https://raw.githubusercontent.com/Clearcloud-Fr/okstatus-agent/main/packaging/install.sh
# (and mirrored at https://get.okstatus.eu/agent/install.sh), invoked as:
#
#   curl -fsSL https://get.okstatus.eu/agent/install.sh | sudo bash -s -- \
#     --token oksa_live_xxxx --name dc-paris-01 --aggregator https://backend.okstatus.eu
#
# Downloads the uptime-agent binary, installs it as the systemd service
# "okstatus-agent" running in private mode: on first start the agent
# exchanges the single-use token for its own credentials (persisted in
# /var/lib/okstatus-agent) and starts pulling checks over outbound HTTPS.
set -eu

TOKEN=""
NAME="$(hostname -s 2>/dev/null || echo private-agent)"
AGGREGATOR="https://backend.okstatus.eu"
# OKS-602 — binaries are published as GitHub release assets
# (okstatus-agent-linux-amd64 / okstatus-agent-linux-arm64 + SHA256SUMS).
# --binary-url overrides for mirrors / pinned versions.
case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
BINARY_URL="https://github.com/Clearcloud-Fr/okstatus-agent/releases/latest/download/okstatus-agent-linux-${ARCH}"

while [ $# -gt 0 ]; do
    case "$1" in
        --token) TOKEN="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --aggregator) AGGREGATOR="$2"; shift 2 ;;
        --binary-url) BINARY_URL="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ -z "$TOKEN" ]; then
    echo "Missing --token — generate one from https://okstatus.eu/dashboard/private-agents" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (pipe into: sudo bash -s -- ...)" >&2
    exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends libssl3 ca-certificates curl >/dev/null
fi

if ! id okstatus-agent >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin okstatus-agent
fi

echo "Downloading agent binary..."
curl -fsSL "$BINARY_URL" -o /usr/local/bin/okstatus-agent.tmp
install -m 0755 -o root -g root /usr/local/bin/okstatus-agent.tmp /usr/local/bin/okstatus-agent
rm -f /usr/local/bin/okstatus-agent.tmp

# Credentials dir — the enrolled per-agent secret lives here after first start.
mkdir -p /var/lib/okstatus-agent
chown okstatus-agent:okstatus-agent /var/lib/okstatus-agent
chmod 0700 /var/lib/okstatus-agent

# Env file: the token is only needed until the first successful enrollment.
mkdir -p /etc/okstatus-agent
cat > /etc/okstatus-agent/okstatus-agent.env <<EOF
AGGREGATOR_URL=${AGGREGATOR}
OKSTATUS_TOKEN=${TOKEN}
OKSTATUS_AGENT_NAME=${NAME}
OKSTATUS_CREDENTIALS_FILE=/var/lib/okstatus-agent/credentials.json
EOF
chown okstatus-agent:okstatus-agent /etc/okstatus-agent/okstatus-agent.env
chmod 0600 /etc/okstatus-agent/okstatus-agent.env

cat > /etc/systemd/system/okstatus-agent.service <<'EOF'
[Unit]
Description=OKStatus private monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
User=okstatus-agent
Group=okstatus-agent
EnvironmentFile=/etc/okstatus-agent/okstatus-agent.env
ExecStart=/usr/local/bin/okstatus-agent
Restart=always
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/okstatus-agent
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable okstatus-agent
systemctl restart okstatus-agent

echo ""
echo "OKStatus private agent installed and started."
echo "It will appear on https://okstatus.eu/dashboard/private-agents within seconds."
echo "Logs: journalctl -u okstatus-agent -f"
