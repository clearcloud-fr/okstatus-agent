#!/bin/sh
# OKStatus private agent installer (OKS-401) — customer-facing.
# Hosted at https://raw.githubusercontent.com/Clearcloud-Fr/okstatus-agent/main/packaging/install.sh
# (synced by Github/sync.sh), invoked as:
#
#   curl -fsSL https://raw.githubusercontent.com/Clearcloud-Fr/okstatus-agent/main/packaging/install.sh \
#     | sudo bash -s -- --token oksa_live_xxxx --name dc-paris-01
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
# --version pins a release (v1.1.0); --binary-url + --sha256 install from a mirror.
case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
ASSET="okstatus-agent-linux-${ARCH}"
VERSION="latest"
BINARY_URL=""
SHA256=""

while [ $# -gt 0 ]; do
    case "$1" in
        --token) TOKEN="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --aggregator) AGGREGATOR="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --binary-url) BINARY_URL="$2"; shift 2 ;;
        --sha256) SHA256="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ -n "$BINARY_URL" ] && [ -z "$SHA256" ]; then
    echo "--binary-url needs --sha256 <checksum of that binary>" >&2
    exit 1
fi
if [ -z "$BINARY_URL" ]; then
    if [ "$VERSION" = "latest" ]; then
        RELEASE_URL="https://github.com/Clearcloud-Fr/okstatus-agent/releases/latest/download"
    else
        RELEASE_URL="https://github.com/Clearcloud-Fr/okstatus-agent/releases/download/${VERSION}"
    fi
    BINARY_URL="${RELEASE_URL}/${ASSET}"
fi

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
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL --proto '=https' "$BINARY_URL" -o "$TMP/$ASSET"
if [ -z "$SHA256" ]; then
    # Same release as the binary: "latest" could move between two downloads,
    # so a mismatch here means "run the installer again", never "install anyway".
    curl -fsSL --proto '=https' "${RELEASE_URL}/SHA256SUMS" -o "$TMP/SHA256SUMS"
    SHA256="$(awk -v f="$ASSET" '$2 == f || $2 == "*"f { print $1 }' "$TMP/SHA256SUMS")"
    if [ -z "$SHA256" ]; then
        echo "No checksum for $ASSET in SHA256SUMS" >&2
        exit 1
    fi
fi
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "$TMP/$ASSET" | awk '{ print $1 }')"
else
    ACTUAL="$(shasum -a 256 "$TMP/$ASSET" | awk '{ print $1 }')"
fi
if [ "$ACTUAL" != "$SHA256" ]; then
    echo "Checksum mismatch for $ASSET: expected $SHA256, got $ACTUAL. Nothing was installed." >&2
    exit 1
fi
echo "Checksum OK ($ACTUAL)"
install -m 0755 -o root -g root "$TMP/$ASSET" /usr/local/bin/okstatus-agent

# Credentials dir — the enrolled per-agent secret lives here after first start.
mkdir -p /var/lib/okstatus-agent
chown okstatus-agent:okstatus-agent /var/lib/okstatus-agent
chmod 0700 /var/lib/okstatus-agent

# Env file: the token is only needed until the first successful enrollment.
# systemd reads it as root before dropping to okstatus-agent, so the agent
# itself never needs to read it — and must not be able to rewrite it (the
# aggregator URL decides where checks come from).
mkdir -p /etc/okstatus-agent
chmod 0755 /etc/okstatus-agent
umask 077
cat > /etc/okstatus-agent/okstatus-agent.env <<EOF
AGGREGATOR_URL=${AGGREGATOR}
OKSTATUS_TOKEN=${TOKEN}
OKSTATUS_AGENT_NAME=${NAME}
OKSTATUS_CREDENTIALS_FILE=/var/lib/okstatus-agent/credentials.json
EOF
umask 022
chown root:root /etc/okstatus-agent/okstatus-agent.env
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
