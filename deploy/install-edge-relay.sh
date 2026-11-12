#!/usr/bin/env bash
set -euo pipefail

# One-step systemd installer for a stateless BeamSync Edge Relay + UDP STUN node
# Ideal for Shanghai / domestic cloud VMs using raw IP + self-signed TLS (zero domain, zero ICP filing)
INSTALL_DIR="${INSTALL_DIR:-/opt/beamsync-edge-relay}"
TLS_DIR="${TLS_DIR:-/var/lib/beamsync-edge-relay}"
ENV_FILE="${ENV_FILE:-/etc/beamsync/edge-relay.env}"

mkdir -p "$INSTALL_DIR" "$TLS_DIR" "$(dirname "$ENV_FILE")"
cp -R . "$INSTALL_DIR/"
cd "$INSTALL_DIR"
npm ci --no-audit --no-fund
npm --workspace @beamsync/protocol run build
npm --workspace @beamsync/edge-relay run build

if [ ! -f "$ENV_FILE" ]; then
  cat >"$ENV_FILE" <<'EOF'
REGION=sha
PUBLIC_IP=101.132.x.x
PORT=8443
STUN_PORT=3478
TLS_MODE=self-signed
COORDINATOR_URL=https://sync.yourdomain.com
RELAY_AUTH_SECRET=change_me_to_match_coordinator_secret
EOF
  chmod 600 "$ENV_FILE"
  echo "Created $ENV_FILE — set PUBLIC_IP, COORDINATOR_URL, and RELAY_AUTH_SECRET, then run: systemctl restart beamsync-edge-relay"
fi

cat >/etc/systemd/system/beamsync-edge-relay.service <<EOF
[Unit]
Description=BeamSync Stateless Edge Relay & UDP STUN Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
Environment=TLS_CACHE_FILE=$TLS_DIR/edge-relay-tls.json
ExecStart=/usr/bin/env node $INSTALL_DIR/packages/edge-relay/dist/bin.js
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now beamsync-edge-relay.service
systemctl status beamsync-edge-relay.service --no-pager
