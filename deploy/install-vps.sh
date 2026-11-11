#!/usr/bin/env bash
set -euo pipefail

# One-step systemd deployment helper for Debian/Ubuntu/RHEL Linux hosts
INSTALL_DIR="${INSTALL_DIR:-/opt/beamsync}"
DATA_DIR="${DATA_DIR:-/var/lib/beamsync}"
ENV_FILE="${ENV_FILE:-/etc/beamsync/beamsync.env}"

mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$(dirname "$ENV_FILE")"
cp -R . "$INSTALL_DIR/"
cd "$INSTALL_DIR"
npm ci --no-audit --no-fund
npm run build

if [ ! -f "$ENV_FILE" ]; then
  cp .env.example "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "Created $ENV_FILE — fill in PUBLIC_URL and Cloudflare R2 credentials, then run: systemctl restart beamsync"
fi

cat >/etc/systemd/system/beamsync.service <<EOF
[Unit]
Description=BeamSync Coordinator, Relay & UDP STUN Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
Environment=DATA_DIR=$DATA_DIR
ExecStart=/usr/bin/env node $INSTALL_DIR/packages/server/dist/bin.js
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now beamsync.service
systemctl status beamsync.service --no-pager
