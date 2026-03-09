#!/usr/bin/env bash
# dns-sentinel install script
# Idempotent — safe to run more than once.
#
# NOTE: If you want to run on port 53 (standard DNS) instead of 5353,
# you must first disable systemd-resolved:
#   sudo systemctl disable --now systemd-resolved
#   sudo rm /etc/resolv.conf
#   echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
# Only do this if you know what you are doing — it will break DNS until
# dns-sentinel is running.

set -euo pipefail

INSTALL_DIR="/opt/dns-sentinel"
SERVICE_USER="dns-sentinel"
SERVICE_FILE="dns-sentinel.service"
VENV_DIR="${INSTALL_DIR}/venv"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Root check ────────────────────────────────────────────────────────────────

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: This script must be run as root (sudo)." >&2
  exit 1
fi

echo "==> Installing DNS Sentinel from ${PROJECT_DIR}"

# ── System user ───────────────────────────────────────────────────────────────

if ! id "${SERVICE_USER}" &>/dev/null; then
  echo "==> Creating system user: ${SERVICE_USER}"
  useradd -r -s /bin/false "${SERVICE_USER}"
else
  echo "==> System user ${SERVICE_USER} already exists"
fi

# ── Install directory ─────────────────────────────────────────────────────────

echo "==> Copying files to ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
rsync -a --exclude='.git' --exclude='*.db' --exclude='__pycache__' \
  "${PROJECT_DIR}/" "${INSTALL_DIR}/"

chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"

# ── Python virtualenv ─────────────────────────────────────────────────────────

if [[ ! -d "${VENV_DIR}" ]]; then
  echo "==> Creating Python virtualenv at ${VENV_DIR}"
  python3 -m venv "${VENV_DIR}"
fi

echo "==> Installing Python dependencies"
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"

# ── Blocklists ────────────────────────────────────────────────────────────────

echo "==> Downloading blocklists (this may take a moment)"
cd "${INSTALL_DIR}"
sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" -c "
import sys
sys.path.insert(0, '.')
try:
    import tomllib
except ImportError:
    import tomli as tomllib
with open('config.toml', 'rb') as f:
    cfg = tomllib.load(f)
from dns_sentinel.blocklist import BlocklistLoader
bl = BlocklistLoader(cfg['blocklist'])
bl.refresh()
print('Blocklist refresh complete.')
" || echo "WARNING: Blocklist download failed — will retry on first run."

# ── systemd service ───────────────────────────────────────────────────────────

echo "==> Installing systemd service"
cp "${INSTALL_DIR}/${SERVICE_FILE}" /etc/systemd/system/
systemctl daemon-reload
systemctl enable dns-sentinel
systemctl restart dns-sentinel

echo ""
echo "==> DNS Sentinel installed and started."
echo ""
echo "    Check status : systemctl status dns-sentinel"
echo "    View logs    : journalctl -u dns-sentinel -f"
echo ""

SERVER_IP=$(hostname -I | awk '{print $1}')
echo "==> Point your devices at this DNS server: ${SERVER_IP} (port 5353)"
echo ""

# ── Firewall hints ────────────────────────────────────────────────────────────

if command -v ufw &>/dev/null; then
  echo "==> UFW detected. To allow DNS traffic on port 5353:"
  echo "    sudo ufw allow 5353/udp"
elif command -v iptables &>/dev/null; then
  echo "==> iptables detected. To allow DNS traffic on port 5353:"
  echo "    sudo iptables -A INPUT -p udp --dport 5353 -j ACCEPT"
fi

echo ""
echo "Done."
