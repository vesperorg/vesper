#!/usr/bin/env bash
# setup-seed.sh - turn a fresh Ubuntu server into an always-on Vesper seed node.
#
#   sudo bash setup-seed.sh <the Vesper repository URL>
#
# Installs Python, copies Vesper to /opt/vesper, runs the self-test (nothing starts if it
# fails), makes a wallet for the node's mining rewards (test coins), installs the node as a
# locked-down system service that starts at every boot, and opens only SSH and port 8880.
set -euo pipefail

REPO="${1:?usage: sudo bash setup-seed.sh <repository URL>}"
PORT=8880
APP=/opt/vesper
DATA=/var/lib/vesper

if [ "$(id -u)" -ne 0 ]; then echo "run it with sudo"; exit 1; fi

echo "== 1/6  packages"
apt-get update -q
apt-get install -y -q python3 python3-venv python3-pip git ufw curl

# A small server (1-2 GB) gets swap space, so a burst of memory slows the node instead of the
# kernel killing it.
if [ "$(awk '/MemTotal/ {print $2}' /proc/meminfo)" -lt 3000000 ] && ! swapon --show | grep -q .; then
  echo "== small server: adding 2 GB of swap space"
  fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo "== 2/6  the code, in $APP"
id vesper >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin vesper
if [ -d "$APP/.git" ]; then git -C "$APP" pull --ff-only; else git clone --depth 1 "$REPO" "$APP"; fi
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q -r "$APP/requirements.txt"

echo "== 3/6  self-test (the node is not started unless every check passes)"
cd "$APP"
"$APP/venv/bin/python" selftest.py

echo "== 4/6  data folder and the node's own wallet (for its mining rewards: test coins)"
mkdir -p "$DATA"
chown -R vesper:vesper "$DATA"
if [ ! -f "$DATA/wallets/default.json" ]; then
  sudo -u vesper "$APP/venv/bin/python" coin.py --data-dir "$DATA" wallet new --password ""
fi

echo "== 5/6  the service"
IP="$(curl -4 -s https://api.ipify.org || true)"
if [ -z "$IP" ]; then echo "could not find this server's public address; edit vesper-node.service by hand"; IP=SERVER_IP; fi
sed -e "s#__APP__#$APP#g" -e "s#__DATA__#$DATA#g" -e "s#__PORT__#$PORT#g" -e "s#__IP__#$IP#g" \
    "$APP/deploy/vesper-node.service" > /etc/systemd/system/vesper-node.service
systemctl daemon-reload
systemctl enable --now vesper-node

echo "== 6/6  firewall: SSH and $PORT only"
ufw allow OpenSSH
ufw allow "$PORT/tcp"
ufw --force enable

sleep 5
echo
echo "Seed node running.  Its address for everyone's config.json \"peers\" list:"
echo "    http://$IP:$PORT"
echo "Check it:   curl -s http://$IP:$PORT/api/info | head -c 300"
echo "Its log:    journalctl -u vesper-node -f"
