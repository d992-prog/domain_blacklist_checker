#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/domain-blacklist-checker"
PYTHON_VERSION="3.12"

sudo apt update
sudo apt install -y \
  git \
  curl \
  nginx \
  python3 \
  python3-venv \
  python3-pip

if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt install -y nodejs
fi

if [ ! -d "$APP_DIR" ]; then
  sudo mkdir -p "$APP_DIR"
  sudo chown -R "$USER":"$USER" "$APP_DIR"
fi

echo "Clone your repository into $APP_DIR, then run:"
echo "cd $APP_DIR/backend && python3 -m venv .venv && source .venv/bin/activate && pip install -e .[dev]"
echo "cd $APP_DIR/frontend && npm install && npm run build"
echo "Copy deploy/domain-blacklist-checker.service to /etc/systemd/system/"
echo "Copy deploy/nginx-domain-blacklist-checker.conf to /etc/nginx/sites-available/"
