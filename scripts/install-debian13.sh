#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="${SENTINEL_INSTALL_DIR:-/opt/sentinel-l1}"
REPO_URL="${SENTINEL_REPO_URL:-}"
MODEL="${OLLAMA_MODEL:-qwen2.5:3b}"
if [[ "$(id -u)" -ne 0 ]]; then echo "Run as root: sudo bash scripts/install-debian13.sh" >&2; exit 1; fi
if [[ ! -r /etc/os-release ]] || ! . /etc/os-release || [[ "${ID:-}" != debian || "${VERSION_ID:-}" != 13 ]]; then
  echo "This installer supports Debian 13 only." >&2; exit 1
fi
if ! command -v curl >/dev/null 2>&1; then apt-get update; apt-get install -y ca-certificates curl; fi
install -d -m 0750 "$APP_DIR"
if [[ -f docker-compose.yml && -f Dockerfile ]]; then
  source_dir="$(pwd -P)"
  target_dir="$(realpath -m "$APP_DIR")"
  if [[ "$source_dir" != "$target_dir" ]]; then cp -a . "$APP_DIR/"; fi
elif [[ -n "$REPO_URL" ]]; then
  if ! command -v git >/dev/null 2>&1; then apt-get update; apt-get install -y git; fi
  git clone --depth 1 "$REPO_URL" "$APP_DIR"
else
  echo "Run this script from the cloned project directory, or set SENTINEL_REPO_URL." >&2; exit 1
fi
install -m 0755 "$APP_DIR/scripts/install-debian13.sh" /usr/local/sbin/sentinel-install
install -m 0755 "$APP_DIR/scripts/backup.sh" /usr/local/sbin/sentinel-backup
install -m 0755 "$APP_DIR/scripts/restore-mariadb.sh" /usr/local/sbin/sentinel-restore
apt-get update
apt-get install -y ca-certificates curl gnupg openssl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
cd "$APP_DIR"
if [[ ! -f .env ]]; then
  cp .env.example .env
  key="$(openssl rand -hex 32)"
  dbpass="$(openssl rand -hex 32)"
  rootpass="$(openssl rand -hex 32)"
  sed -i "s/^INGEST_API_KEY=.*/INGEST_API_KEY=$key/" .env
  sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=$dbpass/" .env
  sed -i "s/^DB_ROOT_PASSWORD=.*/DB_ROOT_PASSWORD=$rootpass/" .env
  sed -i "s/^AI_MODEL=.*/AI_MODEL=$MODEL/" .env
  chmod 0600 .env
fi
docker compose up -d --build
echo "Waiting for MariaDB and API..."
for attempt in $(seq 1 60); do
  if docker compose exec -T mariadb healthcheck.sh --connect --innodb_initialized >/dev/null 2>&1 && curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then break; fi
  sleep 2
done
echo "Waiting for Ollama API..."
for attempt in $(seq 1 60); do
  if docker compose exec -T ollama ollama list >/dev/null 2>&1; then break; fi
  sleep 2
done
docker compose exec -T ollama ollama pull "$MODEL"
echo "Install complete. Dashboard: http://127.0.0.1:8080"
echo "API key: sudo grep '^INGEST_API_KEY=' '$APP_DIR/.env'"
echo "Review docs/INSTALLATION.md and configure TLS/reverse proxy before remote access."
