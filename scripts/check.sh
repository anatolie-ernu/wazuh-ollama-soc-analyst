#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
docker compose config -q
docker compose ps
curl -fsS http://127.0.0.1:8080/healthz
echo
