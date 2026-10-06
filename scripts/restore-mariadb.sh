#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="${SENTINEL_INSTALL_DIR:-/opt/sentinel-l1}"
BACKUP="${1:-}"
if [[ -z "$BACKUP" || ! -f "$BACKUP" ]]; then echo "Usage: sudo $0 /path/to/sentinel-YYYYMMDDTHHMMSSZ.sql" >&2; exit 2; fi
cd "$APP_DIR"
set -a
. ./.env
set +a
read -r -p "Restore $BACKUP to MariaDB database '$DB_NAME'? Type RESTORE to continue: " confirmation
[[ "$confirmation" == RESTORE ]] || { echo "Cancelled."; exit 1; }
docker compose exec -T mariadb mariadb -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < "$BACKUP"
echo "Restore completed. Verify cases in the dashboard."
