#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="${SENTINEL_INSTALL_DIR:-/opt/sentinel-l1}"
BACKUP_DIR="${SENTINEL_BACKUP_DIR:-/var/backups/sentinel-l1}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$BACKUP_DIR"
cd "$APP_DIR"
set -a
. ./.env
set +a
umask 077
docker compose exec -T mariadb mariadb-dump --single-transaction --routines --triggers -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" > "$BACKUP_DIR/sentinel-$STAMP.sql"
test -s "$BACKUP_DIR/sentinel-$STAMP.sql"
chmod 0600 "$BACKUP_DIR/sentinel-$STAMP.sql"
find "$BACKUP_DIR" -type f -name 'sentinel-*.sql' -mtime +14 -delete
echo "MariaDB backup saved: $BACKUP_DIR/sentinel-$STAMP.sql"
