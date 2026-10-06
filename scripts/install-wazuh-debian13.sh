#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Rulează cu sudo: sudo bash scripts/install-wazuh-debian13.sh" >&2
  exit 1
fi
if [[ ! -r /etc/os-release ]] || ! . /etc/os-release || [[ "${ID:-}" != debian || "${VERSION_ID:-}" != 13 ]]; then
  echo "Scriptul este destinat Debian 13 (Trixie)." >&2
  exit 1
fi
if [[ "$(dpkg --print-architecture)" != amd64 ]]; then
  echo "Instalarea PoC este validată doar pe amd64." >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  apt-get update
  apt-get install -y ca-certificates curl
fi

VERSION="${WAZUH_VERSION:-4.14}"
WORK_DIR="$(mktemp -d /root/wazuh-install.XXXXXX)"
LOG_FILE="/var/log/wazuh-install-$(date +%Y%m%d-%H%M%S).log"
chmod 0700 "$WORK_DIR"
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR"
curl --fail --silent --show-error --location \
  "https://packages.wazuh.com/${VERSION}/wazuh-install.sh" -o wazuh-install.sh
chmod 0700 wazuh-install.sh
echo "Instalez Wazuh all-in-one ${VERSION}. Log: ${LOG_FILE}"
if ! bash ./wazuh-install.sh -a >"$LOG_FILE" 2>&1; then
  chmod 0600 "$LOG_FILE"
  tail -n 60 "$LOG_FILE" >&2
  exit 1
fi
chmod 0600 "$LOG_FILE"

[[ -f wazuh-install-files.tar ]] || { echo "Instalarea nu a creat arhiva cu credențiale așteptată." >&2; tail -n 60 "$LOG_FILE" >&2; exit 1; }
install -o root -g root -m 0600 wazuh-install-files.tar /root/wazuh-install-files.tar
systemctl is-active --quiet wazuh-manager
systemctl is-active --quiet wazuh-indexer
systemctl is-active --quiet wazuh-dashboard

echo "Wazuh all-in-one instalat. Deschide https://<IP-ul-serverului>/ ."
echo "Arhiva cu credențiale este protejată la /root/wazuh-install-files.tar."
echo "Log instalare protejat: ${LOG_FILE}"
echo "Debian 13: consultă nota de compatibilitate în docs/WAZUH-CISCO-ASA.md."
