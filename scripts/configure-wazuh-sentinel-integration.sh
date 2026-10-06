#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "$(id -u)" -ne 0 ]]; then echo "Rulează scriptul cu sudo." >&2; exit 1; fi
CONF="${WAZUH_OSSEC_CONF:-/var/ossec/etc/ossec.conf}"
SOURCE="${SENTINEL_SCRIPT_SOURCE:-$(cd "$(dirname "$0")" && pwd)/custom-sentinel}"
ENV_FILE="${SENTINEL_ENV_FILE:-/opt/sentinel-l1/.env}"
ENDPOINT="${SENTINEL_HOOK_URL:-http://127.0.0.1:8080/api/v1/alerts}"
LEVEL="${SENTINEL_ALERT_LEVEL:-5}"
[[ -f "$CONF" && -f "$SOURCE" && -f "$ENV_FILE" ]] || { echo "Lipsește ossec.conf, scriptul de integrare sau .env." >&2; exit 1; }
python3 - "$ENDPOINT" <<'PY'
import sys
from urllib.parse import urlparse
url = urlparse(sys.argv[1])
if url.scheme != "https" and not (url.scheme == "http" and url.hostname in ("127.0.0.1", "::1", "localhost")):
    raise SystemExit("SENTINEL_HOOK_URL trebuie să folosească HTTPS; HTTP este permis doar pe loopback.")
PY
[[ "$LEVEL" =~ ^[0-9]+$ ]] && (( LEVEL >= 0 && LEVEL <= 16 )) || { echo "Pragul level trebuie să fie între 0 și 16." >&2; exit 1; }
API_KEY="$(python3 - "$ENV_FILE" <<'PY'
import sys
for line in open(sys.argv[1], encoding="utf-8"):
    if line.startswith("INGEST_API_KEY="):
        print(line.partition("=")[2].strip().strip("'\""))
        break
PY
)"
[[ -n "$API_KEY" ]] || { echo "INGEST_API_KEY nu este setată în $ENV_FILE." >&2; exit 1; }

TARGET="/var/ossec/integrations/custom-sentinel"
install -o root -g wazuh -m 0750 "$SOURCE" "$TARGET"
SENTINEL_API_KEY="$API_KEY" python3 - "$CONF" "$ENDPOINT" "$LEVEL" <<'PY'
import os, pathlib, re, shutil, sys, tempfile, xml.etree.ElementTree as ET
path = pathlib.Path(sys.argv[1])
endpoint, level = sys.argv[2:]
key = os.environ.pop("SENTINEL_API_KEY")
text = path.read_text()
ET.fromstring(text)
if "<name>custom-sentinel</name>" in text:
    raise SystemExit("Blocul custom-sentinel există deja; verifică-l manual pentru a evita duplicatele.")
esc = lambda value: value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
addition = ("\n  <!-- managed-by: sentinel-l1-api-integration -->\n"
            "  <integration>\n    <name>custom-sentinel</name>\n"
            f"    <hook_url>{esc(endpoint)}</hook_url>\n"
            f"    <api_key>{esc(key)}</api_key>\n    <level>{level}</level>\n"
            "    <alert_format>json</alert_format>\n  </integration>\n")
updated = re.sub(r"</ossec_config>\s*$", addition + "</ossec_config>\n", text)
ET.fromstring(updated)
backup = path.with_name(path.name + ".sentinel-backup")
if not backup.exists(): shutil.copy2(path, backup)
fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
try:
    with os.fdopen(fd, "w") as out: out.write(updated)
    shutil.copystat(path, tmp)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY
unset API_KEY
systemctl restart wazuh-manager
systemctl is-active --quiet wazuh-manager
echo "Integrare instalată; prag alertă=${LEVEL}. Verifică /var/ossec/logs/integrations.log."
