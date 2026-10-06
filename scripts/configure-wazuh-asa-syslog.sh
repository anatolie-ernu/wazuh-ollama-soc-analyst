#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Rulează ca root: sudo ASA_ALLOWED_IPS='192.0.2.20' bash scripts/configure-wazuh-asa-syslog.sh" >&2
  exit 1
fi
if [[ -z "${ASA_ALLOWED_IPS:-}" ]]; then
  echo "Setează ASA_ALLOWED_IPS la IP-ul sau CIDR-ul de management al ASA." >&2
  exit 1
fi
CONF="${WAZUH_OSSEC_CONF:-/var/ossec/etc/ossec.conf}"
LISTEN_IP="${WAZUH_LISTEN_IP:-}"
PORT="${WAZUH_SYSLOG_PORT:-514}"
PROTO="${WAZUH_SYSLOG_PROTOCOL:-udp}"
[[ -f "$CONF" ]] || { echo "Nu găsesc $CONF. Instalează Wazuh Server mai întâi." >&2; exit 1; }
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || { echo "Port invalid." >&2; exit 1; }
[[ "$PROTO" == udp || "$PROTO" == tcp ]] || { echo "Protocolul trebuie să fie udp sau tcp." >&2; exit 1; }

python3 - "$CONF" "$ASA_ALLOWED_IPS" "$LISTEN_IP" "$PORT" "$PROTO" <<'PY'
import ipaddress, os, pathlib, re, shutil, sys, tempfile

path = pathlib.Path(sys.argv[1])
allowed, local_ip, port, protocol = sys.argv[2:]
for item in allowed.split(","):
    ipaddress.ip_network(item.strip(), strict=False)
if local_ip:
    ipaddress.ip_address(local_ip)
if not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535:
    raise SystemExit("Port invalid")
text = path.read_text()
try:
    import xml.etree.ElementTree as ET
    ET.fromstring(text)
except ET.ParseError as exc:
    raise SystemExit(f"ossec.conf XML invalid, nicio modificare făcută: {exc}")
marker = "<!-- managed-by: sentinel-l1-asa-syslog -->"
if marker in text:
    raise SystemExit("Configurația Sentinel pentru syslog ASA există deja; editează manual după backup.")
for m in re.finditer(r"<remote>(.*?)</remote>", text, re.S):
    block = m.group(1)
    if re.search(r"<connection>\s*syslog\s*</connection>", block) and re.search(rf"<port>\s*{port}\s*</port>", block) and re.search(rf"<protocol>\s*{protocol}\s*</protocol>", block):
        raise SystemExit(f"Există deja remote syslog {protocol}/{port}; verifică allowed-ips înainte de a continua.")
block = ["  <remote>", "    <connection>syslog</connection>", f"    <port>{port}</port>", f"    <protocol>{protocol}</protocol>"]
block += [f"    <allowed-ips>{ip.strip()}</allowed-ips>" for ip in allowed.split(",")]
if local_ip:
    block.append(f"    <local_ip>{local_ip}</local_ip>")
block.append("  </remote>")
addition = "\n" + marker + "\n" + "\n".join(block) + "\n"
if not re.search(r"</ossec_config>\s*$", text):
    raise SystemExit("Nu găsesc tag-ul final ossec_config.")
backup = path.with_name(path.name + ".sentinel-backup")
if not backup.exists():
    shutil.copy2(path, backup)
updated = re.sub(r"</ossec_config>\s*$", addition + "</ossec_config>\n", text)
ET.fromstring(updated)
fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
try:
    with os.fdopen(fd, "w") as out:
        out.write(updated)
        out.flush()
        os.fsync(out.fileno())
    shutil.copystat(path, tmp)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
print(f"Adăugat receiver syslog ASA {protocol}/{port}; backup: {backup}")
PY

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  IFS=',' read -r -a sources <<< "$ASA_ALLOWED_IPS"
  for source in "${sources[@]}"; do
    ufw allow from "$source" to any port "$PORT" proto "$PROTO" comment 'Wazuh Cisco ASA syslog'
  done
fi
systemctl restart wazuh-manager
systemctl is-active --quiet wazuh-manager
echo "Receiver activat. Verifică ${CONF}, firewall-ul de rețea și /var/ossec/logs/archives/archives.json."
