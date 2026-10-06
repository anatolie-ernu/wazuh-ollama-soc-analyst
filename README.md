# Wazuh + Ollama SOC AI Analyst

PoC SOC on-prem pentru trierea alertelor Wazuh cu model local Ollama. Oferă ingestie, corelare de alerte repetitive, clasificare L1/L2 asistată de AI, scor de risc, afișarea tehnicilor MITRE ATT&CK prezente în alertă și dashboard live.

> Analiza AI este consultativă. Platforma nu blochează endpointuri, nu izolează gazde și nu închide automat alerte. Analistul validează fiecare decizie. Providerul poate fi Ollama local, OpenAI, Anthropic Claude sau Google Gemini; modelele cloud trimit alerta către furnizorul ales.

## Arhitectură

`Cisco ASA → syslog → Wazuh → Sentinel API → MariaDB → provider AI ales → dashboard`

## Cerințe

- Debian 13 x86_64, acces sudo și internet pentru Docker/model
- Test minim: 4 vCPU, 8 GB RAM, 40 GB disk; 16 GB+ RAM recomandat
- GPU opțional; inferența CPU poate fi lentă

## Instalare de la zero

```bash
git clone https://github.com/anatolie-ernu/wazuh-ollama-soc-analyst.git
cd wazuh-ollama-soc-analyst
sudo bash scripts/install-debian13.sh
```

Installerul verifică Debian 13, instalează Docker Engine și Compose plugin, generează cheia API, pornește serviciile și descarcă `qwen2.5:3b`. Ghidul complet: [docs/INSTALLATION.md](docs/INSTALLATION.md).

Dashboard-ul ascultă implicit pe `127.0.0.1:8080`. Cheia ingestiei: `/opt/sentinel-l1/.env`. Configurează TLS și autentificare prin reverse proxy înainte de acces remote.

Pentru instalarea completă Wazuh all-in-one și integrarea Cisco ASA → Wazuh → Sentinel, vezi [docs/WAZUH-CISCO-ASA.md](docs/WAZUH-CISCO-ASA.md). Wazuh se instalează pe host Debian, iar Sentinel/MariaDB/Ollama rulează în Docker pe același host sau pe un host separat.

Notificările opționale Microsoft Teams se configurează printr-un Workflow webhook; ghidul este [docs/TEAMS-NOTIFICATIONS.md](docs/TEAMS-NOTIFICATIONS.md).

## Test ingestie

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/alerts \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: CHEIA_DIN_ENV' \
  -d '{"timestamp":"2026-10-06T18:00:00Z","rule":{"id":"5710","level":10,"description":"SSH authentication failed","groups":["authentication_failed","sshd"]},"agent":{"id":"003","name":"debian-test"},"data":{"srcip":"192.0.2.10","user":"admin"}}'
```

## Dezvoltare locală

```bash
cp .env.example .env
docker compose up -d --build
docker compose exec ollama ollama pull qwen2.5:3b
```

## Conținut

- `app/` API, persistență MariaDB, analiză AI multi-provider și dashboard
- `docker-compose.yml`, `Dockerfile` stack Docker
- `scripts/` instalare Sentinel/Wazuh, configurare ASA/syslog, integrare webhook, verificare și backup
- `docs/` instalare pas cu pas, integrare Wazuh, securitate, status și roadmap
- `.github/workflows/` CI

Această versiune este PoC, nu un înlocuitor pentru Wazuh/SIEM sau validarea umană.

MariaDB este baza implicită și rulează ca serviciu separat în Docker Compose. Datele persistă în volum numit; backup/restore sunt disponibile prin `sentinel-backup` și `sentinel-restore`.
