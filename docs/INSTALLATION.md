# Ghid de instalare pas cu pas — Debian 13

## 1. Pregătește serverul

PoC: 4 vCPU, 8 GB RAM, 40 GB disk. Recomandat pentru model local: 8+ vCPU și 16–32 GB RAM; GPU compatibil opțional. Modelul și baza ocupă spațiu, planifică disk-ul în consecință. Configurează IP static, DNS intern și NTP.

```bash
sudo apt update && sudo apt full-upgrade -y
cat /etc/os-release
```

Continuă doar dacă este Debian 13 (Trixie). Repornește dacă upgrade-ul a actualizat kernel-ul.

## 2. Clonează proiectul

```bash
sudo apt install -y git
cd /opt
sudo git clone https://github.com/anatolie-ernu/wazuh-ollama-soc-analyst.git sentinel-l1
cd /opt/sentinel-l1
```

## 3. Rulează instalarea automată

```bash
sudo bash scripts/install-debian13.sh
```

Scriptul:

1. verifică sistemul Debian 13 și privilegiile root;
2. instalează Docker Engine/Compose din depozitul oficial Docker;
3. generează secretul `INGEST_API_KEY` dacă nu există `.env`;
4. construiește și pornește API-ul și Ollama;
5. generează secrete pentru API și MariaDB;
6. pornește MariaDB, API-ul și Ollama;
7. descarcă modelul implicit `qwen2.5:3b`.

Prima instalare poate dura în funcție de internet și disk. Urmărește progresul:

```bash
cd /opt/sentinel-l1
sudo docker compose ps
sudo docker compose logs -f api mariadb ollama
```

## 4. Verifică serviciile

```bash
curl -fsS http://127.0.0.1:8080/healthz
sudo docker compose exec ollama ollama list
```

Deschide dashboard-ul local la `http://127.0.0.1:8080`. Publicarea pe host este loopback-only implicit.

## 5. Configurează acces remote în siguranță

Pune reverse proxy cu TLS valid și autentificare în fața dashboard-ului. Backend-ul API trebuie să rămână accesibil doar de pe loopback sau de la IP-ul proxy-ului, cu allowlist firewall. Nu expune portul 8080 și nici Ollama 11434 în Internet. Endpointurile GET/dashboard nu au autentificare nativă în PoC.

Cheia API se păstrează în `.env`, cu acces limitat:

```bash
sudo chmod 0600 /opt/sentinel-l1/.env
sudo grep '^INGEST_API_KEY=' /opt/sentinel-l1/.env
```

Pentru rotație, generează cheia nouă cu `openssl rand -hex 32`, actualizează `.env`, sincronizeaz-o la forwarderul Wazuh și repornește API-ul:

```bash
cd /opt/sentinel-l1
sudo docker compose up -d --force-recreate api
```

## 6. Testează ingestia

Înlocuiește `CHEIA_DIN_ENV` cu cheia din pasul anterior:

```bash
curl -i -X POST http://127.0.0.1:8080/api/v1/alerts \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: CHEIA_DIN_ENV' \
  -d '{"rule":{"id":"5710","level":10,"description":"SSH authentication failed","groups":["authentication_failed"]},"agent":{"id":"003","name":"debian-test"},"data":{"srcip":"192.0.2.10","user":"admin"}}'
```

Răspunsul normal este `202` cu `case_id`. Alerta apare în dashboard după ce analiza locală se încheie.

## 7. Alege providerul AI

Implicit se folosește Ollama local. Pentru OpenAI API, Claude API sau Google Gemini, editează `.env` conform [AI-PROVIDERS.md](AI-PROVIDERS.md), setează cheia providerului și `AI_MODEL`, apoi recreează API-ul. Modelele cloud transmit datele de alertă către furnizor; verifică politica organizației înainte de activare.

## 8. Instalează Wazuh și conectează Cisco ASA

Urmează ghidul [WAZUH-CISCO-ASA.md](WAZUH-CISCO-ASA.md) pentru Wazuh all-in-one, receiver UDP/514 restricționat la ASA, configurarea firewall-ului și forwardarea alertelor JSON către API. Ghidul include nota de compatibilitate Debian 13 și pașii de rollback.

## 9. Operare, update, backup și restaurare

```bash
cd /opt/sentinel-l1
sudo docker compose ps
sudo docker compose logs --since=10m api
sudo /usr/local/sbin/sentinel-backup
```

Actualizarea după revizuirea unei versiuni/tag:

```bash
sudo docker compose down              # volumele persistă
sudo git pull --ff-only
sudo docker compose up -d --build
```

Backup-ul MariaDB se salvează în `/var/backups/sentinel-l1`, cu permisiuni restrictive și rotație locală 14 zile. Copiază-l criptat în afara hostului. Pentru restaurare pe host de test: oprește stack-ul, păstrează o copie a volumului existent, execută `sudo /usr/local/sbin/sentinel-restore /var/backups/sentinel-l1/<backup.sql>` și confirmă cuvântul `RESTORE`. Scriptul importă dump-ul în DB selectată; testează restaurarea pe un mediu separat înainte de recuperarea operațională.

Nu folosi `docker compose down -v` decât dacă intenționezi să ștergi datele persistente.

## 10. Dezinstalare

```bash
cd /opt/sentinel-l1
sudo docker compose down
```

Ștergerea directorului și volumelor Docker elimină configurația și datele; arhivează întâi ce trebuie păstrat.
