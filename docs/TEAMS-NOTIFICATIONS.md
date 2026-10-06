# Notificări Teams, ntfy și e-mail

Sentinel poate trimite notificări opționale când o alertă Wazuh deschide un caz nou și trece pragul de risc. Canalele Teams, ntfy și e-mail sunt independente și pot fi activate simultan. Mesajele conțin doar câmpurile selectate (regulă, agent, IP sursă, scor, severitate, rezumat AI și MITRE), niciodată JSON-ul complet al alertei.

Fără configurare, notificările rămân dezactivate. Alertele corelate în fereastra unui caz nu trimit mesaje repetate. Pragul comun se setează cu `NOTIFICATION_MIN_RISK_SCORE` (0–100, implicit 70).

## Configurare ntfy

În `.env`, setează:

```env
NTFY_SERVER_URL=https://ntfy.sh
NTFY_TOPIC=un-topic-lung-aleatoriu
NTFY_TOKEN=tk_tokenul_tau
```

`NTFY_TOKEN` este opțional pentru instalări ntfy publice; pentru un server privat, folosește tokenul emis de server. Aplicația permite doar URL-uri HTTPS. Abonează aplicația ntfy mobilă la același server și topic. Nu reutiliza topicuri ușor de ghicit: la `ntfy.sh`, topicul funcționează ca un secret de acces, iar mesajele sunt trimise către un serviciu găzduit în afara SOC-ului. Pentru alerte reale recomandăm un server ntfy privat, autentificat. Mesajele sunt sumarizate; nu includ loguri brute sau tokenuri.

## Configurare e-mail (SMTP)

```env
SMTP_HOST=smtp.example.net
SMTP_PORT=587
SMTP_USER=sentinel@example.net
SMTP_PASSWORD=parola-sau-app-password
SMTP_FROM=sentinel@example.net
SMTP_TO=soc@example.net,analist@example.net
```

Portul 587 folosește STARTTLS; portul 465 folosește TLS implicit. Pentru relay intern fără autentificare, lasă `SMTP_USER` și `SMTP_PASSWORD` goale. Dacă `SMTP_HOST` este setat, `SMTP_FROM` și cel puțin o adresă `SMTP_TO` sunt obligatorii; utilizatorul și parola se setează împreună. Aplicația verifică TLS cu certificatul serverului SMTP.

## Configurare Microsoft Teams

1. În canalul Teams, deschide meniul canalului → **Workflows**.
2. Creează un workflow cu trigger-ul webhook Teams și acțiunea care postează un Adaptive Card în canal.
3. Salvează workflow-ul și copiază URL-ul secret în `.env`:

```env
TEAMS_WEBHOOK_URL=https://URL-UL-SECRET-DIN-WORKFLOWS
```

Tratează URL-ul ca pe o parolă și adaugă un co-owner pentru continuitate.

## Aplică setările și verifică

Salvează secretele în `.env` (nu în Git), apoi:

```bash
sudo chmod 0600 /opt/sentinel-l1/.env
cd /opt/sentinel-l1
sudo docker compose up -d --force-recreate api
sudo docker compose logs --since=5m api
```

Trimite o alertă Wazuh care trece pragul configurat. Răspunsul API va conține, de exemplu, `"notification_queued":["ntfy","email"]`. Coadă MariaDB persistentă reîncearcă livrarea cu backoff exponențial și marchează `failed` după 12 eșecuri.

```sql
SELECT id, case_id, channel, status, attempts, last_error, created_at
FROM notification_outbox ORDER BY id DESC LIMIT 20;
```

După remedierea canalului, notificările eșuate pot fi reintroduse în coadă:

```sql
UPDATE notification_outbox
SET status='pending', attempts=0, next_attempt_at=UTC_TIMESTAMP(6), locked_at=NULL, last_error=NULL
WHERE status='failed';
```

## Limitări și siguranță

- Canalele se activează numai când au configurarea minimă; o configurare parțială/invalidă oprește pornirea API-ului pentru a evita o stare ambiguă.
- Pentru ntfy și SMTP permite egress HTTPS/TLS din containerul API către serverele configurate.
- Protejează `.env` și credentialele webhook/SMTP/ntfy; rotește-le dacă au fost expuse.
- Livrarea este at-least-once: dacă un serviciu acceptă mesajul, dar API-ul se oprește înainte să confirme în MariaDB, poate apărea un duplicat după retry.
- Mesajul e-mail și ntfy nu conțin logul original, dar rezumatul de analiză și IP-ul sursă pot totuși fi sensibile. Pentru ntfy.sh folosește un topic aleator și evaluează transferul de date în afara organizației.
