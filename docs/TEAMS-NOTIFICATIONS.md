# Notificări Microsoft Teams

Sentinel poate trimite o notificare în Teams după ce primește o alertă Wazuh care deschide un caz nou și trece pragul de risc configurat. Notificarea conține un Adaptive Card cu regula, agentul, IP-ul sursă, scorul, severitatea, analiza succintă și ID-urile MITRE disponibile. Nu trimite alerta JSON completă.

Notificările sunt opționale. Fără webhook configurat, ingestia și dashboard-ul funcționează normal. Cazurile corelate în fereastra curentă nu generează notificări repetate.

## 1. Creează webhook-ul în Teams

1. Deschide canalul Teams unde vrei notificările și selectează meniul canalului → Workflows.
2. Creează workflow-ul cu trigger-ul When a Teams webhook request is received și acțiunea de postare Adaptive Card în canalul dorit.
3. Pentru apelul direct din Sentinel, configurează trigger-ul să accepte cereri externe prin URL-ul său unic; URL-ul devine secretul webhook-ului.
4. Salvează workflow-ul și copiază URL-ul. Tratează-l ca pe o parolă: cine îl deține poate declanșa workflow-ul. Adaugă un co-owner pentru continuitate dacă proprietarul inițial își pierde accesul.

Microsoft recomandă [Workflows pentru webhook-uri noi](https://learn.microsoft.com/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook); conectoarele Microsoft 365 vechi sunt în curs de retragere. Trigger-ul acceptă POST-uri HTTP și poate porni un flow care publică Adaptive Cards în Teams.

## 2. Configurează Sentinel

Pe server, editează /opt/sentinel-l1/.env:

    TEAMS_WEBHOOK_URL=https://URL-UL-SECRET-COPIAT-DIN-WORKFLOWS
    TEAMS_MIN_RISK_SCORE=70

Pragul acceptă valori între 0 și 100. Implicit, sunt notificate doar cazurile noi cu risc de cel puțin 70.

Protejează secretul și repornește API-ul:

    sudo chmod 0600 /opt/sentinel-l1/.env
    cd /opt/sentinel-l1
    sudo docker compose up -d --force-recreate api
    sudo docker compose logs --since=5m api

## 3. Testează

Trimite exemplul de ingestie din README cu un nivel și grupuri de regulă care produc un scor peste prag. Răspunsul API indică teams_notification_queued=true. Apoi verifică apariția cardului în canal.

Dacă webhook-ul nu este disponibil temporar, Sentinel păstrează notificarea într-un outbox MariaDB și reîncearcă cu întârziere exponențială. După 12 încercări eșuate, notificarea primește status failed.

    SELECT id, case_id, status, attempts, last_error, created_at
    FROM teams_outbox
    ORDER BY id DESC
    LIMIT 20;

Pentru a reîncerca manual notificările eșuate după remedierea webhook-ului:

    UPDATE teams_outbox
    SET status='pending', attempts=0, next_attempt_at=UTC_TIMESTAMP(6), locked_at=NULL, last_error=NULL
    WHERE status='failed';

## Date și limitări

- Sunt notificate cazurile noi care trec pragul; alertele corelate în același caz nu creează mesaje repetate.
- Dacă schimbi URL-ul webhook-ului, actualizează .env și recreează serviciul API.
- Rețeaua Docker trebuie să permită conexiuni HTTPS de ieșire către Microsoft Power Automate/Teams.
- Webhook-ul este o credențială. Nu îl pune în Git, loguri sau comenzi partajate.
- Notificarea este best-effort cu outbox și retry; dacă tenantul dezactivează workflow-ul ori schimbă permisiunile, mesajele vor rămâne în coadă și vor apărea în failed după limita de încercări.
