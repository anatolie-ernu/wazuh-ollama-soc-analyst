# Operare și securitate

- AI este consultativ; nu există auto-remediere ori auto-închidere.
- Alertele pot conține informații sensibile. Menține traficul în rețeaua SOC și definește retenția înainte de a folosi date reale.
- Ingestia și `PATCH` cer API key. Dashboard-ul și `GET` nu au autentificare; protejează-le prin reverse proxy cu SSO/MFA înainte de acces remote sau multi-user.
- TLS trebuie terminat la un proxy de încredere. Nu expune `8080`, `3306` sau `11434` public. API-ul și Ollama au nevoie de egress pentru providerul AI și descărcarea modelului; restricționează egress-ul prin firewall la destinațiile necesare. Porturile DB și Ollama nu sunt publicate pe host.
- `.env` nu se comite și trebuie protejat la nivel de OS.
- URL-ul webhook Microsoft Teams este o credențială; protejează-l în `.env` și rotește-l dacă ajunge în loguri sau într-un repo.
- Conținutul alertei poate include prompt injection; modelul local poate greși. Verifică întotdeauna dovezile în Wazuh.
- MariaDB rulează separat în Compose, cu InnoDB, volum persistent și cont aplicație. Pentru HA/throughput ridicat: replicare MariaDB proiectată separat, migrări, queue persistentă și retenție.
- Aplicația păstrează notă și stare în MariaDB, dar nu are identitate operator, RBAC sau audit imuabil. Protejează dump-urile DB și `.env`.
- Fixează versiunile imaginilor, scanează imagini/dependințe și actualizează după testare.

Cloud providers (OpenAI, Anthropic, Google) receive alert content for analysis when selected. Confirm privacy/data-handling approval and provider API terms before enabling them. See [AI-PROVIDERS.md](AI-PROVIDERS.md).

Teams notifications include selected alert fields and the AI summary, not the raw alert JSON. See [TEAMS-NOTIFICATIONS.md](TEAMS-NOTIFICATIONS.md).

## API

| Metodă | Cale | Access | Scop |
|---|---|---|---|
| GET | `/healthz` | intern | health check |
| GET | `/api/v1/cases` | intern/proxy | listă cazuri |
| GET | `/api/v1/cases/{id}` | intern/proxy | detaliu |
| POST | `/api/v1/alerts` | API key | ingestie și triere |
| PATCH | `/api/v1/cases/{id}` | API key | stare/notă analist |
