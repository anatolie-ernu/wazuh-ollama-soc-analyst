# Alegerea providerului AI

Providerul se selectează în `.env` cu `AI_PROVIDER`: `ollama`, `openai`, `anthropic` sau `google`. Setează `AI_MODEL` la un model disponibil în contul/providerul ales.

| Provider | `AI_PROVIDER` | Cheie necesară | Procesare |
|---|---|---|---|
| Ollama | `ollama` | nu | local/on-prem |
| OpenAI (modele ChatGPT/API) | `openai` | `OPENAI_API_KEY` | cloud API |
| Anthropic Claude | `anthropic` | `ANTHROPIC_API_KEY` | cloud API |
| Google Gemini | `google` | `GOOGLE_API_KEY` | cloud API |

Acest proiect folosește API-urile pentru dezvoltatori, nu abonamentele de chat din interfața ChatGPT/Claude/Gemini. Accesul, modelele și facturarea depind de contul API/provider. Nu introduce chei în repo, issue-uri sau mesaje de log. Pune-le în `.env` pe host și limitează permisiunile la root.

După schimbarea providerului/modelului:

```bash
cd /opt/sentinel-l1
sudo chmod 0600 .env
sudo docker compose up -d --force-recreate api
```

Pentru provider cloud, datele alertei selectate sunt trimise furnizorului extern. Confirmă politica internă de date și cerințele de protecție înainte de activare. OLLAMA poate rămâne pornit în compose, dar API-ul îl folosește numai când `AI_PROVIDER=ollama`.
