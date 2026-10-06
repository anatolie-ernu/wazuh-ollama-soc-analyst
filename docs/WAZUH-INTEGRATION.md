# Integrarea Wazuh

API-ul acceptă un obiect JSON cu structură de alertă Wazuh la `POST /api/v1/alerts`, autentificat prin header `X-API-Key`. Exemplu complet de trimitere este în README.

## Model recomandat

Folosește un forwarder dedicat lângă managerul Wazuh. Forwarderul citește alerta JSON și o trimite prin HTTPS către Sentinel cu certificat verificat, retry limitat și timeout. Nu loga secretul. Restricționează traficul prin firewall la destinația Sentinel.

Wazuh are integrări active configurabile în `ossec.conf`; sintaxa și apelarea scripturilor trebuie verificate pentru versiunea instalată. Acest repo nu modifică automat configurația unui manager existent și nu instalează script cu privilegii pe manager.

Fragment orientativ, de adaptat după documentația versiunii tale:

```xml
<integration>
  <name>custom-sentinel</name>
  <hook_url>https://sentinel.soc.example/api/v1/alerts</hook_url>
  <api_key>REPLACE_WITH_SECRET</api_key>
  <alert_format>json</alert_format>
</integration>
```

Secretul din exemplu este placeholder. Păstrează secretul real separat, protejat de permisiuni restrictive. Înainte de producție testează payload, TLS, retry și volume pe un sistem pilot.

## Validare

- Cheie absentă/incorectă: `401`.
- JSON malformat: `400`.
- Obiect fără `rule`: `422`.
- Corp mai mare decât limita configurată: `413`.
- Alertă validă: `202` și `case_id`.

MITRE ATT&CK se afișează dacă alertarea Wazuh conține ID-urile în `rule.mitre.id`; aplicația nu deduce tehnica numai din descriere.
