# Integrarea Wazuh

API-ul acceptă un obiect JSON cu structură de alertă Wazuh la `POST /api/v1/alerts`, autentificat prin header `X-API-Key`. Exemplu complet de trimitere este în README.

## Traseul complet

Cisco ASA trimite syslog către listener-ul managerului Wazuh; Wazuh aplică decoder-ele/regulile și apoi poate invoca integrarea custom `custom-sentinel` pentru alertele JSON. Ghidul complet este [WAZUH-CISCO-ASA.md](WAZUH-CISCO-ASA.md).

Instalatoarele fac backup la `ossec.conf`, validează XML-ul înainte de scriere, apoi repornesc `wazuh-manager`. Scriptul custom trimite webhook-ul cu timeout și permite HTTP numai către loopback. Cheia API este păstrată în configurația managerului cu acces privilegiat; protejează și arhivează aceste fișiere corespunzător.

Fragmentul creat de instalator pe același host:

```xml
<integration>
  <name>custom-sentinel</name>
  <hook_url>http://127.0.0.1:8080/api/v1/alerts</hook_url>
  <api_key>REPLACE_WITH_SECRET</api_key>
  <alert_format>json</alert_format>
</integration>
```

Schimbă endpointul dacă Sentinel rulează pe alt host (HTTPS cu certificat valid). Pragul implicit este nivel Wazuh 5; fără filtru `group`/`rule_id`, sunt trimise alertele tuturor surselor peste prag.

## Validare

- Cheie absentă/incorectă: `401`.
- JSON malformat: `400`.
- Obiect fără `rule`: `422`.
- Corp mai mare decât limita configurată: `413`.
- Alertă validă: `202` și `case_id`.

MITRE ATT&CK se afișează dacă alertarea Wazuh conține ID-urile în `rule.mitre.id`; aplicația nu deduce tehnica numai din descriere.
