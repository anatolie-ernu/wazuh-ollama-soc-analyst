# Roadmap

## PoC inițial

- ingestie alerte cu formă Wazuh și API key
- analiză structurată Ollama cu fallback determinist
- corelare temporală după regulă, agent, descriere, IP sursă și utilizator
- scor heuristic și ATT&CK IDs furnizate de Wazuh
- dashboard cu actualizare periodică
- instalare Docker Debian 13 și backup MariaDB

## Necesități înainte de producție

1. SSO/RBAC și audit per analist.
2. Migrații MariaDB și queue durabilă pentru scalare.
3. Retenție, export și restore automat validat.
4. Testare model pe alerte etichetate, măsurarea preciziei/recall/calibrării.
5. Validare a integrării Wazuh pe versiunea folosită.
6. Reguli configurabile de corelare și suprimare a zgomotului.
7. Orice răspuns activ să necesite aprobare explicită umană.
