# Project Status

- Updated: 2026-10-06
- Stage: PoC plus Wazuh/Cisco ASA integration scripts prepared for review; not deployed.
- Target: Debian 13 x86_64 with Docker Compose, Wazuh alerts, local Ollama or optional OpenAI, Anthropic Claude, Google Gemini API.

## Implemented in the proposal

FastAPI ingest and cases API, MariaDB storage, provider-selectable Ollama/OpenAI/Anthropic/Google triage, heuristic risk score, MITRE ID display when present in Wazuh payload, single-page dashboard, Debian 13 app installer, Wazuh all-in-one assistant wrapper, restricted ASA syslog receiver setup, Wazuh custom integration to Sentinel, MariaDB backup/restore helpers, documentation and CI workflow.

## Validation state

Shell syntax, Python compilation, and a temporary `ossec.conf` receiver configuration smoke test passed. The custom-integration network test is included in pytest but could not run here because pytest is absent and package network access is blocked. Full CI, container build, Debian 13 install, live Ollama inference, and Wazuh/ASA end-to-end integration have not yet been run. Do not treat as production-ready.

## Known limitations

Dashboard GET endpoints are unauthenticated; reverse proxy SSO is required for remote access. MariaDB runs as a single Compose service; HA/replication and live restore still require separate validation. Wazuh setup scripts modify manager config only when explicitly run and make a backup first. Debian 13 is outside the current Wazuh quickstart recommended OS list and needs VM validation. MariaDB dump and restore helpers are implemented but have not been runtime-tested. AI and risk score are advisory/heuristic.

## Next step

Run CI and review installer and runtime behavior on a disposable Debian 13 VM before connecting to any production ASA or Wazuh manager.
