# Project Status

- Updated: 2026-10-06
- Stage: Initial PoC scaffold prepared for review; not deployed.
- Target: Debian 13 x86_64 with Docker Compose, Wazuh alerts, local Ollama or optional OpenAI, Anthropic Claude, Google Gemini API.

## Implemented in the proposal

FastAPI ingest and cases API, MariaDB storage, provider-selectable Ollama/OpenAI/Anthropic/Google triage, heuristic risk score, MITRE ID display when present in Wazuh payload, single-page dashboard, Debian installer, MariaDB backup/restore helpers, documentation and CI workflow.

## Validation state

Static files are present in the proposed branch. Automated tests, container build, CI, Debian 13 install, live Ollama inference and Wazuh integration have not yet been run. Do not treat as production-ready.

## Known limitations

Dashboard GET endpoints are unauthenticated; reverse proxy SSO is required for remote access. MariaDB runs as a single Compose service; HA/replication and live restore still require separate validation. Wazuh manager config is intentionally not modified by installer. MariaDB dump and restore helpers are implemented but have not been runtime-tested. AI and risk score are advisory/heuristic.

## Next step

Run CI and review installer and runtime behavior on a disposable Debian 13 VM before connecting to any production Wazuh manager.
