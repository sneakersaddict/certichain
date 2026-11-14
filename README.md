# CertiChain

Digital academic credentials platform (Cloud Computing project, Azure, Italy North).

## Structure
- `functions/`: Azure Functions backend (credential engine, trust registry, storage)
- `web/`: Flask web app (Issuer, Holder and Verifier portals)
- `docs/`: architecture and Azure configuration guide

## Getting started
1. Clone the repo and copy `.env.example` to `.env`
2. Sign in with `az login` (access is granted through your Azure account roles)
3. Never commit `.env`, `local.settings.json`, keys or passwords

## Workflow
One branch per feature (`feature/<name>`), pull request, review before merging into `main`.
