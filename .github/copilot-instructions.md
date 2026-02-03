# Copilot instructions for this repository

This repository is small and currently contains a server-side Node/Express dependency list and an empty `client/` folder. Use these notes to get productive quickly.

- **Big picture:** Minimal feedback app scaffold. The repo root contains a short [README.md](README.md). Server dependencies are declared in [server/package.json](server/package.json). The `client/` directory exists but is empty in this checkout.

- **Primary components to inspect:**
  - [server/package.json](server/package.json) — lists `express`, `body-parser`, and `mysql` dependencies; look here first to understand runtime libs and DB usage.
  - `client/` — present but no files; if UI code exists elsewhere check branches or ask the maintainer.

- **Where to find the code:** No server source files are present at top-level `server/` in this checkout. Before changing runtime behavior, search for any JS/TS entrypoints (common places: `server/index.js`, `server/app.js`, `server/src/`) and confirm the app entrypoint.

- **Common developer workflow (what I did to reproduce):**

```bash
cd server
npm install      # installs dependencies from package.json
# If no start script exists, find the entrypoint and run with node, e.g.
# node index.js
ls -la            # confirm which source files are present
```

- **Database / integration notes:** `mysql` is a direct dependency — search the server code for configuration keys like `DB_HOST`, `database`, or `mysql.createConnection` to find where credentials/config are read. If not present, ask the maintainer for the DB schema or sample `.env`.

- **Project-specific conventions discovered:**
  - No tests or scripts detected in this snapshot. Follow the repository's existing directory layout if new files are added (place server code under `server/` and client code under `client/`).
  - Keep server dependency management inside `server/package.json` (do not add top-level package.json without coordinating).

- **What an AI agent should do first (checklist):**
  1. Run `cd server && ls -la` to locate any server entrypoint.
 2. Run `npm install` in `server/` to ensure dependencies are available.
 3. Search the repo for DB usage: `grep -R "mysql" -n server || true`.
 4. If source files are missing, open an issue or ask the maintainer for the expected entrypoint and any `.env`/DB credentials needed for local runs.

- **Examples of project-specific edits that are safe to propose:**
  - Add a `start` script to `server/package.json` if the entrypoint is known (example: `"start": "node index.js"`).
  - Add a small README under `client/` if you scaffold a frontend, explaining how it will be served (static files vs. separate dev server).

- **When to ask the user:**
  - If the server entrypoint or source files are not present in `server/` (ask which branch or path contains them).
  - If DB credentials or sample data are needed to implement or test features.

If anything here is unclear or you want me to expand the instructions with examples (start scripts, sample `.env`, or a suggested file layout), tell me which part to flesh out and I'll iterate.
