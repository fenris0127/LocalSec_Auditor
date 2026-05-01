# LocalSec Auditor

LocalSec Auditor is a local-first security audit tool for scanning project folders, preserving scanner evidence, and producing scanner-grounded security reports with local LLM assistance.

## MVP Direction

- React web UI for scan creation and result review
- FastAPI backend for APIs and local orchestration
- SQLite storage for scans, tasks, findings, and reports
- Scanner wrappers for Semgrep, Gitleaks, and Trivy
- Ollama-based analysis using the `localsec-security` model
- Markdown report generation

## Current Implementation Status

This repository currently contains the Phase 1-2 basic FastAPI server.

Implemented now:

- `backend/` folder skeleton
- `frontend/` placeholder folder
- `data/scans`, `data/reports`, and `data/raw` folders
- Project README
- FastAPI app with `GET /health`

Not implemented yet:

- Scanner wrappers
- SQLite models or migrations
- Ollama client
- Report generation
- Frontend app

## Backend

Install dependencies:

```bash
cd backend
pip install -e .
```

Run the backend:

```bash
cd backend
uvicorn app.main:app --reload
```

Check the health endpoint:

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status":"ok"}
```

## Run Everything

After installing backend and frontend dependencies, start both dev servers from the
repository root:

```powershell
.\scripts\dev.ps1
```

If your terminal is already inside `frontend`, this also works:

```powershell
.\scripts\dev.ps1
```

Open the frontend:

```text
http://127.0.0.1:5173
```

## Planned Frontend Flow

Frontend, once the React app is implemented:

```bash
cd frontend
npm install
npm run dev
```

## Security Boundaries

- Scanner output is the evidence source.
- LLM output must not be treated as scanner evidence.
- Raw secrets must not be stored, printed, or sent to the LLM.
- MVP must not include automatic patching, production server modification, or fine-tuning code.
