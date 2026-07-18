# SecureOps AI

Connects to a real Azure subscription, scans four high-impact misconfiguration
categories (networking, secrets, storage, identity), maps every finding to
MITRE ATT&CK, and uses Claude to turn raw findings into a plain-English
executive summary, a prioritized fix list, and a business-impact statement —
rendered as an interactive dashboard and a downloadable PDF report.

## Architecture

```
backend/    FastAPI service — scanners, MITRE mapping, Claude analysis, PDF report, REST API
frontend/   React + Vite + Tailwind dashboard
```

| Module | What it checks |
|---|---|
| Network scanner | NSG inbound rules exposing management (22, 3389), database (1433, 3306, 5432, ...), or any port to the public internet |
| Key Vault scanner | Purge protection, soft delete, default network access |
| Storage scanner | Public blob access, HTTPS enforcement, minimum TLS version, network firewall default action |
| Conditional Access scanner | MFA enforcement, presence of any CA policy, legacy auth blocking, report-only policies (via Microsoft Graph) |

Every finding carries a severity, a CVSS score, and a MITRE ATT&CK
tactic/technique. A scanner failing (e.g. missing permission) never crashes
the run — it's reported as a coverage gap instead.

## What you need before running this

### 1. An Azure service principal (least privilege, no personal account)

```bash
az ad sp create-for-rbac --name "secureops-ai-scanner" \
  --role "Reader" \
  --scopes /subscriptions/<your-subscription-id>
```

This prints `appId` (client ID), `password` (client secret), and `tenant`.
Save all three — the secret is shown only once.

### 2. Role assignments

- **Security Reader** at subscription scope (in addition to the `Reader` role
  above), so the scanners can read NSG/Key Vault/Storage configuration:
  ```bash
  az role assignment create --assignee <appId> \
    --role "Security Reader" \
    --scope /subscriptions/<your-subscription-id>
  ```

### 3. Microsoft Graph permission (only if you want Conditional Access checks)

- Grant the app registration the **application permission** `Policy.Read.All`
  in Entra ID → App registrations → API permissions, then have a **tenant
  admin grant admin consent**. This is the one step that needs someone with
  tenant admin rights — flag it early, it's a common blocker.

### 4. An Anthropic API key

Get one from the Anthropic Console. This powers the AI executive
summary/remediation plan — without it the scan still runs and returns raw
findings, just without the AI analysis section.

### 5. Fill in environment variables

Copy `backend/.env.example` to `backend/.env` and fill in:

```
AZURE_TENANT_ID=<tenant>
AZURE_CLIENT_ID=<appId>
AZURE_CLIENT_SECRET=<password>
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
ANTHROPIC_API_KEY=<your-anthropic-key>
```

Never commit `.env` — it's already gitignored.

## Run it

### Option A — Docker Compose (one command)

```bash
docker compose up --build
```
Backend on `http://localhost:8000` (docs at `/docs`), frontend on `http://localhost:5173`.

### Option B — run locally

```bash
# Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then fill it in
uvicorn app.main:app --reload

# Frontend (separate terminal)
cd frontend
npm install
cp .env.example .env   # VITE_API_BASE_URL, defaults to http://localhost:8000
npm run dev
```

## Using it

1. Open the dashboard, enter your subscription ID, pick which scanners to
   run, and hit **Run Scan**.
2. Watch severity counts and the MITRE ATT&CK tactic coverage grid populate.
3. Read the AI-generated executive summary, top risks, and remediation plan.
4. Drill into individual findings (filterable by severity).
5. Click **Download PDF Report** for an audit-ready document.

## API

- `POST /api/scan` — run all (or selected) scanners + AI analysis, persist and return the result
- `GET /api/scan/{id}` — re-fetch a previous scan
- `GET /api/scan/{id}/report` — stream back the generated PDF
- `GET /api/scans` — list stored scan IDs
- `GET /docs` — interactive OpenAPI docs

## Proof-of-detection (for a demo)

Deliberately misconfigure a test resource — e.g. open an NSG rule to
`0.0.0.0/0` on port 22 — and re-run a scan. It should show up as a
`CRITICAL`/`HIGH` finding mapped to `T1190 – Exploit Public-Facing
Application`. Only do this against a non-production test subscription.

## Notes on scope

This is a working end-to-end scaffold: real Azure SDK calls, real Microsoft
Graph calls, real Claude integration, real PDF generation, and a functional
dashboard. It has not been run against a live Azure subscription in this
environment (no Azure credentials were available here) — the backend and
frontend have been verified to compile, import, and build successfully, and
the models/MITRE-mapping/PDF-generation path has been exercised end-to-end
with synthetic findings. Run it against your own test subscription to
validate live scanner behavior before using it for a real audit.
