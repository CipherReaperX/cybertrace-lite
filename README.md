<div align="center">

# 🛡️ CyberTrace-Lite

**Lightweight User Behaviour Analytics & Anomaly Detection for Insider-Threat Identification**

*A self-contained, open-source alternative to a full SIEM/UEBA stack — turns raw authentication and*
*application logs into explainable, risk-scored security alerts. No license fees, no cluster, no external dependency.*

[![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-IsolationForest%20%2B%20LOF-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![SHAP](https://img.shields.io/badge/Explainability-SHAP-8A2BE2)](https://github.com/shap/shap)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## Why CyberTrace-Lite

Insider misuse and compromised credentials rarely look malicious one event at a time — a login, a
file download, a resource read. They only become suspicious in aggregate, and reviewing that
aggregate at scale is exactly what commercial SIEM/UEBA platforms are priced out of reach for:
small teams, academic labs, and anyone who needs real detection logic without an ingestion-volume
licence bill.

| | Commercial SIEM/UEBA | ELK / Wazuh (open-source) | **CyberTrace-Lite** |
|---|---|---|---|
| Cost | Licensed, volume-priced | Free, ops-heavy | Free, single binary |
| Risk scoring out of the box | ✅ | ❌ (build it yourself) | ✅ |
| Explainable ML (per-alert reasoning) | Varies | ❌ | ✅ SHAP |
| Setup | Vendor-managed | Cluster + pipelines | `pip install` + run |
| Access control & audit trail | ✅ | Manual | ✅ built in |

CyberTrace-Lite answers one question well: **given yesterday's logs, which accounts should an
analyst look at first, and why.**

## How it works

```
LOG FILES (synthetic or uploaded)
        │
        ▼
 1. Log Collection  ──▶  2. Preprocessing  ──▶  3. Feature Extraction
                                                        │
                                                        ▼
                                          4. Behavioural Baselining (per-user)
                                                        │
                            ┌───────────────────────────┴───────────────────────────┐
                            ▼                                                       ▼
              5. Anomaly Ensemble                                       6. Rule-Based Risk Scoring
        (Isolation Forest + Local Outlier                                (8 weighted indicators,
         Factor, SHAP-explained)                                          0–100 rule score)
                            └───────────────────────────┬───────────────────────────┘
                                                        ▼
                              final_score = 0.7 × rule_score + 0.3 × anomaly_score
                                                        │
                                                        ▼
                                     SQLite  ──▶  Analyst Dashboard  ──▶  7. Email / Webhook Alert
                                                                            (de-duplicated per incident)
```

## Modules

| # | Module | File |
|---|--------|------|
| 1 | Log Generation / Collection | `modules/log_generator.py` |
| 1b | Real Log Ingestion (upload) | `modules/log_ingestion.py` |
| 2 | Log Preprocessing | `modules/preprocessing.py` |
| 3 | Feature Extraction | `modules/feature_extraction.py` |
| 4 | Behavioral Analysis | `modules/behavior_analysis.py` |
| 5 | Anomaly Detection (Isolation Forest + Local Outlier Factor) | `modules/anomaly_detection.py` |
| 6 | Risk Scoring (rule-based, 0–100) | `modules/risk_scoring.py` |
| 7 | Security Dashboard | `app.py`, `templates/dashboard.html` |
| — | Alerting & Notifications | `modules/notifications.py` |

The full pipeline is orchestrated by `run_pipeline.py` and persisted to a local SQLite database at
`database/cybertrace.db`.

## Detection approach

**Layer 1 — Rule-based detection.** Each triggered indicator adds weighted points to a 0–100 risk
score:

| Indicator | Weight |
|---|---|
| Multiple failed logins | +20 |
| Login from a new / unfamiliar IP | +20 |
| Abnormally high resource access | +20 |
| Unusual login time | +15 |
| High volume file downloads | +15 |
| Sensitive resource accessed off-hours (Admin Console, Payroll, Finance DB, Backup Server) | +15 |
| Concurrent session from multiple IPs (*"impossible travel"* proxy) | +15 |
| Rapid burst of activity | +10 |

Score is clipped to 100 even when several indicators fire at once.

**Layer 2 — Anomaly detection (ensemble).** **Isolation Forest** (global, partition-based) and
**Local Outlier Factor** (local density-based) each independently score every user-day of activity
against the overall population; their normalized scores are averaged into `anomaly_score`, and a
row is flagged `is_anomaly` if *either* model considers it an outlier. Two models built on
different assumptions give a more robust "second opinion" than relying on one unsupervised model
alone.

**Explainability.** Each row's anomaly score is explained via **SHAP**
(`shap.TreeExplainer` over the fitted Isolation Forest) — the top 3 contributing features and their
signed impact are stored per user-day and shown in the dashboard's user detail modal ("Top
contributing factors"), with a z-score-based fallback if SHAP itself is unavailable.

Final score = `0.7 × rule_score + 0.3 × anomaly_score`, classified as:

| Score | Classification |
|-------|---------------|
| 0–30 | 🟢 NORMAL |
| 31–60 | 🟡 SUSPICIOUS |
| 61–100 | 🔴 HIGH RISK |

## Model evaluation

`modules/evaluation.py` scores the pipeline's predictions against the ground truth baked into the
synthetic generator (`modules/log_generator.ANOMALOUS_USERS` — the users deliberately given
anomalous behaviour): a user-day counts as an actual positive if it belongs to one of those users,
predicted-positive if its classification isn't `NORMAL`. Precision/recall/F1 and a confusion matrix
are surfaced via `GET /api/model_eval` and the dashboard's **Model Insights** card.

Because those users still behave normally on most days, this ground truth is intentionally
conservative — it counts correctly-scored normal days as false negatives, so treat recall as a
lower bound and precision as the more trustworthy number. Metrics degrade to zero (not an error)
when none of the seeded usernames are present, e.g. after uploading real logs with no known ground
truth.

## Tech stack

Python (Pandas, NumPy, Scikit-learn, SHAP, Flask) + SQLite + HTML/CSS/Bootstrap + Chart.js +
Three.js (3D risk view). Alerting and CSV/PDF export use only the Python standard library
(`smtplib`, `urllib.request`, `csv`) — no extra dependencies.

## Quick start

```bash
git clone https://github.com/CipherReaperX/cybertrace-lite.git
cd cybertrace-lite
python -m venv venv
venv\Scripts\activate          # Windows — use `source venv/bin/activate` on Linux/macOS
pip install -r requirements.txt

# Generate synthetic logs, run the full 7-stage detection pipeline, and populate SQLite
python run_pipeline.py

# Start the dashboard (production WSGI server — Waitress)
python app.py
```

Open **http://127.0.0.1:5000**, sign in with the default admin account below, and change the
password immediately.

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | admin |

```bash
python manage_users.py reset-password admin <new_password>
```

`app.py` serves via [Waitress](https://github.com/Pylons/waitress) (not Flask's dev server /
`debug=True`), so it's safe to leave running continuously. Startup/crash logging goes to
`logs/server.log`. It binds to `127.0.0.1` by default; set `CT_HOST=0.0.0.0` to bind on all
interfaces (needed in a container) and `PORT` to change the port.

### Run with Docker

```bash
docker compose up --build
```

Then open **http://127.0.0.1:5000**. The SQLite database and session secret key (`database/`) and
generated logs (`logs/`) persist in named Docker volumes across container rebuilds/restarts.

This project intentionally stays on SQLite rather than Postgres — it's a single-instance "lite"
tool, and a SQLite-in-a-volume container is enough for a live demo. A future enhancement worth
doing before running this at real multi-instance scale would be migrating `database.py`/`app.py`'s
raw SQL to a Postgres-compatible dialect behind a `DATABASE_URL` env var.

### Deploy to a live URL (Fly.io)

A `fly.toml` is included:

```bash
flyctl auth login
flyctl launch --no-deploy         # creates the app; adjust `app` in fly.toml to match
flyctl volumes create ct_database --size 1 --region <your-region>
flyctl deploy
```

Fly gives you a public `https://<app-name>.fly.dev` URL backed by the same Docker image, with
`/app/database` persisted on the volume. (Railway/Render work too — just point their "deploy from
Dockerfile" option at this repo.)

### Auto-start at Windows login

A shortcut script can be installed at
`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\CyberTrace-Lite.vbs`, silently running
`venv\Scripts\pythonw.exe app.py` (no console window) at every login. Delete that `.vbs` file
(`Win+R` → `shell:startup`) to stop it auto-starting; `taskkill /IM pythonw.exe /F` to stop the
running server.

## Dashboard login & roles

The dashboard is behind session-based login (Flask sessions, hashed passwords via Werkzeug). Every
account has a **role**: `admin` (full access) or `viewer` (read-only — dashboard, report, CSV
export; no regenerate/upload/settings/audit).

```bash
python manage_users.py add <username> <password> [admin|viewer]   # default role: viewer
python manage_users.py set-role <username> <admin|viewer>
python manage_users.py list                                       # list accounts + roles
python manage_users.py delete <username>                          # remove an account
```

Every page and API route requires a logged-in session; unauthenticated requests are redirected to
`/login` (or get a `401` for `/api/*` calls). Admin-only routes return a `403` for viewer accounts.
The session secret key is generated once and stored at `database/secret_key.txt` so logins survive
server restarts.

The dashboard's **"Regenerate Logs & Analyze"** button (admin only) re-runs the entire pipeline
against freshly generated synthetic data on demand.

## Real log ingestion

Admins can import real logs instead of the synthetic demo data from **Upload Logs** in the
dashboard nav (or `POST /logs/upload`). The file must be a CSV using CyberTrace-Lite's internal
schema (same columns the synthetic generator produces):

```
timestamp,username,ip_address,event_type,login_status,resource,download_count,session_duration_min
2026-09-01T09:14:22,jdoe,192.168.1.14,LOGIN,SUCCESS,-,0,12.5
2026-09-01T09:15:03,jdoe,192.168.1.14,RESOURCE_ACCESS,SUCCESS,Finance_DB,0,0
2026-09-01T09:20:47,jdoe,192.168.1.14,DOWNLOAD,SUCCESS,Finance_DB,1,0
```

- `event_type` one of `LOGIN`, `RESOURCE_ACCESS`, `DOWNLOAD`, `LOGOUT`
- `login_status` one of `SUCCESS`, `FAILED`, or `-` for non-login events
- `timestamp` ISO 8601

This targets the project's own internal schema rather than arbitrary Windows Event Log / syslog
exports — convert a real log export into this shape first. The uploaded file is validated
(`modules/log_ingestion.py`) and saved to `logs/imported_logs.csv`, then the full pipeline runs
against it (`run_pipeline.run(log_source="uploaded")`).

## Alerting & notifications

Configure email (SMTP) and/or a webhook (Slack/Teams/generic) under **Settings** (admin only, or
`GET/POST /settings`). Settings are stored in `config.json` next to `app.py` (**not** in the SQLite
database, so credentials never get mixed into data the pipeline resets) — see
`config.example.json` for the shape. `config.json` is git-ignored; never commit real credentials in
it.

Every pipeline run sends **at most one notification per new HIGH RISK incident** — tracked in the
`notified_incidents` table so re-running the pipeline (or re-uploading the same data) never
re-sends a duplicate alert.

## Reporting

- **Report** (`/report`, any logged-in role) — a clean, print-friendly summary page. Click
  "Print / Save as PDF" and use the browser's print dialog — no extra PDF-generation dependency
  needed.
- **Export CSV** (`/api/export/csv`, any logged-in role) — downloads the full `risk_scores` table
  as CSV.
- **Audit Log** (`/audit`, admin only) — who logged in, ran the pipeline, uploaded logs, changed
  settings, or exported a report, and when.

## Project structure

```
cybertrace-lite/
├── app.py                     Flask app: auth, roles, dashboard, admin pages & JSON APIs
├── run_pipeline.py            End-to-end pipeline orchestrator
├── database.py                SQLite schema & connection helper
├── manage_users.py            CLI to add/reset/delete/set-role dashboard login accounts
├── requirements.txt
├── config.example.json        Template for SMTP/webhook settings (copy → config.json)
├── Dockerfile / .dockerignore Container image (SQLite persisted via a named volume)
├── docker-compose.yml         Local Docker run: `docker compose up --build`
├── fly.toml                   Fly.io deploy config: `flyctl deploy`
├── modules/
│   ├── log_generator.py       Module 1  — synthetic log generation
│   ├── log_ingestion.py       Module 1b — validate/import real log uploads
│   ├── preprocessing.py       Module 2
│   ├── feature_extraction.py  Module 3
│   ├── behavior_analysis.py   Module 4
│   ├── anomaly_detection.py   Module 5  — Isolation Forest + LOF ensemble + SHAP
│   ├── risk_scoring.py        Module 6
│   ├── evaluation.py          Precision/recall/F1 vs. seeded ground truth
│   └── notifications.py       Email / webhook alerting
├── templates/
│   ├── login.html
│   ├── dashboard.html         Module 7 — dashboard UI
│   ├── upload_logs.html       Admin: real log upload
│   ├── settings.html          Admin: SMTP/webhook config
│   ├── audit_log.html         Admin: audit trail view
│   └── report.html            Printable security report
└── static/
    ├── css/style.css
    └── js/dashboard.js
```

## Notes

- Logs are synthetically generated (`modules/log_generator.py`) so the project is fully
  self-contained and reproducible without needing access to a real organization's logs. Three
  users (`santhosh`, `user02`, `user15`) are seeded with periodic anomalous behaviour so the
  detection layers have real signal to catch.
- `modules/log_ingestion.py` + the `/logs/upload` route let the same pipeline run against a real
  log export without touching any other module — only the log source changes.
- The anomaly detection layer is a genuine two-model ensemble (Isolation Forest + Local Outlier
  Factor), not a single model.
- Role-based access control (`admin` vs `viewer`) and the audit log give the project a
  security-conscious access-control story beyond just detection: who can trigger a pipeline run or
  change alerting config is itself tracked and restricted.

## License

Released under the [MIT License](LICENSE) — free to use, modify, and build on.

---

<div align="center">

Built as a capstone project · Santhosh Bhandary

</div>
