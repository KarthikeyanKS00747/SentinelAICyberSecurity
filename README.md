# SentinelAI – Setup & Run Instructions (Phase 1)

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | ≥ 3.11 | python.org |
| Ollama | latest | [ollama.com](https://ollama.com) |
| llama3 model | — | `ollama pull llama3` |

---

## 1. Clone & create virtual environment

```bash
git clone <your-repo-url> sentinelai
cd sentinelai

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
```

## 2. Install dependencies

```bash
pip install -r requirements.txt
```

> **Note for Linux:** `python-magic` requires `libmagic`:
> ```bash
> sudo apt install libmagic1   # Debian/Ubuntu
> brew install libmagic        # macOS
> ```

## 3. Configure environment

```bash
cp .env.example .env
# Edit .env — at minimum, set SECRET_KEY to a random string:
# python -c "import secrets; print(secrets.token_hex(32))"
```

## 4. Start Ollama (separate terminal)

```bash
ollama serve          # starts the local LLM daemon on port 11434
ollama pull llama3    # downloads the model (~4 GB, first time only)
```

## 5. Run SentinelAI

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## 6. Test the Phase 1 endpoints

```
GET  http://localhost:8000/           → Health check
GET  http://localhost:8000/api/docs   → Swagger UI (all endpoints)
POST http://localhost:8000/api/test-ollama
```

### Smoke-test Ollama via curl:

```bash
curl -X POST http://localhost:8000/api/test-ollama \
     -H "Content-Type: application/json" \
     -d '{"prompt": "What is a port scan attack?", "model": "llama3"}'
```

Expected response:
```json
{
  "status": "success",
  "model": "llama3",
  "prompt": "What is a port scan attack?",
  "response": "A port scan is...",
  "eval_count": 87
}
```

---

## Two-Factor Authentication (TOTP)

Any signed-in user can turn on a second factor from **Two-Factor Auth**
(`/settings/2fa`): scan the QR code with an authenticator app, then enter the
6-digit code it shows. Nothing is stored on the account until that code
verifies, so an abandoned setup cannot lock you out. Turning it back off
requires the account password, not just a button press. Both actions are
written to the audit log.

At the next sign-in, a correct password leads to a second form asking for the
code. Until that code is accepted the session is *not* authenticated — it
holds a short-lived pending marker only, and every protected page still
redirects it to the login screen.

### Recovering a locked-out user

**There are no backup codes.** If someone loses their authenticator device:

1. **Preferred — another administrator clears it.** On the **Users** page
   (`/users`, admin only), press **Reset 2FA** on that account's row. This
   clears `totp_enabled` and `totp_secret`, records a `2fa_reset` entry in the
   audit log, and lets the user sign in with their password alone and re-enrol.
   It never reveals a secret and never signs anyone in.

2. **Fallback — every administrator is locked out.** With no admin left to
   press that button, edit the database directly. Stop the server first:

   ```bash
   sqlite3 sentinelai.db "UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE username = 'admin';"
   ```

   This bypasses the application, so it leaves **no audit-log entry**. Use
   route 1 whenever an admin can still sign in.

Re-running `python -m utils.seed_admin` resets a password but deliberately
does **not** clear a second factor, so a password reset cannot quietly strip
2FA off an account.

> **Known limitation (course-project scope):** a TOTP code stays valid for its
> full 30-second step and is not marked as consumed after use, so a code
> observed in transit could be replayed inside that window by someone who also
> has the password. Preventing that needs a stored last-used time step per user.

---

## Project Structure

```
sentinelai/
├── main.py              ← FastAPI app, middleware, Ollama test endpoint
├── database.py          ← SQLAlchemy engine, session, all ORM models
├── config.py            ← Settings loaded from .env
├── requirements.txt
├── uploads/             ← Uploaded log files (auto-created, outside web root)
├── utils/
│   └── upload_handler.py ← Phase 2: secure file upload validation
└── routers/             ← Phase 2+: logs, alerts, threats, reports
    ├── logs.py
    ├── alerts.py
    ├── threats.py
    └── reports.py
```

---

## Roadmap

- [x] **Phase 1** – FastAPI setup, DB models, Ollama connection
- [ ] **Phase 2** – Log parsing (Regex engine) + secure file upload
- [ ] **Phase 3** – Rule-based threat detection engine
- [ ] **Phase 4** – Frontend dashboard (Tailwind + HTMX + ApexCharts)
- [ ] **Phase 5** – AI "Explain Threat" (Ollama) + PDF report generation
