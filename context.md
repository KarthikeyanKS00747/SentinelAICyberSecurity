# SentinelAI - Project Context & Rules

## Project Overview

SentinelAI is a lightweight, educational, web-based SIEM dashboard. It analyzes uploaded log files (`.log`, `.txt`, `.csv`), parses them, stores them in SQLite, runs rule-based threat detection, visualizes data on a dashboard, and uses a local LLM to explain threats.

## Tech Stack (Strict Adherence Required)

- **Backend:** FastAPI (Python) with async SQLAlchemy.
- **Database:** SQLite (file-based, zero-config).
- **Frontend:** HTML, Tailwind CSS (via CDN), HTMX (for dynamic UI without JS frameworks), ApexCharts (via CDN).
- **AI Engine:** Ollama (local LLM, e.g. Llama-3 or Phi-3). No OpenAI or external APIs.
- **Templating:** Jinja2 (built into FastAPI).

## Security Hardening Rules

1. Validate uploaded MIME types using magic bytes (`python-magic`), not extensions alone.
2. Sanitize filenames, strip directory components, and save files under UUID names.
3. Rely on Jinja2 auto-escaping; never use `| safe` for log data.
4. Enforce a strict upload-size limit (for example, 10 MB) before writing files.
5. Backend Ollama calls must only target `http://localhost:11434`.

## Core Business Logic

### Log Parsing

Extract timestamp, source IP, destination IP, username, event type, status, and message.

### Threat Detection Rules

- Brute force: multiple failed logins from the same IP.
- Port scan: one IP accessing many ports quickly.
- Malicious IP: login from an IP in the local ThreatIntel database.

### AI Explanation

For an explained alert, Ollama generates a simple explanation, the alert rationale, possible impact, and recommended mitigation steps.

## 5-Phase Implementation Roadmap

1. FastAPI setup, SQLAlchemy models, and Ollama connection test.
2. Secure upload endpoint and regex log parser.
3. Rule-based threat-detection engine.
4. Tailwind/HTMX dashboard and charts.
5. AI threat explanation and PDF report generation.
