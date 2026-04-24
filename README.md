# FORENSTIX 2.0

> **Forensic Intelligence Workstation** — File triage meets live OSINT investigation.

Forenstix 2.0 extends the original Forenstix triage engine with an IOC → OSINT pivot pipeline,
persistent case management, YARA scanning, and SSE-streamed live tool output.

---

## The Big Idea

Original Forenstix asks: *"What is this file?"*

Forenstix 2.0 asks: *"What does this threat connect to?"*

Every IP, domain, email, and hash extracted during triage becomes a **pivot target** — a single
click runs the right investigation tools and the results flow back into a persistent case.

```
File Upload
    │
    ▼
Triage (analyzer.py)
    │  hashes, entropy, YARA, IOCs
    ▼
IOC Pivot (/pivot)         ← NEW
    │  domain → subfinder + amass + nuclei + wafw00f
    │  email  → holehe + theharvester + maigret
    │  ip     → nmap + masscan
    ▼
Case Timeline (cases.py)   ← NEW
    │  SQLite: files + IOCs + pivot results + notes
    ▼
AI Report (/export-pdf)
```

---

## Features

### From Forenstix v1 (all preserved)
- Single file forensic triage (hashes, magic bytes, entropy, metadata, anomalies)
- Batch analysis (up to 20 files)
- Multi-file comparison (2–10 files, shared artifact detection)
- VirusTotal hash lookup
- AI-generated analyst narrative (Claude API) with local fallback
- PDF report export (WeasyPrint)

### New in v2.0
- **YARA scanning** — 25+ bundled rules covering malware, webshells, credential theft,
  ransomware, packing, obfuscation; add your own rules to `yara_rules/community.yar`
- **Expanded IOC extraction** — now includes domains, embedded hashes (MD5/SHA-1/SHA-256),
  and deduplication across URL hostnames and email domains
- **IOC Pivot** — click any extracted IOC to run appropriate OSINT/recon tools against it
- **SSE Streaming** — live tool output streams to the UI line-by-line via Server-Sent Events
- **Case Management** — SQLite-backed investigations with files, IOCs, pivot results, and notes
- **Timeline view** — chronological log of every event in a case
- **Investigate / Triage mode toggle** — passive triage is default; active recon requires
  explicit opt-in to prevent accidental live probing
- **fx_run.py CLI** — run any of 210+ catalog tools from the command line with caching,
  audit logging, parallel execution, and dry-run support
- **Claude Code skill** — `skill.md` makes the full API and workflow available to AI agents

---

## Project Structure

```
Forenstix-2.0/
├── app.py                # Flask web app (all routes)
├── analyzer.py           # Core engine: hashes, entropy, YARA, IOC extraction
├── pivot.py              # IOC → tool mapping and execution
├── cases.py              # SQLite case management
├── report_generator.py   # AI narrative generation (Claude / fallback)
├── virustotal.py         # VirusTotal hash lookup
├── comparator.py         # Cross-file comparison
├── fx_run.py             # CLI tool runner (caching, audit, parallel)
├── fx_catalog.py         # 210+ tool registry
├── fx_env.py             # Environment detection (native/WSL/Docker)
├── fx_output.py          # Output parser and formatter
├── yara_rules/
│   └── community.yar     # Bundled YARA detection rules
├── templates/
│   └── index.html        # Dark UI with pivot buttons, case sidebar
├── requirements.txt
├── skill.md              # Claude Code skill definition
└── README.md
```

---

## Installation

```bash
git clone https://github.com/zidanem17-lgtm/Forenstix-2.0
cd Forenstix-2.0
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> `yara-python` requires the YARA C library. On Ubuntu/Debian:
> `sudo apt install libyara-dev` before `pip install`.
> On macOS: `brew install yara`.
> On Windows: use the pre-built wheel: `pip install yara-python`.

---

## Run

```bash
# Development
python app.py

# Production
gunicorn app:app --bind 0.0.0.0:$PORT --workers 2
```

App starts on `http://localhost:5000`.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | — | Enables AI-generated reports (Claude API) |
| `VIRUSTOTAL_API_KEY` | — | Enables VirusTotal hash lookups |
| `PORT` | `5000` | Server port |
| `FORENSTIX_DB` | `forenstix.db` | SQLite database path |
| `FORENSTIX_CACHE` | `~/.forenstix/cache/` | CLI tool result cache directory |
| `FORENSTIX_CACHE_TTL` | `3600` | Cache TTL in seconds |
| `FORENSTIX_AUDIT` | `~/.forenstix/audit.jsonl` | CLI audit log path |

---

## API Reference

### Analysis
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/analyze` | Analyze one file (field: `file`) |
| POST | `/analyze-batch` | Analyze up to 20 files (field: `files`) |
| POST | `/compare` | Compare 2–10 files (field: `files`) |
| GET  | `/virustotal/<hash>` | Hash lookup (MD5/SHA-1/SHA-256) |
| POST | `/export-pdf` | Export report HTML as PDF |

### IOC Pivot
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/pivot` | Run tools against an IOC (JSON body) |
| GET  | `/pivot/stream` | SSE streaming pivot (query params) |
| GET  | `/pivot/tools` | IOC → default tool mapping |

### Cases
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/cases` | List all cases |
| POST | `/cases` | Create case `{name, description}` |
| GET  | `/cases/<id>` | Case details + stats |
| PUT  | `/cases/<id>` | Update `{name, description, status}` |
| DELETE | `/cases/<id>` | Delete case |
| POST | `/cases/<id>/files` | Upload + analyze file, add to case |
| GET  | `/cases/<id>/files` | List case files |
| GET  | `/cases/<id>/iocs` | List IOCs (`?type=domain`) |
| POST | `/cases/<id>/iocs` | Manually add IOC |
| GET  | `/cases/<id>/pivot-results` | All pivot results in case |
| GET  | `/cases/<id>/notes` | List notes |
| POST | `/cases/<id>/notes` | Add note `{content}` |
| GET  | `/cases/<id>/timeline` | Chronological event timeline |

---

## CLI Usage

```bash
# Run a single tool
python fx_run.py nmap 192.168.1.1
python fx_run.py subfinder example.com --output json

# Run multiple tools in parallel
python fx_run.py --parallel subfinder,amass,dnstwist example.com --output table

# Dry run
python fx_run.py nuclei example.com --dry-run

# Check tool availability
python fx_run.py --check nmap

# List all catalog tools
python fx_run.py --list
python fx_run.py --list --category "Memory Forensics"

# Tag with evidence ID
python fx_run.py nmap 10.0.0.1 --evidence-id CASE-2025-042
```

---

## IOC → Tool Defaults

| IOC Type | Default Tools |
|----------|--------------|
| `domain` | subfinder, amass, dnstwist, httpx, wafw00f, nuclei |
| `url` | httpx, wafw00f, nuclei, testssl, katana |
| `email` | holehe, theharvester, maigret |
| `ip` | nmap, masscan |
| `hash` | VirusTotal (UI) |
| `username` | sherlock, maigret, socialscan |

Override defaults per-request via the `tools` array in `/pivot`.

---

## YARA Rules

Add custom rules to `yara_rules/community.yar`:

```yara
rule My_Custom_Rule {
    meta:
        description = "Detects my threat pattern"
        severity    = "high"
    strings:
        $s1 = "evil_string" ascii nocase
    condition:
        $s1
}
```

Forenstix will pick up new rules on the next analysis without restart.

---

## Architecture

```
Browser
  │  upload / view results / pivot buttons / case sidebar
  ▼
Flask (app.py)
  ├── /analyze*      → analyzer.py (YARA + IOC extraction)
  ├── /pivot         → pivot.py   (tool execution, synchronous)
  ├── /pivot/stream  → pivot.py   (SSE streaming generator)
  └── /cases*        → cases.py  (SQLite R/W)

pivot.py
  └── fx_run.py / fx_catalog.py → native binary or Docker image

cases.py
  └── forenstix.db (SQLite WAL)

report_generator.py
  └── Anthropic API / local fallback
```

For high-scale deployments, replace the synchronous `/pivot` call with a Celery/RQ worker
and push results via SSE from the `/pivot/stream` endpoint. The streaming architecture
is already in place — only the execution backend needs to change.

---

## Roadmap

- [ ] Memory dump analysis (Volatility 3 integration via web UI)
- [ ] MITRE ATT&CK technique tagging on YARA matches
- [ ] Graph view of IOC relationships (D3.js)
- [ ] Shodan / Censys API integration for IP pivot
- [ ] Unified case PDF export (full case: files + IOCs + pivot results + timeline)
- [ ] Docker Compose deployment with Redis + Celery worker
- [ ] Mobile forensics tab (ALEAPP/ILEAPP for iOS/Android artifacts)

---

## Disclaimer

Forenstix 2.0 is a forensic investigation tool for authorized use only.
Active recon tools (nmap, nuclei, amass, etc.) make real network requests.
Always obtain proper authorization before investigating external infrastructure.