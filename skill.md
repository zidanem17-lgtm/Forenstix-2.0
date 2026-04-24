# FORENSTIX 2.0 — Claude Code Skill

## What is Forenstix 2.0?

Forenstix 2.0 is a forensic intelligence workstation that combines file triage with live OSINT investigation.
It bridges two workflows that analysts normally do manually:

1. **Triage** — Extract hashes, entropy, metadata, YARA hits, and IOCs from suspicious files.
2. **Investigate** — Feed extracted IOCs (IPs, domains, emails, hashes, usernames) directly into
   the right OSINT and recon tools, chain the results, and build a persistent case.

Use this skill when the user asks you to:
- Analyze a suspicious file or batch of files
- Investigate an IP address, domain, email, or hash
- Build an investigation case around a threat
- Pivot from one IOC to related infrastructure
- Run specific security tools (nmap, subfinder, holehe, nuclei, volatility3, etc.)
- Export a forensic report

---

## IOC → Tool Pipeline

The core concept is that extracted IOCs are **pivot targets**. Map each IOC type to the default tools:

| IOC Type | Default Tools |
|----------|--------------|
| `domain` | subfinder, amass, dnstwist, httpx, wafw00f, nuclei |
| `url`    | httpx, wafw00f, nuclei, testssl, katana |
| `email`  | holehe, theharvester, maigret |
| `ip`     | nmap, masscan |
| `hash`   | VirusTotal (via `/virustotal/<hash>`) |
| `username` | sherlock, maigret, socialscan |

---

## Flask API Endpoints

### Analysis (v1 compatible)
```
POST /analyze              # Single file
POST /analyze-batch        # Up to 20 files
POST /compare              # Compare 2–10 files
GET  /virustotal/<hash>    # Hash reputation
POST /export-pdf           # Export report as PDF
```

### IOC Pivot (NEW)
```
POST /pivot
{
  "ioc_type": "domain|url|email|ip|hash|username",
  "value":    "<target>",
  "tools":    ["subfinder","amass"],  // optional override
  "timeout":  60,                     // optional
  "case_id":  1,                      // optional — save to case
  "ioc_id":   5                       // optional — link to case IOC row
}

GET /pivot/stream?ioc_type=domain&value=example.com&tools=subfinder,amass
// SSE endpoint — streams tool output in real time

GET /pivot/tools           // Returns the IOC→tool mapping
```

### Case Management (NEW)
```
GET    /cases                       # list all cases
POST   /cases                       # create case {name, description}
GET    /cases/<id>                  # case details + stats
PUT    /cases/<id>                  # update {name, description, status}
DELETE /cases/<id>                  # delete case

POST   /cases/<id>/files            # upload+analyze file, add to case
GET    /cases/<id>/files            # list files in case
GET    /cases/<id>/files/<fid>      # get file with full analysis JSON

GET    /cases/<id>/iocs             # list IOCs (?type=domain)
POST   /cases/<id>/iocs             # manually add IOC {ioc_type, value}

GET    /cases/<id>/pivot-results    # all pivot results across case IOCs
GET    /cases/<id>/notes            # list analyst notes
POST   /cases/<id>/notes            # add note {content}
GET    /cases/<id>/timeline         # chronological event timeline
```

---

## CLI (fx_run.py)

Run tools from the command line:

```bash
# Single tool
python fx_run.py nmap 192.168.1.1
python fx_run.py subfinder example.com --output json
python fx_run.py volatility3 memory.dmp --timeout 300

# Parallel tools
python fx_run.py --parallel subfinder,amass,dnstwist example.com

# Dry run (shows command without executing)
python fx_run.py nmap 10.0.0.1 --dry-run

# Check availability
python fx_run.py --check nmap

# List all tools (optionally filter by category)
python fx_run.py --list --category "Network Scanner"

# Tag with evidence ID
python fx_run.py nmap 192.168.1.1 --evidence-id "CASE-2025-001"
```

---

## Tool Catalog

The full catalog is in `fx_catalog.py` (210+ tools). Key categories:

| Category | Example Tools |
|----------|--------------|
| Information Gathering | nmap, masscan, subfinder, amass, theharvester, recon-ng |
| Vulnerability Analysis | nuclei, nikto, openvas, sqlmap |
| Web Hacking | sqlmap, xsstrike, dalfox, wfuzz, ffuf, katana |
| Password Attacks | hashcat, john, hydra, medusa |
| Wireless | aircrack-ng, airgeddon, wifite |
| Network Sniffing | wireshark, tshark, tcpdump, mitmproxy |
| OSINT | theharvester, sherlock, holehe, maigret, phoneinfoga |
| Social Engineering | gophish, beef |
| **Memory Forensics** | **volatility3**, avml, LiME |
| **Disk Forensics** | **sleuthkit**, autopsy, ddrescue, photorec, foremost, scalpel |
| **Log Analysis** | **chainsaw**, hayabusa, sigma |
| **Malware Analysis** | **capa**, YARA, radare2, Ghidra, strings, binwalk, exiftool |
| **Network Forensics** | **zeek**, suricata, NetworkMiner, tshark |
| **Timeline** | **plaso**, timesketch |
| **Container Forensics** | **trivy**, falco, sysdig |

---

## Investigation Workflow (Recommended)

When a user uploads a suspicious file or describes a threat, follow this chain:

1. **Triage** — `POST /analyze` to extract hashes, IOCs, entropy, YARA hits
2. **Create Case** — `POST /cases` with a descriptive name
3. **Add File to Case** — `POST /cases/<id>/files`
4. **Pivot on IOCs** — For each high-value IOC, `POST /pivot` with appropriate tools
5. **Chain results** — Use pivot findings to discover more IOCs, add them to the case
6. **Annotate** — `POST /cases/<id>/notes` with analyst observations at each step
7. **Report** — `POST /export-pdf` for the final forensic report

---

## YARA Rules

Bundled rules in `yara_rules/community.yar` detect:
- Hidden PE/ELF executables
- UPX packing
- Base64-encoded payloads
- PowerShell download cradles and encoded commands
- VBA AutoOpen macros with shell execution
- PHP/ASPX webshells
- Mimikatz strings
- Credential file references (SAM, NTDS)
- C2 beacon patterns, Tor .onion references
- Ransomware notes and crypto API usage
- AWS access key leaks
- Embedded SSH private keys

Add custom rules to `yara_rules/community.yar` using standard YARA syntax.

---

## Environment & Backends

Forenstix detects available backends automatically:
- **native** — uses tools installed on the host
- **docker** — uses purpose-built Docker images when available
- **wsl** — runs Windows tools via WSL

Run `python fx_env.py` to see your detected environment.

---

## Passive vs Active Mode

The UI has a **Triage / Investigate Mode** toggle in the header.

- **Triage Mode (default)** — Only file analysis. No live tool execution. Safe for all files.
- **Investigate Mode** — Enables IOC pivot buttons on extracted artifacts.
  Active recon tools (nmap, amass, nuclei) make **real network requests** — only enable
  with explicit intent and appropriate authorization.
