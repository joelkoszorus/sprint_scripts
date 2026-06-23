# Scripting & Automation for Security Administration

A portfolio of Python tooling and infrastructure automation built for security and
systems administration — log analysis, host telemetry, network reconnaissance,
health monitoring, and multi-server deployment with Ansible. Every project was
written to solve a practical problem, run on a real AWS Linux lab, and stand on
its own as a usable tool.

> **Why this repo exists.** This is coursework from a scripting and automation
> course (SEC444) approached from a sysadmin and cybersecurity perspective — but
> I deliberately built it as a showcase rather than a folder of throwaway
> exercises. The goal was learning-by-doing: writing real scripts that solve real
> problems instead of textbook snippets, and incorporating AI tools intentionally,
> the way they're actually applied in professional environments today. Each sprint
> builds on the last, ending in a fully automated, idempotent deployment pipeline.

---

## The Sprints

Each sprint is a self-contained project with its own detailed README, source, and
sample output. Click through for the deep dive.

| # | Project | What it does | Highlights |
|---|---------|--------------|------------|
| 1 | **[SSH Log Parser](sprint1/)** | Scans Linux `auth.log` for failed SSH logins and reports timestamp, user, and source IP to terminal + CSV | Regex parsing, stdlib-only, full error handling |
| 2 | **[System Information Gatherer](sprint2/)** | Collects host telemetry (CPU, RAM, disk, network, uptime) and emits screen / CSV / JSON | `psutil`, importable as a module, structured output |
| 3 | **[NetRecon](sprint3/)** | Network recon tool combining Nmap port scanning with IP geolocation into one CSV report | `python-nmap`, public API, optional remote scan over SSH |
| 4 | **[HealthMon](sprint4/)** | Configurable system-health monitor with threshold alerts to a dedicated log and syslog | `logging` framework, JSON config, cron-ready |
| 5 | **[HealthMon Deployment](sprint5/)** | Automates provisioning + deployment of HealthMon across multiple AWS servers with Ansible | Idempotent playbooks, SSH hardening, proven `changed=0` reruns |

---

## Sprint 1 — [SSH Log Parser](sprint1/)

A command-line tool that scans a Linux `auth.log`, pulls out every failed SSH
login attempt, and reports the timestamp, username, and source IP to both the
terminal and a CSV file for further analysis. Detects both standard and
`invalid user` failure formats using a single compiled regular expression.

- Pure Python standard library — no dependencies
- Clean formatted terminal table plus CSV export with header row
- Handles missing files, bad permissions, and empty results with plain-English messages
- The kind of script you'd run after spotting unusual activity or as a scheduled audit step

→ **[Read the full write-up, regex breakdown, and examples](sprint1/README.md)**

## Sprint 2 — [System Information Gatherer](sprint2/)

`sysinfo.py` collects detailed system information from a Linux host and outputs it
in the format you choose — a human-readable screen report, CSV, or JSON for
pipelines and monitoring tools.

- Hostname/OS/kernel, CPU model + live utilization, memory, all mounted partitions, per-interface IP/MAC, and uptime
- Works as a standalone executable **and** an importable module (`sysinfo.collect_all()`)
- Validates arguments and degrades gracefully when data or permissions are unavailable

→ **[Read the full write-up and example outputs](sprint2/README.md)**

## Sprint 3 — [NetRecon](sprint3/)

A network reconnaissance tool that combines **Nmap port scanning** (`python-nmap`,
`-sV -Pn`) with **IP geolocation** from the public `ip-api.com` API into a single
CSV report — one row per open port.

- Optional remote scan mode: connects to a host over SSH (Paramiko) and runs the scan from there
- Secure credential prompting with `getpass` — no hardcoded secrets
- Clean terminal summary plus combined geo + port CSV

→ **[Read the full write-up and usage modes](sprint3/README.md)**

## Sprint 4 — [HealthMon](sprint4/)

A configurable Linux health monitor that checks disk, memory, CPU load average,
and systemd service status against user-defined thresholds, then sends structured
alerts to a dedicated alert log and to syslog whenever a threshold is exceeded.

- All thresholds and paths come from `config.json` — nothing hardcoded
- Built on Python's `logging` framework (no `print()`); WARNING/ERROR events forwarded to syslog
- `--check` summary mode for hourly review; designed for unattended cron execution

→ **[Read the full write-up, config reference, and alert testing guide](sprint4/README.md)**

## Sprint 5 — [Automated HealthMon Deployment with Ansible](sprint5/)

The capstone: take the Sprint 4 monitor and automate its provisioning and
deployment across multiple AWS Linux servers using **Ansible**. One server doubles
as the control node — configuring itself locally and a second server over SSH —
through two idempotent playbooks:

- **`configure.yml`** — baseline hardening: packages, a dedicated service account, timezone, SSH hardening, and logging
- **`deploy.yml`** — deploys the Sprint 4 scripts, installs dependencies, sets permissions, and schedules via cron

Both playbooks are **fully idempotent** — the first run applies state and reports
`changed`, the second run reports `changed=0` on every host. This is captured with
live `PLAY RECAP` screenshots in the sprint README.

→ **[Read the full write-up, architecture diagram, and idempotency proof](sprint5/README.md)**

---

## CI/CD — Quality & Security Gates

Every push and pull request to `main` runs an automated
[GitHub Actions pipeline](.github/workflows/qualityassurance.yml) covering the
whole repo:

| Job | Tool | Purpose |
|-----|------|---------|
| **Lint** | `ruff` | Style and correctness checks |
| **CodeQL** | GitHub CodeQL (`security-extended`) | Static application security testing (SAST) |
| **Dependency CVE Scan** | `pip-audit` | Scans every `requirements.txt` for known vulnerabilities |

---

## Course Outcomes Demonstrated

- Operate in a virtual server environment (AWS EC2)
- Apply scripting and debugging techniques to automate security administration tasks
- Use Git for source control, change management, and code sharing
- Automate logging, monitoring, database/API interaction, and reporting
- Provision and deploy infrastructure repeatably with configuration management

## Stack

- **Languages / tooling:** Python, Ansible, Bash
- **Environment:** AWS (EC2), Ubuntu Server
- **Libraries:** `psutil`, `python-nmap`, `paramiko`, `requests`
- **CI/CD:** GitHub Actions, ruff, CodeQL, pip-audit
- **Focus:** Security administration, config management, automation

---

*Scripts in this repo are written to solve practical problems — not textbook
examples. AI tools were incorporated intentionally, reflecting how they're applied
in professional environments today.*