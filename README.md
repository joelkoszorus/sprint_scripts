# Scripting & Automation for Security Administration
My portfolio of tooling and infrastructure automation built for security and
systems administration - log analysis, host telemetry, network reconnaissance,
health monitoring, and multi-server deployment. Every project was
written to solve a practical problem and stand on
its own as a usable tool.

---

## The Scripts

Each script is a self-contained project with its own detailed README, source, and
sample output. Click through for the deep dive.

| # | Project | What it does | Highlights |
|---|---------|--------------|------------|
| 1 | **[SSH Log Parser](sprint1/)** | Scans Linux `auth.log` for failed SSH logins and reports timestamp, user, and source IP to terminal + CSV | Regex parsing, stdlib-only, full error handling |
| 2 | **[System Information Gatherer](sprint2/)** | Collects host telemetry (CPU, RAM, disk, network, uptime) and emits screen / CSV / JSON | `psutil`, importable as a module, structured output |
| 3 | **[NetRecon](sprint3/)** | Network recon tool combining Nmap port scanning with IP geolocation into one CSV report | `python-nmap`, public API, optional remote scan over SSH |
| 4 | **[HealthMon](sprint4/)** | Configurable system-health monitor with threshold alerts to a dedicated log and syslog | `logging` framework, JSON config, cron-ready |
| 5 | **[HealthMon Deployment](sprint5/)** | Automates provisioning + deployment of HealthMon across multiple AWS servers with Ansible | Idempotent playbooks, SSH hardening, proven `changed=0` reruns |

---

## [SSH Log Parser](sprint1/)

A command-line tool that scans a Linux `auth.log`, pulls out every failed SSH
login attempt, and reports the timestamp, username, and source IP to both the
terminal and a CSV file for further analysis. Detects both standard and
`invalid user` failure formats using a single compiled regular expression.

- Pure Python standard library
- Clean formatted terminal table plus CSV export with header row
- Handles missing files, bad permissions, and empty results with plain-English messages
- The kind of script you'd run after spotting unusual activity or as a scheduled audit step

## [System Information Gatherer](sprint2/)

`sysinfo.py` collects detailed system information from a Linux host and outputs it
in the format you choose: a human-readable screen report, CSV, or JSON for
pipelines and monitoring tools.

- Hostname/OS/kernel, CPU model + live utilization, memory, all mounted partitions, per-interface IP/MAC, and uptime
- Works as a standalone executable **and** an importable module (`sysinfo.collect_all()`)
- Validates arguments and degrades gracefully when data or permissions are unavailable

## [NetRecon](sprint3/)

A network reconnaissance tool that combines **Nmap port scanning** (`python-nmap`,
`-sV -Pn`) with **IP geolocation** from the public `ip-api.com` API into a single
CSV report.

- Optional remote scan mode: connects to a host over SSH (Paramiko) and runs the scan from there
- Secure credential prompting with `getpass` - no hardcoded secrets
- Clean terminal summary plus combined geo + port CSV

## [HealthMon](sprint4/)

A configurable Linux health monitor that checks disk, memory, CPU load average,
and systemd service status against user-defined thresholds, then sends structured
alerts to a dedicated alert log and to syslog whenever a threshold is exceeded.

- All thresholds and paths come from `config.json` - nothing hardcoded
- Built on Python's `logging` framework (no `print()`); WARNING/ERROR events forwarded to syslog
- `--check` summary mode for hourly review; designed for unattended cron execution

## [Automated HealthMon Deployment with Ansible](sprint5/)

Take HealthMon and automate its provisioning and
deployment across multiple AWS Linux servers using **Ansible**. One server doubles
as the control node, configuring itself locally and a second server over SSH, all
donw with two idempotent playbooks:

- **`configure.yml`** - baseline hardening: packages, a dedicated service account, timezone, SSH hardening, and logging
- **`deploy.yml`** - deploys the HealthMon script, installs dependencies, sets permissions, and schedules via cron

Both playbooks are **fully idempotent** - the first run applies state and reports
`changed`, the second run reports `changed=0` on every host. This is captured with
live `PLAY RECAP` screenshots in the sprint README.

---

## CI/CD - Quality & Security Gates

Every push and pull request to `main` runs an automated
[GitHub Actions pipeline](.github/workflows/qualityassurance.yml) covering the
whole repo:

| Job | Tool | Purpose |
|-----|------|---------|
| **Lint** | `ruff` | Style and correctness checks |
| **CodeQL** | GitHub CodeQL (`security-extended`) | Static application security testing (SAST) |
| **Dependency CVE Scan** | `pip-audit` | Scans every `requirements.txt` for known vulnerabilities |

---

## Skill Outcomes

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

*Scripts in this repo are written to solve practical problems. AI tools were incorporated intentionally, reflecting how they're applied in professional environments today.*
