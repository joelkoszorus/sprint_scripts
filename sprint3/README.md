# NetRecon

A command-line network reconnaissance tool that combines **Nmap port scanning** and **IP geolocation** into a single CSV report. Optionally runs the scan from a remote host over SSH.

---

## Features

- TCP port scan using `python-nmap` (`-sV -Pn`)
- IP geolocation via the public `ip-api.com` API (country, region, city, ISP)
- Combined CSV output — one row per open port
- Clean terminal summary after each scan
- Optional remote scan mode via SSH (Paramiko)
- Secure credential prompting with `getpass` — no hardcoded passwords
- Graceful handling of invalid input, network failures, and permission errors

---

## Requirements

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| Nmap | Latest stable (system package) |

Python dependencies (see `requirements.txt`):

```
python-nmap
requests
paramiko
```

---

## Installation

### Linux / macOS

```bash
# Install Nmap
sudo apt install nmap          # Debian / Ubuntu
sudo dnf install nmap          # Fedora / RHEL
brew install nmap              # macOS (Homebrew)

# Install Python dependencies
pip install -r requirements.txt
```

### Windows

1. Download and install Nmap from [nmap.org/download](https://nmap.org/download.html).
2. During installation, check **"Add Nmap to PATH"** (or add it manually).
3. Install Python dependencies:

```powershell
pip install -r requirements.txt
```

> **Note:** Some Nmap scan types (e.g., SYN scan) require Administrator privileges on Windows. Right-click your terminal and choose **"Run as Administrator"** if you receive a permissions error.

---

## Usage

### Local scan

```bash
python3 netrecon.py <target_ip> <output.csv>
```

Example:

```bash
python3 netrecon.py 192.168.1.10 results.csv
```

### Remote SSH scan

```bash
python3 netrecon.py <target_ip> <output.csv> --remote <ssh_host>
```

Example:

```bash
python3 netrecon.py 10.0.0.5 results.csv --remote 192.168.1.20
```

When `--remote` is used, the script:
1. Prompts you for SSH credentials (username + password via `getpass`)
2. Connects to `ssh_host` over SSH
3. Executes the Nmap scan from that remote host
4. Parses the output and combines it with geolocation data locally

---

## Console Output Example

```
========================================
        NetRecon Scan Summary
========================================

Target: 192.168.1.10

Location:
  Country : United States
  Region  : Washington
  City    : Seattle
  ISP     : Comcast

Open Ports:
  22/tcp          ssh          open
  80/tcp          http         open
  443/tcp         https        open

Results written to:
  results.csv

========================================
```

---

## CSV Output Example

| target_ip | country | region | city | isp | port | service | state |
|---|---|---|---|---|---|---|---|
| 192.168.1.10 | United States | Washington | Seattle | Comcast | 22/tcp | ssh | open |
| 192.168.1.10 | United States | Washington | Seattle | Comcast | 80/tcp | http | open |
| 192.168.1.10 | United States | Washington | Seattle | Comcast | 443/tcp | https | open |

If no open ports are found, the script still writes one row containing the geolocation data with the `state` field set to `"no open ports"`.

---
