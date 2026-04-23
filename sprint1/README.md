# Sprint 1 — SSH Log Parser

## 1. Project Overview

`logparser.py` is a command-line tool that scans a Linux `auth.log` file and pulls out every failed SSH login attempt. It reports the timestamp, username, and source IP of each failure — both to the terminal and to a CSV file you can keep for further analysis.

This is the kind of script you would run after spotting unusual activity or as a scheduled audit step. It is intentionally simple and uses only Python standard-library modules.

---

## 2. Features

- Parses standard Linux `auth.log` format
- Detects both failure formats:
  - `Failed password for admin from ...`
  - `Failed password for invalid user test from ...`
- Extracts: **timestamp**, **username**, and **source IPv4 address**
- Prints a clean, formatted table to the terminal
- Writes results to a CSV file with a header row
- Handles every common error (missing file, bad permissions, no results) with a clear message

---

## 3. Requirements

- Python 3.6 or later
- No external packagess

---

## 4. Installation

Clone the repository and navigate to the sprint1 directory:

```bash
git clone <repo-url>
cd sprint_scripts/sprint1
```

No pip install or virtual environment is needed.

---

## 5. Usage

```
python logparser.py <logfile> <output.csv>
```

| Argument | Description |
|---|---|
| `<logfile>` | Path to the `auth.log` file you want to analyze |
| `<output.csv>` | Path where the CSV report will be written |

**Example:**

```bash
python logparser.py auth.log failed_logins.csv
```

---

## 6. Example Output

### Terminal

```
[INFO] Found 3 failed login attempts:

Timestamp           Username        Source IP       
----------------------------------------------------
Apr 14 00:28:06     admin           142.146.24.37   
Apr 14 00:28:09     test            142.146.24.37   
Apr 14 00:28:11     root            142.146.24.37   

[INFO] Results saved to: failed_logins.csv
```

### CSV (`failed_logins.csv`)

```
timestamp,username,source_ip
Apr 14 00:28:06,admin,142.146.24.37
Apr 14 00:28:09,test,142.146.24.37
Apr 14 00:28:11,root,142.146.24.37
```

---

## 7. How It Works

### Parsing Strategy

The script reads the log file one line at a time and tests each line against a compiled regular expression. Lines that don't match (successful logins, cron jobs, kernel messages, etc.) are skipped. Only lines that look like a failed SSH password attempt are kept.

### The Regular Expression

```python
r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"  # timestamp
r"\s+\S+"                                    # hostname (ignored)
r"\s+sshd\[\d+\]:\s+"                       # sshd process tag
r"Failed password for\s+"                    # literal failure text
r"(?:invalid user\s+)?"                      # optional "invalid user" prefix
r"(\S+)"                                     # username
r"\s+from\s+"                                # separator
r"((?:\d{1,3}\.){3}\d{1,3})"               # IPv4 address
```

Breaking it down piece by piece:

| Piece | What it matches | Why |
|---|---|---|
| `(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})` | `Apr 14 00:28:06` | Captures the raw timestamp string. Three-letter month, 1–2 digit day, `HH:MM:SS`. |
| `\s+\S+` | `linux1` | Consumes the hostname but doesn't capture it — we don't need it. |
| `\s+sshd\[\d+\]:\s+` | `sshd[1006]: ` | Anchors us to SSH daemon log lines specifically. |
| `Failed password for\s+` | `Failed password for ` | Literal match — ensures we only grab actual failure events. |
| `(?:invalid user\s+)?` | `invalid user ` or nothing | Non-capturing optional group. When `invalid user` appears, this group eats it so the very next `\S+` still grabs the real username. |
| `(\S+)` | `admin` or `test` | Captures the username — any non-whitespace sequence. |
| `\s+from\s+` | ` from ` | Separator between username and IP. |
| `((?:\d{1,3}\.){3}\d{1,3})` | `142.146.24.37` | Captures an IPv4 address. Four groups of 1–3 digits separated by dots. IPv6 is intentionally not matched. |

The regex is compiled once at module load time (stored in `FAILED_LOGIN_PATTERN`) so it is not recompiled for every line, I found this to be an efficient way to apply a pattern across a large file.

### Data Flow

```
auth.log
   │
   ▼
extract_failed_logins()  ← applies regex line by line
   │
   ├──► print_results()  → formatted table to terminal
   │
   └──► write_to_csv()   → CSV file with header row
```

---

## 8. Error Handling

| Situation | What happens |
|---|---|
| Wrong number of arguments | `argparse` prints usage and exits — no traceback |
| Log file does not exist | `[ERROR] File not found: <path>` then exit |
| Path is a directory, not a file | `[ERROR] Path is not a regular file: <path>` then exit |
| File exists but is not readable | `[ERROR] Permission denied — cannot read: <path>` then exit |
| IO error during read | `[ERROR] Could not read file: <reason>` then exit |
| Cannot write CSV | `[ERROR] Could not write CSV: <reason>` then exit |
| Log file has no matching lines | `[INFO] No failed SSH login attempts found` — no CSV written |

All errors use a `[ERROR]` or `[INFO]` prefix and plain English so the cause is immediately obvious without needing to read a stack trace.
