# HealthMon

A configurable Linux system health monitoring utility written in Python.

Monitors disk usage, memory usage, CPU load average, and systemd service
status against user-defined thresholds. Sends structured alerts to a
dedicated alert log and to syslog whenever a threshold is exceeded. Designed
for unattended execution via cron and also usable interactively.

---

## Features

- **Disk monitoring** – checks root filesystem usage via `shutil.disk_usage`.
- **Memory monitoring** – checks RAM usage via `psutil.virtual_memory`.
- **CPU load monitoring** – checks the 1-minute load average via `os.getloadavg`.
- **Service monitoring** – checks systemd service status via `systemctl is-active`.
- **Configurable thresholds** – all limits and paths come from `config.json`; nothing is hardcoded.
- **Python `logging` framework** – no `print()` calls; all output goes through structured loggers.
- **Syslog alerts** – WARNING and ERROR events are forwarded to syslog via `SysLogHandler`.
- **Dedicated alert log** – threshold violations are also written to a separate `alerts.log`.
- **`--check` summary mode** – prints a formatted health snapshot suitable for hourly review.
- **Cron-ready** – exits cleanly; produces no unwanted stdout under normal operation.
- **Importable as a module** – guarded by `if __name__ == "__main__"`.

---

## Requirements

| Requirement | Version |
|-------------|---------|
| OS          | Linux (systemd) |
| Python      | 3.10 or newer |
| psutil      | any recent release |

Install the only external dependency:

```bash
pip install psutil
```

---

## File Structure

```
sprint4/
├── healthmon.py          # Main monitoring script
├── config.json           # Threshold and path configuration
├── README.md             # This file
├── healthmon.log.example # Sample normal log output
├── alerts.log.example    # Sample alert log output
└── cron_example.txt      # Cron job setup instructions and examples
```

---

## Configuration

All thresholds and log file paths live in `config.json`. Edit this file
before running the script.

```json
{
    "checks": {
        "disk_usage_percent": 80,
        "memory_usage_percent": 90,
        "cpu_load_1min": 2.0,
        "services": [
            "sshd",
            "cron"
        ]
    },
    "log_file": "/home/ubuntu/healthmon.log",
    "alert_log": "/home/ubuntu/alerts.log"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `checks.disk_usage_percent` | number | Root filesystem usage % that triggers a disk alert |
| `checks.memory_usage_percent` | number | RAM usage % that triggers a memory alert |
| `checks.cpu_load_1min` | number | 1-minute load average that triggers a CPU alert |
| `checks.services` | list of strings | Systemd service names to verify are active |
| `log_file` | string | Absolute path for the normal monitoring log |
| `alert_log` | string | Absolute path for the dedicated alert log |

The script validates all fields at startup and exits with a non-zero code
and an error message if anything is missing, wrongly typed, or unparseable.

---

## Usage

### Standard monitoring pass

```bash
python3 healthmon.py config.json
```

Runs all checks once. Logs results to `log_file`. Writes any alerts to
`alert_log` and to syslog. Exits 0 on success.

### Monitoring pass with health summary

```bash
python3 healthmon.py config.json --check
```

Runs all checks and then logs a formatted summary table that shows each
metric's current value and OK/WARNING/FAILED status.

Example summary output (written to the log file and stderr):

```
========== SYSTEM HEALTH SUMMARY ==========
Disk Usage:   OK (42.5%)
Memory Usage: OK (64.4%)
CPU Load:     WARNING (3.91)
Service sshd: OK
Service cron: FAILED
===========================================
```

---

## Logging

Two separate log files are written:

| File | Content |
|------|---------|
| `log_file` | All INFO, WARNING, and ERROR messages from every run |
| `alert_log` | Only WARNING and ERROR alert messages |

Both use the format:

```
%(asctime)s - %(levelname)s - %(message)s
```

Alerts at WARNING or ERROR level are also forwarded to syslog (facility
`LOG_DAEMON`) via `logging.handlers.SysLogHandler`. View syslog entries with:

```bash
sudo journalctl -t healthmon
# or
sudo grep healthmon /var/log/syslog
```

---

## Testing Alerts

### Trigger a CPU alert

Install `stress-ng` and run a short load spike:

```bash
sudo apt-get install stress-ng   # Debian/Ubuntu
stress-ng --cpu 4 --timeout 30
```

While the load spike is running, lower the CPU threshold in `config.json`
temporarily (e.g. `"cpu_load_1min": 0.5`) and run:

```bash
python3 healthmon.py config.json --check
```

### Trigger a service alert

Stop the cron service, then run the health check:

```bash
sudo systemctl stop cron
python3 healthmon.py config.json --check
```

Remember to restart it afterward:

```bash
sudo systemctl start cron
```

### Trigger a disk alert

Lower `disk_usage_percent` in `config.json` below the current usage
percentage shown in `df -h /`.

### Trigger a memory alert

Lower `memory_usage_percent` in `config.json` below the current value
shown in `free -m`, or use `stress-ng --vm 1 --vm-bytes 80%`.

---

## Cron Automation

Open your crontab:

```bash
crontab -e
```

Add entries for scheduled monitoring. See `cron_example.txt` for full
examples. Minimal setup:

```cron
# Full check every 5 minutes
*/5 * * * * /usr/bin/python3 /home/ubuntu/sprint4/healthmon.py /home/ubuntu/sprint4/config.json >> /dev/null 2>&1

# Summary report every hour
0 * * * * /usr/bin/python3 /home/ubuntu/sprint4/healthmon.py /home/ubuntu/sprint4/config.json --check >> /dev/null 2>&1
```

Verify the entries are saved:

```bash
crontab -l
```

Monitor log output in real time:

```bash
tail -f /home/ubuntu/healthmon.log
```

---

## Example Output

### Normal run (no alerts)

```
2026-06-07 14:00:01 - INFO - Health monitoring started.
2026-06-07 14:00:01 - INFO - Disk usage: 42.3% (threshold: 80.0%)
2026-06-07 14:00:01 - INFO - Memory usage: 63.7% (threshold: 90.0%)
2026-06-07 14:00:01 - INFO - CPU load (1min): 1.32 (threshold: 2.00)
2026-06-07 14:00:01 - INFO - Service sshd: active
2026-06-07 14:00:01 - INFO - Service cron: active
2026-06-07 14:00:01 - INFO - Health monitoring complete. Overall status: ALL CLEAR.
```

### Run with CPU and service alerts

```
2026-06-07 14:15:01 - INFO - Health monitoring started.
2026-06-07 14:15:01 - INFO - Disk usage: 42.4% (threshold: 80.0%)
2026-06-07 14:15:01 - INFO - Memory usage: 67.8% (threshold: 90.0%)
2026-06-07 14:15:01 - WARNING - CPU ALERT:
Current load: 4.15
Threshold:    2.00
2026-06-07 14:15:01 - INFO - Service sshd: active
2026-06-07 14:15:01 - ERROR - SERVICE ALERT:
Service:  cron
Status:   inactive
Expected: active
2026-06-07 14:15:01 - INFO - Health monitoring complete. Overall status: ALERTS DETECTED.
```

### Corresponding alerts.log entries

```
2026-06-07 14:15:01 - WARNING - CPU ALERT:
Current load: 4.15
Threshold:    2.00

2026-06-07 14:15:01 - ERROR - SERVICE ALERT:
Service:  cron
Status:   inactive
Expected: active
```

---

## Error Handling

The script handles all failure modes gracefully and exits with a non-zero
code after logging a clear error message. No silent failures.

| Scenario | Behavior |
|----------|----------|
| Config file not found | `ERROR: Configuration file not found: <path>` → exit 1 |
| Config file is invalid JSON | `ERROR: Invalid JSON syntax in configuration file: <detail>` → exit 1 |
| Missing required config key | `ERROR: Missing required configuration field: <key>` → exit 1 |
| Threshold field is wrong type | `ERROR: Configuration field checks.<field> must be numeric` → exit 1 |
| Services list is empty | `ERROR: checks.services must be a non-empty list` → exit 1 |
| Log file not writable | `ERROR: Cannot open log file <path>: <detail>` → exit 1 |
| syslog not reachable | `WARNING: Cannot connect to syslog. Syslog alerts disabled.` → continues |
| systemctl not found | `ERROR: systemctl not found – service checks require a systemd Linux environment.` |
| systemctl times out | `ERROR: systemctl timed out after 10s checking service: <name>` |
