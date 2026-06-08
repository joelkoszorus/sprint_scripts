#!/usr/bin/env python3
# Health Monitoring Tool
# Joel Koszorus 06/07/2026
#
# Usage:
#    python3 healthmon.py config.json
#    python3 healthmon.py config.json --check

import argparse
import json
import logging
import logging.handlers
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import psutil


# Internal constants – nothing threshold-related lives here

_LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_SYSLOG_SOCKET = "/dev/log"          # standard Linux syslog socket path
_SYSLOG_FACILITY = logging.handlers.SysLogHandler.LOG_DAEMON
_SYSTEMCTL_TIMEOUT = 10              # seconds before giving up on systemctl


# Configuration

# Load and validate config.json. Exits on missing file, bad JSON, or missing/wrong-typed keys.
def load_config(config_path: str) -> dict[str, Any]:
    path = Path(config_path)

    if not path.exists():
        logging.error("Configuration file not found: %s", config_path)
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8") as fh:
            config = json.load(fh)
    except json.JSONDecodeError as exc:
        logging.error("Invalid JSON syntax in configuration file: %s", exc)
        sys.exit(1)
    except OSError as exc:
        logging.error("Cannot read configuration file: %s", exc)
        sys.exit(1)

    # Top-level required keys
    for key in ("checks", "log_file", "alert_log"):
        if key not in config:
            logging.error("Missing required configuration field: %s", key)
            sys.exit(1)

    checks = config["checks"]

    # Numeric threshold sub-keys
    for field in ("disk_usage_percent", "memory_usage_percent", "cpu_load_1min"):
        if field not in checks:
            logging.error("Missing required configuration field: checks.%s", field)
            sys.exit(1)
        if not isinstance(checks[field], (int, float)):
            logging.error(
                "Configuration field checks.%s must be numeric, got %s.",
                field,
                type(checks[field]).__name__,
            )
            sys.exit(1)

    # Service list
    if "services" not in checks:
        logging.error("Missing required configuration field: checks.services")
        sys.exit(1)
    if not isinstance(checks["services"], list) or not checks["services"]:
        logging.error(
            "Configuration field checks.services must be a non-empty list."
        )
        sys.exit(1)

    # Expand ~ so paths like "~/healthmon.log" work for any user
    config["log_file"] = os.path.expanduser(config["log_file"])
    config["alert_log"] = os.path.expanduser(config["alert_log"])

    return config


# Logging setup

# Set up file, stderr, and syslog handlers. Returns (main_logger, alert_logger).
# main_logger: INFO+ → log_file + stderr, WARNING+ → syslog.
# alert_logger: WARNING+ → alert_log + stderr only (no double-write to main file).
def setup_logging(
    config: dict[str, Any]
) -> tuple[logging.Logger, logging.Logger]:
    log_file = config["log_file"]
    alert_log = config["alert_log"]
    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    # ------------------------------------------------------------------
    # Main logger
    # ------------------------------------------------------------------
    main_logger = logging.getLogger("healthmon")
    main_logger.setLevel(logging.DEBUG)

    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)
        fh.setFormatter(formatter)
        main_logger.addHandler(fh)
    except OSError as exc:
        # Can't write the log file – surface the error and exit cleanly.
        logging.basicConfig(level=logging.ERROR, format=_LOG_FORMAT, datefmt=_DATE_FORMAT)
        logging.error("Cannot open log file %s: %s", log_file, exc)
        sys.exit(1)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.INFO)
    stderr_handler.setFormatter(formatter)
    main_logger.addHandler(stderr_handler)

    # Syslog – WARNING and above only
    try:
        if os.path.exists(_SYSLOG_SOCKET):
            syslog_handler = logging.handlers.SysLogHandler(
                address=_SYSLOG_SOCKET,
                facility=_SYSLOG_FACILITY,
            )
        else:
            # Fallback for environments without /dev/log (containers, macOS)
            syslog_handler = logging.handlers.SysLogHandler(
                address=("localhost", 514),
                facility=_SYSLOG_FACILITY,
            )
        syslog_handler.setLevel(logging.WARNING)
        syslog_handler.setFormatter(
            logging.Formatter("healthmon: " + _LOG_FORMAT, datefmt=_DATE_FORMAT)
        )
        main_logger.addHandler(syslog_handler)
    except OSError as exc:
        main_logger.warning(
            "Cannot connect to syslog (%s). Syslog alerts disabled.", exc
        )

    # Alert logger – dedicated file, no propagation to main logger
    alert_logger = logging.getLogger("healthmon.alerts")
    alert_logger.setLevel(logging.WARNING)
    alert_logger.propagate = False

    try:
        Path(alert_log).parent.mkdir(parents=True, exist_ok=True)
        ah = logging.FileHandler(alert_log)
        ah.setLevel(logging.WARNING)
        ah.setFormatter(formatter)
        alert_logger.addHandler(ah)
    except OSError as exc:
        main_logger.error("Cannot open alert log %s: %s", alert_log, exc)
        sys.exit(1)

    # Mirror alerts to stderr so they are visible during interactive runs
    alert_logger.addHandler(stderr_handler)

    return main_logger, alert_logger


# Alert helper

# Write an alert to the main log (→ syslog via SysLogHandler) and the dedicated alert log.
def send_alert(
    main_logger: logging.Logger,
    alert_logger: logging.Logger,
    level: int,
    message: str,
) -> None:
    main_logger.log(level, message)
    alert_logger.log(level, message)


# Health checks

# Check root disk usage via shutil.disk_usage("/"). Returns (percent, is_ok).
def check_disk(
    config: dict[str, Any],
    main_logger: logging.Logger,
    alert_logger: logging.Logger,
) -> tuple[float, bool]:
    threshold: float = config["checks"]["disk_usage_percent"]
    usage = shutil.disk_usage("/")
    percent = (usage.used / usage.total) * 100.0

    if percent >= threshold:
        msg = (
            f"DISK ALERT:\n"
            f"Current usage: {percent:.1f}%\n"
            f"Threshold:     {threshold:.1f}%"
        )
        send_alert(main_logger, alert_logger, logging.WARNING, msg)
        return percent, False

    main_logger.info(
        "Disk usage: %.1f%% (threshold: %.1f%%)", percent, threshold
    )
    return percent, True


# Check RAM usage via psutil.virtual_memory().percent. Returns (percent, is_ok).
def check_memory(
    config: dict[str, Any],
    main_logger: logging.Logger,
    alert_logger: logging.Logger,
) -> tuple[float, bool]:
    threshold: float = config["checks"]["memory_usage_percent"]
    memory = psutil.virtual_memory()
    percent: float = memory.percent

    if percent >= threshold:
        msg = (
            f"MEMORY ALERT:\n"
            f"Current usage: {percent:.1f}%\n"
            f"Threshold:     {threshold:.1f}%"
        )
        send_alert(main_logger, alert_logger, logging.WARNING, msg)
        return percent, False

    main_logger.info(
        "Memory usage: %.1f%% (threshold: %.1f%%)", percent, threshold
    )
    return percent, True


# Check 1-min CPU load average via os.getloadavg(). Returns (load_1min, is_ok).
def check_cpu(
    config: dict[str, Any],
    main_logger: logging.Logger,
    alert_logger: logging.Logger,
) -> tuple[float, bool]:
    threshold: float = config["checks"]["cpu_load_1min"]

    getloadavg = getattr(os, "getloadavg", None)
    if getloadavg is None:
        main_logger.error("os.getloadavg() is not available on this platform. CPU check requires Linux.")
        return 0.0, True
    load_1min: float = getloadavg()[0]

    if load_1min >= threshold:
        msg = (
            f"CPU ALERT:\n"
            f"Current load: {load_1min:.2f}\n"
            f"Threshold:    {threshold:.2f}"
        )
        send_alert(main_logger, alert_logger, logging.WARNING, msg)
        return load_1min, False

    main_logger.info(
        "CPU load (1min): %.2f (threshold: %.2f)", load_1min, threshold
    )
    return load_1min, True


# Check each configured service via `systemctl is-active`. Returns {service: is_active}.
# Any status other than "active" triggers an alert.
def check_services(
    config: dict[str, Any],
    main_logger: logging.Logger,
    alert_logger: logging.Logger,
) -> dict[str, bool]:
    services: list[str] = config["checks"]["services"]
    results: dict[str, bool] = {}

    for service in services:
        status = _query_service_status(service, main_logger)
        is_active = status == "active"

        if is_active:
            main_logger.info("Service %s: active", service)
        else:
            msg = (
                f"SERVICE ALERT:\n"
                f"Service:  {service}\n"
                f"Status:   {status if status else 'unknown'}\n"
                f"Expected: active"
            )
            send_alert(main_logger, alert_logger, logging.ERROR, msg)

        results[service] = is_active

    return results


# Run `systemctl is-active <service>` and return trimmed stdout, or "" on failure.
def _query_service_status(service: str, main_logger: logging.Logger) -> str:
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True,
            text=True,
            timeout=_SYSTEMCTL_TIMEOUT,
        )
        return proc.stdout.strip()
    except FileNotFoundError:
        main_logger.error(
            "systemctl not found – service checks require a systemd Linux environment."
        )
    except subprocess.TimeoutExpired:
        main_logger.error(
            "systemctl timed out after %ds checking service: %s",
            _SYSTEMCTL_TIMEOUT,
            service,
        )
    except OSError as exc:
        main_logger.error(
            "Cannot execute systemctl for service %s: %s", service, exc
        )

    return ""


# Summary report

# Log the formatted --check health summary table via main_logger at INFO level.
def generate_summary(
    main_logger: logging.Logger,
    disk_pct: float,
    disk_ok: bool,
    mem_pct: float,
    mem_ok: bool,
    cpu_load: float,
    cpu_ok: bool,
    service_results: dict[str, bool],
) -> None:
    lines: list[str] = [
        "========== SYSTEM HEALTH SUMMARY ==========",
        f"Disk Usage:   {'OK' if disk_ok else 'WARNING'} ({disk_pct:.1f}%)",
        f"Memory Usage: {'OK' if mem_ok else 'WARNING'} ({mem_pct:.1f}%)",
        f"CPU Load:     {'OK' if cpu_ok else 'WARNING'} ({cpu_load:.2f})",
    ]
    for svc, active in service_results.items():
        lines.append(f"Service {svc}: {'OK' if active else 'FAILED'}")
    lines.append("===========================================")

    for line in lines:
        main_logger.info(line)


# Entry point


# Parse args, load config, run all checks, and optionally emit the --check summary.
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="healthmon.py",
        description="Linux system health monitoring utility.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 healthmon.py config.json\n"
            "  python3 healthmon.py config.json --check\n"
        ),
    )
    parser.add_argument(
        "config",
        help="Path to the JSON configuration file.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Print a formatted health summary after running all checks.",
    )
    args = parser.parse_args()

    # Minimal bootstrap logger so config errors are visible before the full
    # logging stack is initialised.
    logging.basicConfig(
        level=logging.ERROR,
        format=_LOG_FORMAT,
        datefmt=_DATE_FORMAT,
        stream=sys.stderr,
    )

    config = load_config(args.config)
    main_logger, alert_logger = setup_logging(config)

    main_logger.info("Health monitoring started.")

    disk_pct, disk_ok = check_disk(config, main_logger, alert_logger)
    mem_pct, mem_ok = check_memory(config, main_logger, alert_logger)
    cpu_load, cpu_ok = check_cpu(config, main_logger, alert_logger)
    service_results = check_services(config, main_logger, alert_logger)

    if args.check:
        generate_summary(
            main_logger,
            disk_pct, disk_ok,
            mem_pct, mem_ok,
            cpu_load, cpu_ok,
            service_results,
        )

    all_ok = disk_ok and mem_ok and cpu_ok and all(service_results.values())
    main_logger.info(
        "Health monitoring complete. Overall status: %s.",
        "ALL CLEAR" if all_ok else "ALERTS DETECTED",
    )


if __name__ == "__main__":
    main()
