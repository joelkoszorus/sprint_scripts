#!/usr/bin/env python3
# Network Reconnaissance Tool
# Joel Koszorus 05/24/2026
#
# Usage: 
#     python3 netrecon.py <target_ip> <output_csv> [--remote <ssh_host>]

import argparse
import csv
import getpass
import ipaddress
import logging
import socket
import sys
from typing import Optional

import requests

# Optional imports with clear user-facing errors 
try:
    import nmap
except ImportError:
    sys.exit("[ERROR] python-nmap is not installed. Run: pip install python-nmap")

try:
    import paramiko
except ImportError:
    paramiko = None

# Constants 
GEO_API_URL = "http://ip-api.com/json/{ip}"
GEO_TIMEOUT = 10          # seconds
NMAP_ARGS = "-sV -Pn"
SSH_PORT = 22
CSV_FIELDS = ["target_ip", "country", "region", "city", "isp", "port", "service", "state"]
DEFAULT_OUTPUT = "output.txt"

# Logging setup with INFO level and simple formatting
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
log = logging.getLogger(__name__)


# Input validation 

def validate_ip(ip: str) -> str:
    """Return the IP string if valid, otherwise exit with an error."""
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        # Accept hostnames too — resolve them so the rest of the script
        # always works with a numeric IP.
        try:
            resolved = socket.gethostbyname(ip)
            log.info("Resolved %s → %s", ip, resolved)
            return resolved
        except socket.gaierror:
            sys.exit(f"[ERROR] '{ip}' is not a valid IP address or resolvable hostname.")


# Geolocation

def get_geolocation(ip: str) -> dict:
    """
    Query ip-api.com for geolocation data.
    Returns a dict with keys: country, region, city, isp.
    Falls back to empty strings on any failure.
    """
    empty = {"country": "", "region": "", "city": "", "isp": ""}

    # Private / reserved ranges won't resolve via the public API.
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved:
            log.warning("IP %s is non-routable; skipping geolocation lookup.", ip)
            return empty
    except ValueError:
        return empty

    url = GEO_API_URL.format(ip=ip)
    try:
        resp = requests.get(url, timeout=GEO_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        log.error("Geolocation API timed out after %d seconds.", GEO_TIMEOUT)
        return empty
    except requests.exceptions.ConnectionError:
        log.error("Could not reach geolocation API. Check your network connection.")
        return empty
    except requests.exceptions.HTTPError as exc:
        log.error("Geolocation API returned an error: %s", exc)
        return empty
    except ValueError:
        log.error("Geolocation API returned invalid JSON.")
        return empty

    if data.get("status") != "success":
        log.warning("Geolocation lookup failed: %s", data.get("message", "unknown reason"))
        return empty

    return {
        "country": data.get("country", ""),
        "region":  data.get("regionName", ""),
        "city":    data.get("city", ""),
        "isp":     data.get("isp", ""),
    }


# Local Nmap scan

def run_local_scan(target: str) -> list[dict]:
    """
    Run an Nmap scan locally and return a list of open-port dicts.
    Each dict has keys: port, service, state.
    """
    try:
        scanner = nmap.PortScanner()
    except nmap.PortScannerError:
        sys.exit("[ERROR] Nmap executable not found. Install nmap and ensure it is in PATH.")

    log.info("Starting local Nmap scan on %s …", target)
    try:
        scanner.scan(hosts=target, arguments=NMAP_ARGS)
    except nmap.PortScannerError as exc:
        sys.exit(f"[ERROR] Nmap scan failed: {exc}")
    except PermissionError:
        sys.exit("[ERROR] Insufficient permissions to run Nmap. Try running with sudo/Administrator.")

    return _parse_nmap_scanner(scanner, target)


def _parse_nmap_scanner(scanner: nmap.PortScanner, target: str) -> list[dict]:
    """Extract open ports from a completed PortScanner object."""
    open_ports: list[dict] = []

    if target not in scanner.all_hosts():
        log.warning("Host %s did not respond or returned no results.", target)
        return open_ports

    host_data = scanner[target]

    for protocol in host_data.all_protocols():
        ports = host_data[protocol].keys()
        for port in sorted(ports):
            port_info = host_data[protocol][port]
            if port_info.get("state") == "open":
                open_ports.append({
                    "port":    f"{port}/{protocol}",
                    "service": port_info.get("name", "unknown"),
                    "state":   port_info.get("state", ""),
                })

    return open_ports


# Remote SSH scan

def run_remote_scan(target: str, ssh_host: str) -> list[dict]:   
    if paramiko is None:
        sys.exit("[ERROR] Paramiko is not installed. Run: pip install paramiko")

    print(f"\nSSH credentials for {ssh_host}:")
    username = input("  Username: ").strip()
    password = getpass.getpass("  Password: ")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=ssh_host,
            port=SSH_PORT,
            username=username,
            password=password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException:
        sys.exit("[ERROR] SSH authentication failed. Check your username and password.")
    except paramiko.SSHException as exc:
        sys.exit(f"[ERROR] SSH connection error: {exc}")
    except socket.timeout:
        sys.exit(f"[ERROR] SSH connection to {ssh_host} timed out.")
    except OSError as exc:
        sys.exit(f"[ERROR] Could not reach SSH host {ssh_host}: {exc}")

    cmd = f"nmap {NMAP_ARGS} {target}"
    log.info("Running remote scan: %s", cmd)

    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=120)
        output = stdout.read().decode("utf-8", errors="replace")
        err    = stderr.read().decode("utf-8", errors="replace")
    except paramiko.SSHException as exc:
        client.close()
        sys.exit(f"[ERROR] Remote command execution failed: {exc}")
    finally:
        client.close()

    if err.strip():
        log.warning("Nmap stderr: %s", err.strip())

    return _parse_nmap_text(output, target)


def _parse_nmap_text(output: str, target: str) -> list[dict]:
    
    open_ports: list[dict] = []

    for line in output.splitlines():
        line = line.strip()
        # Nmap port lines look like: "22/tcp   open  ssh"
        parts = line.split()
        if len(parts) >= 3 and "/" in parts[0] and parts[1] == "open":
            open_ports.append({
                "port":    parts[0],
                "service": parts[2] if len(parts) > 2 else "unknown",
                "state":   "open",
            })

    if not open_ports:
        log.warning("No open ports detected in remote scan output.")

    return open_ports


# CSV writer

def write_csv(
    output_path: str,
    target: str,
    geo: dict,
    ports: list[dict],
) -> None:
    rows = []

    if ports:
        for p in ports:
            rows.append({
                "target_ip": target,
                "country":   geo["country"],
                "region":    geo["region"],
                "city":      geo["city"],
                "isp":       geo["isp"],
                "port":      p["port"],
                "service":   p["service"],
                "state":     p["state"],
            })
    else:
        # Still write one row with geo data even if no open ports were found.
        rows.append({
            "target_ip": target,
            "country":   geo["country"],
            "region":    geo["region"],
            "city":      geo["city"],
            "isp":       geo["isp"],
            "port":      "",
            "service":   "",
            "state":     "no open ports",
        })

    try:
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    except PermissionError:
        sys.exit(f"[ERROR] Cannot write to '{output_path}'. Check file permissions.")
    except OSError as exc:
        sys.exit(f"[ERROR] Failed to write CSV: {exc}")

    log.info("CSV written to %s", output_path)


# Console summary 

def print_summary(
    target: str,
    geo: dict,
    ports: list[dict],
) -> None:
    print("\n" + "=" * 40)
    print("        NetRecon Scan Summary")
    print("=" * 40)
    print(f"\nTarget: {target}\n")

    print("Location:")
    print(f"  Country : {geo['country'] or 'N/A'}")
    print(f"  Region  : {geo['region']  or 'N/A'}")
    print(f"  City    : {geo['city']    or 'N/A'}")
    print(f"  ISP     : {geo['isp']     or 'N/A'}")

    print("\nOpen Ports:")
    if ports:
        for p in ports:
            print(f"  {p['port']:<15} {p['service']:<12} {p['state']}")
    else:
        print("  (none detected)")

    print("\n" + "=" * 40 + "\n")


# CLI

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netrecon.py",
        description="Network reconnaissance: port scan + geolocation → CSV report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 netrecon.py 192.168.1.10 results.csv\n"
            "  python3 netrecon.py 192.168.1.10 results.csv --remote 192.168.1.20\n"
        ),
    )
    parser.add_argument("target_ip",  help="Target IP address or hostname to scan.")
    parser.add_argument(
        "output_csv",
        nargs="?",
        default=DEFAULT_OUTPUT,
        help=f"Path for the CSV output file (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--remote",
        metavar="SSH_HOST",
        help="Run the Nmap scan from a remote SSH host instead of locally.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    target = validate_ip(args.target_ip)

    # Geolocation (always local regardless of --remote)
    log.info("Fetching geolocation for %s …", target)
    geo = get_geolocation(target)

    # Port scan — local or remote
    if args.remote:
        ssh_host = validate_ip(args.remote)
        ports = run_remote_scan(target, ssh_host)
    else:
        ports = run_local_scan(target)

    write_csv(args.output_csv, target, geo, ports)
    print_summary(target, geo, ports)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user (Ctrl+C). Exiting.")
        sys.exit(0)
