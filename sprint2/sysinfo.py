#!/usr/bin/env python3
# System Information Gatherer for Security Analysis
# Joel Koszorus 05/6/2026

# Collects system, CPU, memory, disk, network, and uptime information from the
# local Linux machine and outputs results as terminal output, a CSV, or a JSON
# file depending on the argument passed at the command line.
#
# Usage:
#     python3 sysinfo.py <screen|csv|json>

import os
import sys
import platform
import subprocess
import socket
import json
import csv
import datetime
import argparse
from typing import Any, Dict, List

# Catch missing psutil early so the error message is helpful rather than a traceback.
try:
    import psutil
except ImportError:
    print("Error: Required module 'psutil' is not installed.")
    print("Install it with:  pip install psutil")
    print("Or system-wide:   sudo apt install python3-psutil")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _bytes_to_human(num_bytes: int) -> str:
    # Divide by 1024 repeatedly and step up the unit label until the value fits,
    # returning a two-decimal string such as '15.61 GB'.
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"


# ---------------------------------------------------------------------------
# Collection functions
# ---------------------------------------------------------------------------

def get_system_info() -> Dict[str, str]:
    # Returns hostname, FQDN, OS name, OS version, kernel release, and architecture.
    info: Dict[str, str] = {}

    info["hostname"] = socket.gethostname()

    try:
        info["fqdn"] = socket.getfqdn()
    except Exception:
        info["fqdn"] = "N/A"

    info["os_name"] = platform.system()

    # freedesktop_os_release() reads /etc/os-release for a clean version string
    # like "Ubuntu 24.04.1 LTS". Falls back to lsb_release, then platform.version().
    try:
        rel = platform.freedesktop_os_release()
        info["os_version"] = rel.get("PRETTY_NAME", platform.version())
    except (AttributeError, OSError):
        try:
            result = subprocess.run(
                ["lsb_release", "-d", "-s"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                info["os_version"] = result.stdout.strip().strip('"')
            else:
                info["os_version"] = platform.version()
        except Exception:
            info["os_version"] = platform.version()

    info["kernel_version"] = platform.release()
    info["architecture"] = platform.machine()

    return info


def get_cpu_info() -> Dict[str, Any]:
    # Returns CPU model name, physical core count, logical CPU count, and live utilization.
    info: Dict[str, Any] = {}

    # Read /proc/cpuinfo for the human-readable model name; psutil does not expose it.
    cpu_model = "N/A"
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("model name"):
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    except (FileNotFoundError, PermissionError):
        cpu_model = platform.processor() or "N/A"

    info["cpu_model"] = cpu_model
    info["physical_cores"] = psutil.cpu_count(logical=False) or "N/A"
    info["logical_cpus"] = psutil.cpu_count(logical=True) or "N/A"

    try:
        # interval=1 takes a one-second blocking sample for an accurate reading.
        info["cpu_utilization"] = f"{psutil.cpu_percent(interval=1)}%"
    except Exception:
        info["cpu_utilization"] = "N/A"

    return info


def get_memory_info() -> Dict[str, str]:
    # Returns total, used, and available RAM plus usage percentage via psutil.virtual_memory().
    info: Dict[str, str] = {}

    try:
        mem = psutil.virtual_memory()
        info["total_ram"] = _bytes_to_human(mem.total)
        info["used_ram"] = _bytes_to_human(mem.used)
        # available includes reclaimable cache, making it more useful than mem.free.
        info["available_ram"] = _bytes_to_human(mem.available)
        info["memory_percent"] = f"{mem.percent}%"
    except Exception:
        info["total_ram"] = "N/A"
        info["used_ram"] = "N/A"
        info["available_ram"] = "N/A"
        info["memory_percent"] = "N/A"

    return info


def get_disk_info() -> List[Dict[str, str]]:
    # Returns a list of dicts for each real mounted partition (all=False skips
    # pseudo-filesystems like tmpfs), with device, mountpoint, sizes, and usage.
    disks: List[Dict[str, str]] = []

    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception:
        return disks

    for part in partitions:
        # Pre-populate N/A so the entry is still included if the mountpoint is unreadable.
        entry: Dict[str, str] = {
            "device": part.device,
            "mountpoint": part.mountpoint,
            "total": "N/A",
            "used": "N/A",
            "free": "N/A",
            "percent": "N/A",
        }
        try:
            usage = psutil.disk_usage(part.mountpoint)
            entry["total"] = _bytes_to_human(usage.total)
            entry["used"] = _bytes_to_human(usage.used)
            entry["free"] = _bytes_to_human(usage.free)
            entry["percent"] = f"{usage.percent}%"
        except PermissionError:
            pass  # Mount point not accessible; leave values as N/A.
        disks.append(entry)

    return disks


def get_network_info() -> Dict[str, Any]:
    # Returns the primary outbound IP plus IPv4 and MAC for every network interface.
    info: Dict[str, Any] = {}

    # Connecting a UDP socket sets routing context without sending any packets,
    # revealing which local address the OS would use to reach the internet.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        info["primary_ip"] = sock.getsockname()[0]
        sock.close()
    except Exception:
        try:
            info["primary_ip"] = socket.gethostbyname(socket.gethostname())
        except Exception:
            info["primary_ip"] = "127.0.0.1"

    interfaces: List[Dict[str, str]] = []
    try:
        addrs = psutil.net_if_addrs()
        for iface_name, addr_list in addrs.items():
            entry: Dict[str, str] = {
                "interface": iface_name,
                "ipv4": "N/A",
                "mac": "N/A",
            }
            for addr in addr_list:
                # psutil.AF_LINK is the cross-platform family for MAC addresses.
                if addr.family == psutil.AF_LINK:
                    entry["mac"] = addr.address
                elif addr.family == socket.AF_INET:
                    entry["ipv4"] = addr.address
            interfaces.append(entry)
    except Exception:
        pass

    info["interfaces"] = interfaces
    return info


def get_uptime_info() -> Dict[str, str]:
    # Returns the boot timestamp and elapsed uptime broken into days, hours, and minutes.
    info: Dict[str, str] = {}

    try:
        boot_ts = psutil.boot_time()
        boot_dt = datetime.datetime.fromtimestamp(boot_ts)
        info["boot_time"] = boot_dt.strftime("%Y-%m-%d %H:%M:%S")

        # Integer division and modulo avoid double-counting between units.
        delta = datetime.datetime.now() - boot_dt
        total_seconds = int(delta.total_seconds())
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        info["uptime"] = f"{days}d {hours}h {minutes}m"
    except Exception:
        info["boot_time"] = "N/A"
        info["uptime"] = "N/A"

    return info


def collect_all() -> Dict[str, Any]:
    # Calls all six collection functions and merges results into a single dict
    # so every output function works from one shared data structure.
    return {
        "system": get_system_info(),
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "disk": get_disk_info(),
        "network": get_network_info(),
        "uptime": get_uptime_info(),
    }


# ---------------------------------------------------------------------------
# Output functions
# ---------------------------------------------------------------------------

def _header(title: str) -> None:
    # Prints a section divider in the "===== TITLE =====" style.
    print(f"\n===== {title} =====")


def display_to_screen(data: Dict[str, Any]) -> None:
    # Prints each category as a labeled, aligned block. Disk and interface
    # entries are looped since there may be more than one of each.
    sys_info = data["system"]
    _header("SYSTEM INFORMATION")
    print(f"  Hostname         : {sys_info.get('hostname', 'N/A')}")
    print(f"  FQDN             : {sys_info.get('fqdn', 'N/A')}")
    print(f"  OS               : {sys_info.get('os_name', 'N/A')}")
    print(f"  OS Version       : {sys_info.get('os_version', 'N/A')}")
    print(f"  Kernel Version   : {sys_info.get('kernel_version', 'N/A')}")
    print(f"  Architecture     : {sys_info.get('architecture', 'N/A')}")

    cpu_info = data["cpu"]
    _header("CPU INFORMATION")
    print(f"  CPU Model        : {cpu_info.get('cpu_model', 'N/A')}")
    print(f"  Physical Cores   : {cpu_info.get('physical_cores', 'N/A')}")
    print(f"  Logical CPUs     : {cpu_info.get('logical_cpus', 'N/A')}")
    print(f"  CPU Utilization  : {cpu_info.get('cpu_utilization', 'N/A')}")

    mem_info = data["memory"]
    _header("MEMORY INFORMATION")
    print(f"  Total RAM        : {mem_info.get('total_ram', 'N/A')}")
    print(f"  Used RAM         : {mem_info.get('used_ram', 'N/A')}")
    print(f"  Available RAM    : {mem_info.get('available_ram', 'N/A')}")
    print(f"  Memory Usage     : {mem_info.get('memory_percent', 'N/A')}")

    _header("DISK INFORMATION")
    disks = data["disk"]
    if disks:
        for disk in disks:
            print(f"  Device           : {disk.get('device', 'N/A')}")
            print(f"  Mount Point      : {disk.get('mountpoint', 'N/A')}")
            print(f"  Total            : {disk.get('total', 'N/A')}")
            print(f"  Used             : {disk.get('used', 'N/A')}")
            print(f"  Free             : {disk.get('free', 'N/A')}")
            print(f"  Usage            : {disk.get('percent', 'N/A')}")
            print()
    else:
        print("  No disk information available.")

    net_info = data["network"]
    _header("NETWORK INFORMATION")
    print(f"  Primary IP       : {net_info.get('primary_ip', 'N/A')}")
    interfaces = net_info.get("interfaces", [])
    if interfaces:
        print("  Interfaces:")
        for iface in interfaces:
            print(f"    [{iface.get('interface', 'N/A')}]")
            print(f"      IPv4 : {iface.get('ipv4', 'N/A')}")
            print(f"      MAC  : {iface.get('mac', 'N/A')}")
    else:
        print("  No interface information available.")

    up_info = data["uptime"]
    _header("UPTIME INFORMATION")
    print(f"  Boot Time        : {up_info.get('boot_time', 'N/A')}")
    print(f"  Uptime           : {up_info.get('uptime', 'N/A')}")
    print()


def write_csv(data: Dict[str, Any], filepath: str = "sysinfo.csv") -> None:
    # Flattens the nested data dict into a three-column CSV (Category, Item, Value).
    # Disk entries are labeled "Disk N (mountpoint)" to distinguish multiple partitions.
    rows: List[List[str]] = []

    for key, val in data["system"].items():
        rows.append(["System", key.replace("_", " ").title(), str(val)])

    for key, val in data["cpu"].items():
        rows.append(["CPU", key.replace("_", " ").title(), str(val)])

    for key, val in data["memory"].items():
        rows.append(["Memory", key.replace("_", " ").title(), str(val)])

    for i, disk in enumerate(data["disk"], start=1):
        label = f"Disk {i} ({disk.get('mountpoint', '?')})"
        for key, val in disk.items():
            if key != "mountpoint":
                rows.append([label, key.replace("_", " ").title(), str(val)])
            else:
                rows.append([label, "Mount Point", str(val)])

    rows.append(["Network", "Primary IP", data["network"].get("primary_ip", "N/A")])
    for iface in data["network"].get("interfaces", []):
        name = iface.get("interface", "N/A")
        rows.append(["Network", f"{name} IPv4", iface.get("ipv4", "N/A")])
        rows.append(["Network", f"{name} MAC", iface.get("mac", "N/A")])

    for key, val in data["uptime"].items():
        rows.append(["Uptime", key.replace("_", " ").title(), str(val)])

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Category", "Item", "Value"])
            writer.writerows(rows)
        print(f"CSV report saved to: {os.path.abspath(filepath)}")
    except IOError as exc:
        print(f"Error: Could not write '{filepath}': {exc}", file=sys.stderr)
        sys.exit(1)


def write_json(data: Dict[str, Any], filepath: str = "sysinfo.json") -> None:
    # Serializes the data dict to a pretty-printed JSON file (indent=4).
    # The nested structure is preserved, making it easy to parse with jq or json.load().
    try:
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=4)
        print(f"JSON report saved to: {os.path.abspath(filepath)}")
    except IOError as exc:
        print(f"Error: Could not write '{filepath}': {exc}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    # Parses exactly one argument (screen | csv | json) and dispatches to the
    # matching output function. argparse handles invalid input automatically.
    parser = argparse.ArgumentParser(
        prog="sysinfo.py",
        description="Gather and report Linux system information.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 sysinfo.py screen\n"
            "  python3 sysinfo.py csv\n"
            "  python3 sysinfo.py json\n"
        ),
    )
    parser.add_argument(
        "output_format",
        choices=["screen", "csv", "json"],
        metavar="<screen|csv|json>",
        help="Output format: 'screen' prints to terminal, 'csv' saves sysinfo.csv, 'json' saves sysinfo.json",
    )

    args = parser.parse_args()
    data = collect_all()

    if args.output_format == "screen":
        display_to_screen(data)
    elif args.output_format == "csv":
        write_csv(data)
    elif args.output_format == "json":
        write_json(data)


if __name__ == "__main__":
    main()
