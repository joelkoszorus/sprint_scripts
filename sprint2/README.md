# sysinfo.py — Linux System Information Gatherer

## Description

`sysinfo.py` is a Python automation script that collects detailed system information from a local Linux server and outputs it in the format you choose. It demonstrates Python scripting skills relevant to security automation: gathering host telemetry, parsing system state, and producing structured output for use in reports, pipelines, or monitoring tools.

Supported output formats:

| Format | Behavior |
|--------|----------|
| `screen` | Prints a formatted, human-readable report to the terminal |
| `csv` | Writes all data to `sysinfo.csv` in the current directory |
| `json` | Writes all data to `sysinfo.json` in the current directory |

---

## Features

- Collects hostname, FQDN, OS name, OS version, kernel version, and architecture
- Reports CPU model, physical core count, logical CPU count, and live utilization
- Reports total, used, and available RAM with usage percentage
- Enumerates all mounted disk partitions with size, usage, and free space
- Reports the primary IP address and per-interface IPv4 and MAC addresses
- Calculates system uptime from boot time in a human-readable format
- Outputs data to the terminal, a CSV file, or a JSON file
- Works as both a standalone executable and an importable Python module
- Validates all command-line arguments and exits gracefully on invalid input
- Handles missing permissions and unavailable data without crashing

---

## Requirements

- **OS:** Ubuntu Server 24.04 (or any modern Linux distribution)
- **Python:** 3.10 or higher
- **Python modules:**
  - `psutil` (third-party — see Installation)
  - `os`, `sys`, `platform`, `subprocess`, `socket`, `json`, `csv`, `datetime`, `argparse` (all standard library)

---

## Installation

### 1. Update the system and install Python

```bash
sudo apt update
sudo apt install python3 python3-pip -y
```

### 2. Verify Python version

```bash
python3 --version
# Expected: Python 3.10.x or higher
```

### 3. Install psutil

```bash
pip install psutil
```

Or, for a system-wide installation:

```bash
sudo apt install python3-psutil
```

### 4. Download the script

Clone the repository or copy `sysinfo.py` into your working directory.

---

## Usage

```bash
python3 sysinfo.py <screen|csv|json>
```

### Print to the terminal

```bash
python3 sysinfo.py screen
```

### Save to a CSV file

```bash
python3 sysinfo.py csv
# Creates: sysinfo.csv
```

### Save to a JSON file

```bash
python3 sysinfo.py json
# Creates: sysinfo.json
```

---

## Example Outputs

### Screen output

```
===== SYSTEM INFORMATION =====
  Hostname         : server01
  FQDN             : server01.example.com
  OS               : Linux
  OS Version       : Ubuntu 24.04.1 LTS
  Kernel Version   : 6.8.0-51-generic
  Architecture     : x86_64

===== CPU INFORMATION =====
  CPU Model        : Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz
  Physical Cores   : 4
  Logical CPUs     : 8
  CPU Utilization  : 3.2%

===== MEMORY INFORMATION =====
  Total RAM        : 15.61 GB
  Used RAM         : 4.22 GB
  Available RAM    : 11.39 GB
  Memory Usage     : 27.0%

===== DISK INFORMATION =====
  Device           : /dev/sda1
  Mount Point      : /
  Total            : 49.09 GB
  Used             : 12.83 GB
  Free             : 33.76 GB
  Usage            : 27.6%

===== NETWORK INFORMATION =====
  Primary IP       : 192.168.1.105
  Interfaces:
    [eth0]
      IPv4 : 192.168.1.105
      MAC  : 52:54:00:ab:cd:ef
    [lo]
      IPv4 : 127.0.0.1
      MAC  : 00:00:00:00:00:00

===== UPTIME INFORMATION =====
  Boot Time        : 2026-05-01 08:14:32
  Uptime           : 7d 3h 45m
```

### CSV output (`sysinfo.csv`)

```
Category,Item,Value
System,Hostname,server01
System,Fqdn,server01.example.com
System,Os Name,Linux
System,Os Version,Ubuntu 24.04.1 LTS
System,Kernel Version,6.8.0-51-generic
System,Architecture,x86_64
CPU,Cpu Model,"Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz"
CPU,Physical Cores,4
CPU,Logical Cpus,8
CPU,Cpu Utilization,3.2%
Memory,Total Ram,15.61 GB
Memory,Used Ram,4.22 GB
Memory,Available Ram,11.39 GB
Memory,Memory Percent,27.0%
...
```

### JSON output (`sysinfo.json`)

```json
{
    "system": {
        "hostname": "server01",
        "fqdn": "server01.example.com",
        "os_name": "Linux",
        "os_version": "Ubuntu 24.04.1 LTS",
        "kernel_version": "6.8.0-51-generic",
        "architecture": "x86_64"
    },
    "cpu": {
        "cpu_model": "Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz",
        "physical_cores": 4,
        "logical_cpus": 8,
        "cpu_utilization": "3.2%"
    },
    "memory": {
        "total_ram": "15.61 GB",
        "used_ram": "4.22 GB",
        "available_ram": "11.39 GB",
        "memory_percent": "27.0%"
    },
    "disk": [
        {
            "device": "/dev/sda1",
            "mountpoint": "/",
            "total": "49.09 GB",
            "used": "12.83 GB",
            "free": "33.76 GB",
            "percent": "27.6%"
        }
    ],
    "network": {
        "primary_ip": "192.168.1.105",
        "interfaces": [
            {
                "interface": "eth0",
                "ipv4": "192.168.1.105",
                "mac": "52:54:00:ab:cd:ef"
            }
        ]
    },
    "uptime": {
        "boot_time": "2026-05-01 08:14:32",
        "uptime": "7d 3h 45m"
    }
}
```

---

## Project Structure

```
sprint2/
├── sysinfo.py       # Main script
├── README.md        # This file
├── sysinfo.csv      # Generated when run with 'csv' argument
└── sysinfo.json     # Generated when run with 'json' argument
```

---

## Using as an Importable Module

`sysinfo.py` can be imported without triggering execution:

```python
import sysinfo

data = sysinfo.collect_all()
print(data["system"]["hostname"])
print(data["cpu"]["logical_cpus"])
```

Individual collection functions are also importable:

```python
from sysinfo import get_memory_info, get_disk_info

mem = get_memory_info()
disks = get_disk_info()
```

---

## Error Handling

| Situation | Behavior |
|-----------|----------|
| No argument supplied | Prints usage message and exits with code 1 |
| Invalid argument (e.g., `xml`) | Prints usage message and exits with code 1 |
| Too many arguments | Prints usage message and exits with code 1 |
| `psutil` not installed | Prints installation instructions and exits with code 1 |
| Disk mount point not readable | Records `N/A` for that partition; continues |
| Network interface unavailable | Records `N/A` for missing fields; continues |
| File write permission denied | Prints a specific error message and exits with code 1 |

No Python tracebacks are displayed for expected user errors.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'psutil'`**

```bash
pip install psutil
```

If `pip` is not found:

```bash
sudo apt install python3-pip -y
pip install psutil
```

---

**`PermissionError` when reading disk or CPU info**

Run with `sudo` if accessing restricted system paths:

```bash
sudo python3 sysinfo.py screen
```

---

**CPU utilization always shows 0.0%**

The first call to `psutil.cpu_percent()` always returns `0.0` on some systems. The script uses `interval=1` to take a blocking one-second measurement, which should return an accurate value. If you still see `0.0%`, the system may genuinely be idle.

---

**FQDN shows the hostname instead of the full domain**

This is expected on systems that are not joined to a DNS domain. The hostname and FQDN will be identical in that case.

---

**Output files are saved in the wrong directory**

The script saves `sysinfo.csv` and `sysinfo.json` in the current working directory — wherever the terminal session is when the script is run. Navigate to the desired directory before running:

```bash
cd /path/to/project
python3 sysinfo.py csv
```
