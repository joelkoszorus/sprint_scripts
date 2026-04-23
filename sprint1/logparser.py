#!/usr/bin/python3
# Log Parser for Security Analysis
# Joel Koszorus 04/22/2026

# import statements
import argparse
import re
import csv
import sys
import os

# constants

# Regex to match failed SSH login attempts in Linux auth.log.
#
# Handles both formats:
#   Failed password for admin from 142.146.24.37 port 16271 ssh2
#   Failed password for invalid user test from 10.0.0.1 port 12345 ssh2
#
# The "invalid user" prefix is optional — the non-capturing group (?:invalid user\s+)?
# absorbs it when present so the username group still lands in group 2.
FAILED_LOGIN_PATTERN = re.compile(
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"  # Group 1 — timestamp: "Apr 14 00:28:06"
    r"\s+\S+"                                    # hostname (not captured)
    r"\s+sshd\[\d+\]:\s+"                       # sshd process tag, e.g. sshd[1006]:
    r"Failed password for\s+"                    # literal failure notice
    r"(?:invalid user\s+)?"                      # optional "invalid user" prefix
    r"(\S+)"                                     # Group 2 — username
    r"\s+from\s+"                                # separator
    r"((?:\d{1,3}\.){3}\d{1,3})"               # Group 3 — IPv4 address only
)

# Column widths for the terminal output table
COL_TIMESTAMP = 20
COL_USERNAME  = 16
COL_SOURCE_IP = 16

# CSV field names — also used as the header row
CSV_HEADER = ["timestamp", "username", "source_ip"]


# functions

def parse_arguments():
    """Parse command-line arguments and return the result.

    argparse handles the usage message automatically, so the user
    sees a friendly error instead of a Python traceback when they
    forget an argument.
    """
    parser = argparse.ArgumentParser(
        description="Extract failed SSH login attempts from a Linux auth.log file.",
        usage="%(prog)s <logfile> <output.csv>",
    )
    parser.add_argument("logfile", help="Path to the auth.log file to analyze")
    parser.add_argument("output",  help="Destination path for the CSV report")
    return parser.parse_args()


def validate_file(path):
    """Confirm the log file exists and is readable before we try to open it.

    Exits with a clear message on failure so the user knows exactly
    what went wrong rather than seeing a raw Python exception.

    Args:
        path: String filesystem path to check.
    """
    if not os.path.exists(path):
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)

    if not os.path.isfile(path):
        print(f"[ERROR] Path is not a regular file: {path}")
        sys.exit(1)

    if not os.access(path, os.R_OK):
        # This can happen if the file exists but permissions block us
        print(f"[ERROR] Permission denied — cannot read: {path}")
        sys.exit(1)


def extract_failed_logins(logfile_path):
    """Read the log file line by line and collect every failed SSH login record.

    Applies FAILED_LOGIN_PATTERN to each line. Lines that don't match
    (successful logins, cron entries, etc.) are silently skipped — we
    only care about the failures.

    Args:
        logfile_path: String path to the auth.log file.

    Returns:
        A list of dicts, each containing 'timestamp', 'username', 'source_ip'.
    """
    records = []

    try:
        # errors="replace" keeps us moving if a line has unexpected encoding
        with open(logfile_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                match = FAILED_LOGIN_PATTERN.search(line)
                if match:
                    records.append({
                        "timestamp": match.group(1),  # raw string — not normalized
                        "username":  match.group(2),
                        "source_ip": match.group(3),
                    })
    except OSError as e:
        # Catches any IO/permission issues that slipped past validate_file
        print(f"[ERROR] Could not read file: {e}")
        sys.exit(1)

    return records


def write_to_csv(records, output_path):
    """Write the extracted login records to a CSV file with a header row.

    Args:
        records:     List of dicts from extract_failed_logins().
        output_path: String path where the CSV will be written.
    """
    try:
        # newline="" is required by the csv module to prevent extra blank rows on Windows
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADER)
            writer.writeheader()   # writes: timestamp,username,source_ip
            writer.writerows(records)
    except OSError as e:
        print(f"[ERROR] Could not write CSV: {e}")
        sys.exit(1)

    print(f"\n[INFO] Results saved to: {output_path}")


def print_results(records):
    """Print a formatted table of failed login attempts to the terminal.

    Uses fixed-width columns so the table stays readable regardless of
    username or IP length (within normal bounds).

    Args:
        records: List of dicts from extract_failed_logins().
    """
    count = len(records)

    if count == 0:
        # Don't silently succeed — tell the user nothing matched
        print("[INFO] No failed SSH login attempts found in the log file.")
        return

    plural = "s" if count != 1 else ""
    print(f"\n[INFO] Found {count} failed login attempt{plural}:\n")

    # Print the column header
    header = (
        f"{'Timestamp':<{COL_TIMESTAMP}}"
        f"{'Username':<{COL_USERNAME}}"
        f"{'Source IP':<{COL_SOURCE_IP}}"
    )
    print(header)
    print("-" * (COL_TIMESTAMP + COL_USERNAME + COL_SOURCE_IP))

    # Print one row per record
    for rec in records:
        print(
            f"{rec['timestamp']:<{COL_TIMESTAMP}}"
            f"{rec['username']:<{COL_USERNAME}}"
            f"{rec['source_ip']:<{COL_SOURCE_IP}}"
        )


def main():
    """Tie everything together: parse args, validate, extract, and report."""
    args = parse_arguments()

    # Make sure we can actually read the input before doing any real work
    validate_file(args.logfile)

    # Extract matching records from the log
    records = extract_failed_logins(args.logfile)

    # Always show the terminal summary, even if empty
    print_results(records)

    # Only write the CSV if there is something to put in it
    if records:
        write_to_csv(records, args.output)


if __name__ == "__main__":
    main()
