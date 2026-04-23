#!/usr/bin/python3
# Log Parser for Security Analysis
# Joel Koszorus 04/22/2026

# IMPORTS
import argparse
import re
import csv
import sys
import os

# CONSTANTS
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
# This regex captures the timestamp, username, and source IP from failed SSH login attempts in auth.log.
# The "invalid user" prefix is optional — the non-capturing group (?:invalid user\s+)? absorbs it when present so the username group still lands in group 2.

COL_TIMESTAMP = 20
COL_USERNAME  = 16
COL_SOURCE_IP = 16
# Column widths for the terminal output table

CSV_HEADER = ["timestamp", "username", "source_ip"]
# CSV field names, which are also used as the header row

# FUNCTIONS
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Extract failed SSH login attempts from a Linux auth.log file.",
        usage="%(prog)s <logfile> <output.csv>",
    )
    parser.add_argument("logfile", help="Path to the auth.log file to analyze")
    parser.add_argument("output",  help="Destination path for the CSV report")
    return parser.parse_args()
# Parses command-line arguments; argparse handles the usage message on error instead of a raw Python traceback


def validate_file(path):
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
# Confirms the log file exists and is readable before any work begins. If not it exits with a clear message on failure instead of a raw exception


def extract_failed_logins(logfile_path):
    records = []

    try:
        # errors="replace" keeps us moving if a line has unexpected encoding
        with open(logfile_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                match = FAILED_LOGIN_PATTERN.search(line)
                if match:
                    records.append({
                        "timestamp": match.group(1),  # raw string, this is not normalized
                        "username":  match.group(2),
                        "source_ip": match.group(3),
                    })
    except OSError as e:
        # Catches any IO/permission issues that slipped past validate_file
        print(f"[ERROR] Could not read file: {e}")
        sys.exit(1)

    return records
# Reads the log file line by line and returns a list of dicts for every line that matches FAILED_LOGIN_PATTERN; non-matching lines are silently skipped as we are only looking for failures


def write_to_csv(records, output_path):
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
# Writes the extracted records to a CSV file with a header row


def print_results(records):
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
# Prints a fixed-width table of results to the terminal. Informs the user if nothing matched so we never silently succeed on an empty result


def main():
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
# Entry point — ties together argument parsing, validation, extraction, and output
