import argparse
import csv
import re
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

#regex patterns dictionary
_TS = r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)"

PATTERNS = {
    "ssh_success": re.compile(
        _TS + r"\s+\S+\s+"
        r"sshd\[(?P<pid>\d+)\]:\s+Accepted\s+\S+\s+for\s+(?P<username>\S+)"
        r"\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
    ),
    "ssh_failure": re.compile(
        _TS + r"\s+\S+\s+"
        r"sshd\[(?P<pid>\d+)\]:\s+Failed\s+\S+\s+for\s+(invalid user\s+)?"
        r"(?P<username>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
    ),
    "sudo": re.compile(
        _TS + r"\s+\S+\s+"
        r"sudo:\s+(?P<username>\S+)\s+:.*?COMMAND=(?P<command>.+)"
    ),
    "session_open": re.compile(
        _TS + r"\s+\S+\s+"
        r"\S+?\[?\d*\]?:?\s*pam_unix\((?P<service>[\w-]+):session\):\s+session opened"
        r"\s+for user\s+(?P<username>[\w.-]+)"
    ),
    "session_close": re.compile(
        _TS + r"\s+\S+\s+"
        r"\S+?\[?\d*\]?:?\s*pam_unix\((?P<service>[\w-]+):session\):\s+session closed"
        r"\s+for user\s+(?P<username>[\w.-]+)"
    ),
}
STATUS = {
    "ssh_success": "success",
    "ssh_failure": "failure",
}


#function for parsing single line of log file
def parse_line(line: str):
    line = line.strip()
    if not line:
        return None

    for event_type, pattern in PATTERNS.items():
        match = pattern.search(line)
        if match:
            data = match.groupdict()
            data["event_type"] = event_type
            data["status"] = STATUS.get(event_type)
            data.setdefault("ip", None)
            data.setdefault("port", None)
            data.setdefault("pid", None)
            return data

    return None 

#function for parsing the entire log file using filepath as argument
def parse_log_file(filepath: str):
    events = []
    total = 0
    skipped = 0

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            total += 1
            event = parse_line(line)
            if event:
                events.append(event)
            else:
                skipped += 1

    print(f"Processed {total} lines — {len(events)} matched, {skipped} skipped.\n")
    return events

3#function for summary
def print_summary(events: list[dict]):
    status_counter = Counter(e["status"] for e in events if e["status"])
    username_counter = Counter(e["username"] for e in events if e.get("username"))
    ip_counter = Counter(e["ip"] for e in events if e.get("ip"))

    total_attempts = status_counter.get("success", 0) + status_counter.get("failure", 0)

    print("=== Auth Log Summary ===")
    print(f"Total login attempts : {total_attempts}")
    print(f"  Success            : {status_counter.get('success', 0)}")
    print(f"  Failure            : {status_counter.get('failure', 0)}")

    print("\nTop targeted usernames:")
    for user, count in username_counter.most_common(5):
        print(f"  {user} {count}")

    print("\nTop source IPs:")
    for ip, count in ip_counter.most_common(5):
        print(f"  {ip} {count}")

def _parse_timestamp(text: str, current_year: int):
    """Parse either classic syslog ('Jan 15 10:23:45') or ISO/journald
    ('2026-10-04T08:09:28.230550+00:00') timestamp strings."""
    try:
        return datetime.strptime(f"{current_year} {text}", "%Y %b %d %H:%M:%S")
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None

#brute force

def bruteforce(events: list[dict], threshold: int, window_seconds: int):
    failures = defaultdict(list)
    current_year = datetime.now().year

    for e in events:
        if e["status"] != "failure" or not e.get("ip") or not e.get("timestamp"):
            continue
        ts = _parse_timestamp(e["timestamp"], current_year)
        if ts is None:
            continue
        failures[e["ip"]].append(ts)
    print("\n--- Brute-force Detection ---")
    flagged_any = False

    for ip, timestamps in failures.items():
        timestamps.sort()
        # Sliding window: for each timestamp, count how many fall within
        # window_seconds after it.
        for i, start in enumerate(timestamps):
            count = 1
            for later in timestamps[i + 1:]:
                if (later - start).total_seconds() <= window_seconds:
                    count += 1
                else:
                    break
            if count >= threshold:
                print(f"  \u26a0 {ip} \u2014 {count} failures within {window_seconds}s "
                      f"(starting {start})")
                flagged_any = True
                break  
    if not flagged_any:
        print("  No suspicious IPs detected.")


# export function

def export_csv(events: list[dict], filepath: str):
    out_path = Path(filepath).with_suffix(".csv")

    if not events:
        print("No events to export.")
        return

    fieldnames = sorted({key for e in events for key in e.keys()})
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    print(f"Exported {len(events)} events to {out_path}")


# watch function

def watch_log_file(filepath: str):
    print(f"Watching {filepath} for new entries... (Ctrl+C to stop)\n")
    with open(filepath, "r") as f:
        f.seek(0, 2) 
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                event = parse_line(line)
                if event:
                    print(f"[{event['event_type']}] {event}")
        except KeyboardInterrupt:
            print("\nStopped watching.")


#Command line Interface argparse

def main():
    parser = argparse.ArgumentParser(description="Parse and summarize auth log files.")
    parser.add_argument("logfile", help="Path to the auth log file")
    parser.add_argument("--export", action="store_true", help="Export parsed events to CSV")
    parser.add_argument("--watch", action="store_true", help="Live monitoring mode")
    parser.add_argument("--brute", type=int, default=5,
                         help="Failed attempts to trigger a brute-force flag (default: 5)")
    parser.add_argument("--brute-window", type=int, default=60,
                         help="Time window in seconds for brute-force detection (default: 60)")
    args = parser.parse_args()

    if not Path(args.logfile).is_file():
        print(f"Error: file not found — {args.logfile}")
        return

    if args.watch:
        watch_log_file(args.logfile)
        return

    events = parse_log_file(args.logfile)
    print_summary(events)
    bruteforce(events, args.brute, args.brute_window)

    if args.export:
        export_csv(events, args.logfile)

main()