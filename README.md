# AuthLogParser

A command-line Python tool built for the **EHAX project** that parses authentication logs, extracts structured login/security events, and flags suspicious activity.

## What it does

An **auth log** is a record file that captures security and login events on a system (e.g. Linux's `/var/log/auth.log`) — things like SSH login attempts, `sudo` command usage, and session open/close events.

**Parsing** means reading that raw, unstructured text and turning it into organized, searchable data — in this case, a list of structured events (timestamp, username, IP, status, etc.) that can be summarized or exported.

## Features

- Parses SSH login attempts (success/failure), `sudo` commands, and session open/close events
- Supports **both** classic syslog timestamps (`Jan 15 10:23:45`) and modern ISO 8601 / journald timestamps (`2026-10-04T08:09:28.230550+00:00`), so it works on both older rsyslog-based systems and newer systemd/journald-based ones
- Prints an analytical summary: total login attempts, success/failure breakdown, top targeted usernames, top source IPs
- Gracefully skips malformed or unrecognized lines without crashing
- **Brute-force detection** — flags an IP if it exceeds a given number of failed login attempts within a given time window
  - Default: **5 failed attempts within 60 seconds** before an IP is flagged
  - Both the threshold and time window are configurable via CLI flags
- **Watch mode** — monitors the log file for new content in real time (like `tail -f`); as new lines are appended, they're parsed and printed immediately. Stops cleanly on `Ctrl+C`
- CSV export of all parsed events

## How it works (code overview)

**Regex pattern matching (`PATTERNS` dict)**
Each known type of log line (SSH success, SSH failure, `sudo`, session open, session close) has its own regex pattern, written using **named capture groups** (`(?P<name>...)`). A named group lets the matched text be pulled out as a ready-made dictionary via `match.groupdict()`, instead of manually indexing into numbered groups. All five patterns share one combined timestamp pattern that uses regex's `|` ("or") operator to accept either the classic syslog format or the ISO 8601 format in a single pass.

**Line-by-line parsing (`parse_line`, `parse_log_file`)**
Each line of the log file is tested against every pattern in turn. The first pattern that matches determines the event's type; if nothing matches, the line is skipped without crashing the program — important since real logs contain plenty of unrelated noise (systemd messages, dbus errors, etc.) that the parser isn't meant to capture.

**Summary statistics (`print_summary`)**
Uses `collections.Counter` to tally how often each status, username, and IP address appears across all parsed events, and `.most_common()` to pull out the top 5 of each — without writing manual counting/sorting logic by hand.

**Brute-force detection (`bruteforce`)**
Groups all failed login attempts by source IP, parses each timestamp into a real `datetime` object (trying the classic format first, then falling back to ISO 8601), sorts them chronologically, and slides a time window across each IP's failures to check whether enough of them happened close enough together to count as a suspicious burst.

**CSV export (`export_csv`)**
Writes every parsed event out as a row in a CSV file using `csv.DictWriter`, with column headers built from the union of every key that appears across all events (since different event types capture slightly different fields).

**Watch mode (`watch_log_file`)**
Opens the log file, seeks to the end, and polls for newly appended lines, parsing and printing each one as it arrives — the standard technique behind tools like `tail -f`.

## What I learned building this

- **Regular expressions (`re` module)** — the core tool used throughout this project. Learned how to build patterns using named capture groups, character classes, quantifiers (`+`, `*`, `?`, `{n,m}`), non-greedy matching (`.*?`), non-capturing groups (`(?:...)`), and the `|` alternation operator to handle multiple possible formats within a single pattern
- **`argparse`** — built the CLI interface, including positional arguments, optional flags (`--export`, `--watch`), and configurable numeric options with defaults (`--brute`, `--brute-window`)
- **General Python fundamentals** — file I/O, dictionaries, `Counter`/`defaultdict` from `collections`, `datetime` parsing and arithmetic, and writing structured CSV output

## Usage
Test file attached which was used for testing
```bash
# Basic run — prints the summary and runs brute-force detection
python authlogparser.py auth.log

# Export parsed events to CSV
python authlogparser.py auth.log --export

# Customize brute-force sensitivity
python authlogparser.py auth.log --brute 3 --brute-window 30

# Watch the log file live for new entries
python authlogparser.py auth.log --watch
```

## Requirements

- Python 3.10+ (standard library only — no third-party dependencies)
