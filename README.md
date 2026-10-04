AuthLogParser

A command-line Python tool built for the EHAX project that parses authentication logs, extracts structured login/security events, and flags suspicious activity.

What it does

An auth log is a record file that captures security and login events on a system (e.g. Linux's /var/log/auth.log) — things like SSH login attempts, sudo command usage, and session open/close events.

Parsing means reading that raw, unstructured text and turning it into organized, searchable data — in this case, a list of structured events (timestamp, username, IP, status, etc.) that can be summarized, searched, or exported.

Features
Parses SSH login attempts (success/failure), sudo commands, and session open/close events
Prints an analytical summary: total login attempts, success/failure breakdown, top targeted usernames, top source IPs
Gracefully skips malformed or unrecognized lines without crashing
Brute-force detection — flags an IP if it exceeds a given number of failed login attempts within a given time window
Default: 5 failed attempts within 60 seconds before an IP is flagged
Both the threshold and time window are configurable via CLI flags
Watch mode — monitors the log file for new content in real time (like tail -f); as new lines are appended, they're parsed and printed immediately. Stops cleanly on Ctrl+C
CSV export of all parsed events
What I learned building this
Regular expressions (re module) — the core tool used to match and extract structured fields (timestamp, PID, username, IP, port) from raw log lines using named capture groups
Basics of argparse for building the command-line interface
General Python fundamentals — file I/O, dictionaries, loops, and string handling


Sample File is attached with which i tested this project
