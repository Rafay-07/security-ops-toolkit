"""Detect brute force, password spraying and web attacks in log files.

Usage: python log_detect.py samples/auth.log samples/access.log
Each finding is mapped to a MITRE ATT&CK technique so it can be triaged consistently.
"""
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import unquote_plus

# One regular expression per log format. The groups are the fields the detectors need.
AUTH_LINE = re.compile(r"^(\S+) login (fail|success) user=(\S+) ip=(\S+)")
WEB_LINE = re.compile(r'^(\S+) .*?"(\w+) (\S+(?: [^"]*?)?) HTTP/[\d.]+" (\d{3})')

BRUTE_FORCE_FAILS = 5          # failures against one account from one IP...
SPRAY_ACCOUNTS = 5             # ...or failures against this many accounts from one IP
WINDOW = timedelta(minutes=5)

# Each web rule: a name, the MITRE ATT&CK technique it maps to, and a pattern to look for in the URL.
WEB_RULES = [
    ("SQL injection", "T1190", re.compile(r"('|%27)\s*or\s*'?\d|union\s+select|;\s*drop\s+table", re.I)),
    ("Cross-site scripting", "T1190", re.compile(r"<script|javascript:|onerror\s*=", re.I)),
    ("Path traversal", "T1083", re.compile(r"\.\./|\.\.%2f", re.I)),
]


def parse_auth(lines):
    """Turn auth log lines into dictionaries. Lines that do not match are skipped."""
    events = []
    for line in lines:
        m = AUTH_LINE.match(line.strip())
        if m:
            events.append({"time": datetime.fromisoformat(m[1]), "result": m[2], "user": m[3], "ip": m[4]})
    return events


def detect_auth(events):
    """Look for brute force and password spraying in the login events."""
    findings = []
    fails = [e for e in events if e["result"] == "fail"]

    # Brute force: many failures on one account from one IP inside the window
    by_pair = defaultdict(list)
    for e in fails:
        by_pair[(e["user"], e["ip"])].append(e["time"])
    for (user, ip), times in by_pair.items():
        times.sort()
        # Slide over the sorted times. If one failure and the one BRUTE_FORCE_FAILS later
        # fall inside the window, that is a burst.
        for i in range(len(times) - BRUTE_FORCE_FAILS + 1):
            if times[i + BRUTE_FORCE_FAILS - 1] - times[i] <= WINDOW:
                # A successful login after the burst suggests the password was guessed, so it rates higher.
                success = any(e["result"] == "success" and e["user"] == user and e["ip"] == ip
                              and e["time"] > times[i] for e in events)
                findings.append({
                    "type": "Brute force" + (" followed by successful login" if success else ""),
                    "technique": "T1110.001", "severity": "high" if success else "medium",
                    "detail": f"{len(times)} failed logins for {user} from {ip}"})
                break

    # Password spraying: one IP failing against many different accounts inside the window
    by_ip = defaultdict(list)
    for e in fails:
        by_ip[e["ip"]].append(e)
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["time"])
        for i, start in enumerate(evs):
            # Count the different accounts this IP failed on inside the window that starts here.
            users = {e["user"] for e in evs[i:] if e["time"] - start["time"] <= WINDOW}
            if len(users) >= SPRAY_ACCOUNTS:
                findings.append({"type": "Password spraying", "technique": "T1110.003", "severity": "high",
                                 "detail": f"{ip} failed logins on {len(users)} accounts in under 5 minutes"})
                break
    return findings


def detect_web(lines):
    """Check each web request against the attack patterns."""
    findings = []
    for line in lines:
        m = WEB_LINE.match(line.strip())
        if not m:
            continue
        # Decode the URL first (%27 becomes '), so encoded attacks are still matched.
        ip, method, path, status = m[1], m[2], unquote_plus(m[3]), m[4]
        for name, technique, rule in WEB_RULES:
            if rule.search(path):
                # A 2xx or 5xx reply means the request got through or broke something, so it rates high.
                # Anything else was most likely rejected.
                findings.append({"type": name, "technique": technique,
                                 "severity": "high" if status.startswith(("2", "5")) else "low",
                                 "detail": f"{ip} {method} {path[:80]} -> {status}"})
    return findings


def report(findings):
    """Build a Markdown table of the findings, most severe first, with a count line."""
    order = {"high": 0, "medium": 1, "low": 2}
    lines = ["| Severity | Finding | ATT&CK | Detail |", "|---|---|---|---|"]
    for f in sorted(findings, key=lambda f: order[f["severity"]]):
        lines.append(f"| {f['severity']} | {f['type']} | {f['technique']} | {f['detail']} |")
    counts = {s: sum(f["severity"] == s for f in findings) for s in order}
    lines.append(f"\nTotal: {len(findings)} findings ({counts['high']} high, {counts['medium']} medium, {counts['low']} low)")
    return "\n".join(lines)


def main(paths):
    findings = []
    for path in paths:
        with open(path) as f:
            lines = f.readlines()
        # Work out which kind of log this is from its lines, then run the matching detector.
        if any(AUTH_LINE.match(l) for l in lines):
            findings += detect_auth(parse_auth(lines))
        else:
            findings += detect_web(lines)
    print(report(findings))


if __name__ == "__main__":
    main(sys.argv[1:] or ["samples/auth.log", "samples/access.log"])
