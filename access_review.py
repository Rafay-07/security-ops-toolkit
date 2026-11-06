"""User access review: compare accounts against the HR roster and the role policy.

Usage: python access_review.py samples/accounts.csv samples/hr_roster.csv samples/role_policy.csv
Flags orphaned accounts, accounts of people on leave, privileges beyond the role, and stale logins.
"""
import csv
import sys
from datetime import date

STALE_DAYS = 90


def read(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def review(accounts, roster, policy, today):
    people = {r["username"]: r for r in roster}
    allowed = {p["role"]: set(p["allowed_groups"].split(";")) for p in policy}
    findings = []
    for acct in accounts:
        user, role = acct["username"], acct["role"]
        groups = set(filter(None, acct["groups"].split(";")))
        person = people.get(user)

        if role == "service":
            pass  # service accounts are not on the HR roster; reviewed by owner instead
        elif person is None:
            findings.append((user, "high", "No matching person in HR roster (orphaned account)", "Disable"))
        elif person["status"] == "terminated":
            findings.append((user, "high", "Account still exists for terminated employee", "Disable and remove access"))
        elif person["status"] == "leave":
            findings.append((user, "medium", "Employee on leave still has active access", "Suspend until return"))

        extra = groups - allowed.get(role, set())
        if extra:
            findings.append((user, "high", f"Groups beyond {role} role: {', '.join(sorted(extra))}", "Remove extra groups"))

        days = (today - date.fromisoformat(acct["last_login"])).days
        if days > STALE_DAYS:
            findings.append((user, "low", f"No login for {days} days", "Confirm still needed"))
    return findings


def main(args):
    accounts, roster, policy = (read(p) for p in args)
    findings = review(accounts, roster, policy, date.today())
    with open("access_review_findings.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["username", "severity", "finding", "recommended_action"])
        w.writerows(findings)
    for row in findings:
        print(" | ".join(row))
    print(f"\n{len(findings)} findings across {len(accounts)} accounts. Saved to access_review_findings.csv")


if __name__ == "__main__":
    main(sys.argv[1:] or ["samples/accounts.csv", "samples/hr_roster.csv", "samples/role_policy.csv"])
