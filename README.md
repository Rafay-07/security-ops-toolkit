# Security Ops Toolkit

Two small Python tools for day-to-day security operations, with sample data, unit tests and a GitHub Actions pipeline that runs the tests and a Bandit static security scan on every push. No third-party packages are needed to run the tools.

## 1. Log detection (`log_detect.py`)

Reads authentication and web server logs and reports suspicious activity, each mapped to a MITRE ATT&CK technique.

| Detection | Rule | ATT&CK |
|---|---|---|
| Brute force | 5+ failed logins on one account from one IP within 5 minutes. Raised to high if a successful login follows | T1110.001 |
| Password spraying | One IP failing on 5+ different accounts within 5 minutes | T1110.003 |
| SQL injection | `' OR 1`, `UNION SELECT`, `; DROP TABLE` in a decoded URL | T1190 |
| Cross-site scripting | `<script`, `javascript:`, `onerror=` in a decoded URL | T1190 |
| Path traversal | `../` in a decoded URL | T1083 |

Web findings are high severity when the server answered 2xx or 5xx (the request was processed or broke something) and low when it was blocked (4xx).

```bash
python log_detect.py samples/auth.log samples/access.log
```

## 2. User access review (`access_review.py`)

Compares the account list against the HR roster and a role-to-group policy, the way a quarterly access review works.

| Finding | Severity | Action |
|---|---|---|
| Account with no matching person (orphaned) | High | Disable |
| Account still active for a terminated employee | High | Disable and remove access |
| Groups beyond what the role allows (least privilege) | High | Remove extra groups |
| Employee on leave with active access | Medium | Suspend until return |
| No login in 90+ days | Low | Confirm still needed |

```bash
python access_review.py samples/accounts.csv samples/hr_roster.csv samples/role_policy.csv
```

Results are printed and saved to `access_review_findings.csv` for tracking remediation.

## NIST CSF mapping

| Function | Category | Covered by |
|---|---|---|
| Protect | PR.AA (Identity management and access control) | Access review: least privilege, joiner/mover/leaver checks |
| Detect | DE.CM (Continuous monitoring) | Log detection rules |
| Detect | DE.AE (Adverse event analysis) | Severity rating and ATT&CK mapping |

## Tests

```bash
python -m pytest tests
```

Six tests check each detection on the sample logs, that a single mistyped password is not flagged, that blocked web attacks are rated low, and that the access review flags the right accounts and skips service accounts and clean users.
