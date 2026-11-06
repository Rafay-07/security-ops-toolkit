import os
import sys
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import access_review  # noqa: E402
import log_detect  # noqa: E402

S = os.path.join(os.path.dirname(__file__), "..", "samples")


def lines(name):
    with open(os.path.join(S, name)) as f:
        return f.readlines()


def test_brute_force_with_success_is_high():
    found = log_detect.detect_auth(log_detect.parse_auth(lines("auth.log")))
    bf = [f for f in found if f["technique"] == "T1110.001"]
    assert len(bf) == 1 and bf[0]["severity"] == "high" and "jsmith" in bf[0]["detail"]


def test_password_spraying_detected():
    found = log_detect.detect_auth(log_detect.parse_auth(lines("auth.log")))
    assert any(f["type"] == "Password spraying" and "198.51.100.23" in f["detail"] for f in found)


def test_single_typo_is_not_flagged():
    found = log_detect.detect_auth(log_detect.parse_auth(lines("auth.log")))
    assert not any("10.0.4.30" in f["detail"] for f in found)


def test_web_rules_catch_each_attack_and_skip_normal_traffic():
    found = log_detect.detect_web(lines("access.log"))
    types = sorted(f["type"] for f in found)
    assert types == ["Cross-site scripting", "Path traversal", "SQL injection", "SQL injection"]
    assert not any("10.0.4." in f["detail"] for f in found)


def test_blocked_request_is_low_severity():
    found = log_detect.detect_web(lines("access.log"))
    assert [f["severity"] for f in found if f["type"] == "Path traversal"] == ["low"]


def test_access_review_findings():
    read = lambda n: access_review.read(os.path.join(S, n))
    found = access_review.review(read("accounts.csv"), read("hr_roster.csv"), read("role_policy.csv"),
                                 today=date(2026, 10, 13))
    by_user = {}
    for user, sev, msg, _ in found:
        by_user.setdefault(user, []).append(msg)
    assert any("domain-admins" in m for m in by_user["alee"])
    assert any("terminated" in m for m in by_user["olduser"])
    assert any("leave" in m for m in by_user["cdiaz"])
    assert "svc_backup" not in by_user and "jsmith" not in by_user
