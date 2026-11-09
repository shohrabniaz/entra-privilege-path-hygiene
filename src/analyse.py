from __future__ import annotations
import csv
from pathlib import Path

PRIV_ROLES = {"global administrator", "privileged role administrator", "user administrator"}

def analyse(path: Path) -> dict:
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    findings = []
    for r in rows:
        upn = r.get("upn")
        roles = [x.strip() for x in (r.get("roles") or "").split(";") if x.strip()]
        groups = [x.strip() for x in (r.get("groups") or "").split(";") if x.strip()]
        enabled = str(r.get("enabled")).lower() in {"true", "1", "yes"}
        is_admin_upn = str(r.get("is_admin_upn")).lower() in {"true", "1", "yes"}
        priv_roles = [x for x in roles if x.lower() in PRIV_ROLES]
        priv_groups = [g for g in groups if "priv" in g.lower() or "admin" in g.lower()]
        if priv_roles and not is_admin_upn:
            findings.append({"upn": upn, "issue": "standing_priv_on_daily_upn", "severity": "high", "detail": priv_roles})
        if (not enabled) and (priv_roles or priv_groups):
            findings.append({"upn": upn, "issue": "disabled_but_still_privileged", "severity": "critical", "detail": priv_roles + priv_groups})
    ga = sum(1 for r in rows if "global administrator" in (r.get("roles") or "").lower())
    if ga > 2:
        findings.append({"upn": "*", "issue": "too_many_global_admins", "severity": "high", "detail": [f"count={ga}"]})
    return {
        "identity_count": len(rows),
        "finding_count": len(findings),
        "findings": findings,
        "guidance": [
            "Separate admin UPNs from daily mailboxes",
            "Remove disabled accounts from privileged groups weekly",
            "Prefer JIT elevation over standing Global Administrator",
        ],
    }
