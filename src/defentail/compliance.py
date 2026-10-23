"""SOC 2 technical evidence built from a real scan, a real coverage record and real memory.

Honesty rules baked in:
- A criterion is never marked satisfied. Statuses describe *evidence*, not compliance.
- Criteria DefenTail cannot touch are reported as human-evidence-required, not skipped.
- Missing scanners downgrade a criterion to `partial` instead of silently passing it.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .core import seal, scan
from .intelligence import bundled_data
from .memory import record_scan
from .memory import summary as memory_summary

EVIDENCE_SCHEMA = "defentail.soc2.evidence.v1"
STATUSES = ("technical-evidence-collected", "partial", "finding-observed", "human-evidence-required")
MAX_OBSERVATIONS = 10


def _matches(finding: dict[str, Any], criterion: dict[str, Any]) -> bool:
    rule = str(finding.get("rule_id", ""))
    if any(rule.startswith(prefix) for prefix in criterion.get("rule_prefixes", [])):
        return True
    return finding.get("engine") in criterion.get("finding_engines", [])


def _observation(finding: dict[str, Any]) -> dict[str, Any]:
    item = {
        "rule_id": finding.get("rule_id"),
        "engine": finding.get("engine"),
        "path": finding.get("path"),
        "line": finding.get("line", 0),
        "severity": finding.get("severity"),
        "fingerprint": finding.get("fingerprint"),
    }
    if finding.get("known_exploited"):
        item["known_exploited"] = True
    return item


def soc2_evidence(root: Path, *, profile: str = "basic", record: bool = True) -> dict[str, Any]:
    root = Path(root).expanduser().resolve(strict=True)
    report = scan(root, profile=profile)
    catalog = bundled_data("soc2.json")
    coverage = {c.get("engine"): c.get("status") for c in report.get("checks", [])}
    memory = memory_summary(root)
    results = []
    gaps: list[dict[str, Any]] = []

    for criterion in catalog["criteria"]:
        matched = [f for f in report.get("findings", []) if _matches(f, criterion)]
        required = criterion.get("coverage_engines", [])
        unavailable = [e for e in required if coverage.get(e) not in ("complete", "not-applicable")]
        if criterion["support"] == "none":
            status = "human-evidence-required"
        elif matched:
            status = "finding-observed"
        elif unavailable:
            status = "partial"
        else:
            status = "technical-evidence-collected"
        entry = {
            "id": criterion["id"],
            "title": criterion["title"],
            "plain_english": criterion["simple"],
            "support": criterion["support"],
            "status": status,
            "checks_required": required,
            "checks_unavailable": unavailable,
            "observations": [_observation(f) for f in matched[:MAX_OBSERVATIONS]],
            "observation_count": len(matched),
            "technical_evidence": list(criterion.get("defentail_evidence", [])),
            "human_evidence_required": list(criterion.get("human_evidence", [])),
        }
        if criterion["id"] == "CC4.1":
            entry["recurring_findings"] = len(memory["recurring_findings"])
            entry["returned_after_clear"] = len(memory["returned_after_clear"])
        results.append(entry)
        if unavailable:
            for engine in unavailable:
                gaps.append({"kind": "check-did-not-run", "engine": engine, "criterion": criterion["id"]})
        if criterion["support"] == "none":
            gaps.append({"kind": "human-evidence-required", "criterion": criterion["id"],
                         "items": list(criterion.get("human_evidence", []))})
        if matched:
            gaps.append({"kind": "open-findings", "criterion": criterion["id"], "count": len(matched)})

    counts = {status: sum(1 for r in results if r["status"] == status) for status in STATUSES}
    pack = {
        "schema": EVIDENCE_SCHEMA,
        "framework": catalog["framework"],
        "catalog_as_of": catalog["as_of"],
        "generated_utc": report["generated_utc"],
        "scope": {
            "workspace_name": report["workspace_name"],
            "profile": profile,
            "assurance": report["assurance"],
            "coverage": coverage,
            "findings_total": len(report.get("findings", [])),
            "report_digest": report["digest"],
        },
        "control_summary": counts,
        "criteria": results,
        "gaps": gaps,
        "memory": {
            "scans_recorded": memory["scans"],
            "decisions_recorded": memory["decisions"],
            "recurring_findings": memory["recurring_findings"],
        },
        "disclaimer": catalog["disclaimer"],
        "limitations": [
            "This is technical evidence for a subset of criteria, not a SOC 2 report or an audit opinion.",
            "Only the checks listed in scope.coverage ran; absent scanners are reported, never assumed clean.",
            "Organizational controls (governance, HR, vendor management, physical security) are outside this tool.",
            "A finding can disappear because it was fixed, because a scanner was missing, or because the file moved.",
        ],
    }
    if record:
        record_scan(root, report)
    return seal(pack)
