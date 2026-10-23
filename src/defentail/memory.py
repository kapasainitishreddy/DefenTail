"""Attack Memory: a project-local, append-only ledger of what was scanned and decided.

Why it exists: a scanner tells you what is wrong right now. Memory tells you what has
already been seen, what keeps coming back, and what a previous run called fixed. It is
plain JSON lines inside `.defentail/`, so it stays on the user's machine, survives across
agent sessions, can be reviewed in a pull request, and never needs an account.

No secrets are stored: records keep rule ids, workspace-relative paths, line numbers,
severity and fingerprints only.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

MEMORY_VERSION = 1
MAX_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 5000
INTERNAL = "_absent_since"


def memory_path(root: Path) -> Path:
    return Path(root) / ".defentail" / "memory.jsonl"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _append(root: Path, record: dict[str, Any]) -> bool:
    """Best-effort append. A full disk or an unreadable folder must never break a scan."""
    path = memory_path(root)
    try:
        if path.is_file() and path.stat().st_size > MAX_BYTES:
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
        with open(path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
        return True
    except OSError:
        return False


def record_scan(root: Path, report: dict[str, Any]) -> bool:
    findings = [
        {"fp": issue.get("fingerprint"), "rule": issue.get("rule_id"),
         "path": issue.get("path"), "line": issue.get("line", 0),
         "severity": issue.get("severity")}
        for issue in report.get("findings", []) if issue.get("fingerprint")
    ]
    return _append(Path(root), {
        "v": MEMORY_VERSION,
        "ts": _now(),
        "kind": "scan",
        "profile": report.get("profile"),
        "digest": report.get("digest"),
        "gate": bool((report.get("gate") or {}).get("passed")),
        "assurance": report.get("assurance"),
        "coverage": {c.get("engine"): c.get("status") for c in report.get("checks", [])},
        "findings": findings,
    })


def record_decision(root: Path, verdict: str, blocking: list[str], note: str = "") -> bool:
    if verdict not in ("BLOCK", "PASS_SELECTED_CHECKS"):
        raise ValueError("verdict must be BLOCK or PASS_SELECTED_CHECKS")
    return _append(Path(root), {
        "v": MEMORY_VERSION, "ts": _now(), "kind": "decision",
        "verdict": verdict, "blocking": [str(fp)[:40] for fp in blocking][:100],
        "note": str(note)[:500],
    })


def load(root: Path, *, limit: int = MAX_RECORDS) -> list[dict[str, Any]]:
    """Read the tail of the ledger. Corrupt or truncated lines are skipped, never fatal."""
    path = memory_path(root)
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    records = []
    for line in lines[-limit:]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and item.get("kind") in ("scan", "decision"):
            records.append(item)
    return records


def fingerprint_stats(root: Path) -> dict[str, dict[str, Any]]:
    """Per-finding history: how often seen, when first/last, and whether it came back."""
    stats: dict[str, dict[str, Any]] = {}
    for record in load(root):
        if record.get("kind") != "scan":
            continue
        stamp = str(record.get("ts", ""))
        present = {f["fp"]: f for f in record.get("findings", []) if isinstance(f, dict) and f.get("fp")}
        for fp, info in present.items():
            entry = stats.setdefault(fp, {
                "rule_id": info.get("rule"), "path": info.get("path"), "line": info.get("line", 0),
                "severity": info.get("severity"), "times_seen": 0,
                "first_seen": stamp, "last_seen": stamp, "reappeared": False, INTERNAL: False,
            })
            entry["times_seen"] += 1
            entry["last_seen"] = stamp
            if entry[INTERNAL]:
                entry["reappeared"] = True
                entry[INTERNAL] = False
        for fp, entry in stats.items():
            if fp not in present:
                entry[INTERNAL] = True
    for entry in stats.values():
        entry.pop(INTERNAL, None)
    return stats


def history_for(root: Path, fingerprints: list[str]) -> dict[str, dict[str, Any]]:
    stats = fingerprint_stats(root)
    return {fp: stats[fp] for fp in fingerprints if fp in stats}


def summary(root: Path) -> dict[str, Any]:
    records = load(root)
    scans = [r for r in records if r.get("kind") == "scan"]
    decisions = [r for r in records if r.get("kind") == "decision"]
    stats = fingerprint_stats(root)
    recurring = sorted(
        ({"fingerprint": fp, **info} for fp, info in stats.items() if info["times_seen"] > 1),
        key=lambda item: (-item["times_seen"], str(item.get("path") or "")),
    )[:10]
    returning = [item for item in recurring if item.get("reappeared")]
    return {
        "schema": "defentail.memory.v1",
        "memory_file": str(memory_path(root)),
        "records": len(records),
        "scans": len(scans),
        "decisions": len(decisions),
        "blocked_decisions": sum(1 for d in decisions if d.get("verdict") == "BLOCK"),
        "passed_decisions": sum(1 for d in decisions if d.get("verdict") == "PASS_SELECTED_CHECKS"),
        "first_record": records[0].get("ts") if records else None,
        "latest_record": records[-1].get("ts") if records else None,
        "recurring_findings": recurring,
        "returned_after_clear": returning,
        "note": ("Memory is local evidence, not proof of a fix. A finding can disappear because "
                 "code changed, because a scanner was not installed, or because the file moved."),
    }
