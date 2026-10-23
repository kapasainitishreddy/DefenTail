"""Local-only scanner adapters and evidence reports.

The starter intentionally never executes project scripts or untrusted MCP servers.
Scanner executables are installed separately. Reports omit raw secret matches.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

SCHEMA = "defentail.scan.v0.1"
COMPARISON_SCHEMA = "defentail.comparison.v0.1"
ENGINES = {"basic": ("builtin",), "quick": ("builtin", "semgrep", "betterleaks", "osv-scanner"), "full": ("builtin", "semgrep", "betterleaks", "osv-scanner", "trivy") }
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}


def _json_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def seal(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["digest"] = "sha256:" + _json_hash(result)
    return result


def digest_valid(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    actual = payload.get("digest", "")
    stripped = {k: v for k, v in payload.items() if k != "digest"}
    return actual == "sha256:" + _json_hash(stripped)


def _severity(raw: Any) -> str:
    value = str(raw or "UNKNOWN").upper()
    return value if value in SEVERITIES else "UNKNOWN"


def _title(value: Any, *, secret: bool = False) -> str:
    if secret:
        return "Potential secret or credential detected (value omitted)"
    if not isinstance(value, str):
        return "Security finding"
    cleaned = " ".join(value.split())
    # Avoid retaining scanner messages that can include credential fragments.
    # This title is an untrusted hint and MUST NOT be assumed fully sanitized.
    return cleaned[:160] if cleaned else "Security finding"


def _safe_path(value: Any, root: Path) -> str:
    if not isinstance(value, str) or not value:
        return "unknown"
    try:
        actual = Path(value)
        if not actual.is_absolute():
            actual = root / actual
        return actual.resolve().relative_to(root).as_posix()
    except (ValueError, RuntimeError, OSError):
        return "outside-workspace"


def _finding(engine: str, rule: Any, path: Any, line: Any, severity: Any, title: Any,
             root: Path, *, secret: bool = False) -> dict[str, Any]:
    rule_id = str(rule or "unspecified")[:100]
    safe_path = _safe_path(path, root)
    try:
        lineno = max(0, int(line))
    except (ValueError, TypeError):
        lineno = 0
    result = {
        "engine": engine,
        "rule_id": rule_id,
        "path": safe_path,
        "line": lineno,
        "severity": _severity(severity),
        "title": _title(title, secret=secret),
    }
    fp = "|".join([engine, rule_id, safe_path, str(lineno)])
    result["fingerprint"] = hashlib.sha256(fp.encode()).hexdigest()[:20]
    return result


def parse_semgrep(data: Any, root: Path) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("Invalid Semgrep report")
    items = []
    for entry in data["results"]:
        if not isinstance(entry, dict):
            continue
        extra = entry.get("extra") or {}
        metadata = extra.get("metadata") or {}
        # Semgrep ERROR/WARNING are rule severities, not exploitability ratings.
        # Use the author's impact metadata when present; otherwise UNKNOWN.
        severity = metadata.get("impact", "UNKNOWN") if isinstance(metadata, dict) else "UNKNOWN"
        items.append(_finding("semgrep", entry.get("check_id"), entry.get("path"),
                              (entry.get("start") or {}).get("line"), severity,
                              "Static code rule triggered", root))
    return items


def parse_betterleaks(data: Any, root: Path) -> list[dict[str, Any]]:
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("findings")
        if not isinstance(records, list):
            records = data.get("Findings")
    else:
        records = None
    if not isinstance(records, list):
        raise ValueError("Invalid Betterleaks report")
    return [_finding("betterleaks", rec.get("RuleID") or rec.get("rule_id"),
                     rec.get("File") or rec.get("file") or rec.get("Source"),
                     rec.get("StartLine") or rec.get("start_line"), "HIGH",
                     "Credential match", root, secret=True)
            for rec in records if isinstance(rec, dict)]


def parse_trivy(data: Any, root: Path) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("Results"), list):
        raise ValueError("Invalid Trivy report")
    findings = []
    for group in data["Results"]:
        if not isinstance(group, dict):
            continue
        target = group.get("Target", "unknown")
        for category, idkey, titlekey in (
            ("Vulnerabilities", "VulnerabilityID", "Title"),
            ("Misconfigurations", "ID", "Title"),
            ("Secrets", "RuleID", "Title"),
        ):
            for issue in group.get(category) or []:
                if not isinstance(issue, dict):
                    continue
                is_secret = category == "Secrets"
                findings.append(_finding("trivy", issue.get(idkey), issue.get("FilePath") or target,
                                         issue.get("StartLine", 0), issue.get("Severity"),
                                         issue.get(titlekey), root, secret=is_secret))
    return findings


def build_command(engine: str, root: Path, output: Path, *, rules: Path | None = None) -> list[str]:
    """Fixed commands only. No shell evaluation and no user-provided executable paths."""
    if engine == "semgrep":
        rule_file = (rules or Path(__file__).with_name("rules.yml")).resolve()
        return ["semgrep", "scan", "--json", "--metrics=off", "--disable-version-check",
                "--config", str(rule_file), "--exclude", ".defentail",
                "--exclude", "node_modules", "--exclude", "dist", "--output", str(output), str(root)]
    if engine == "betterleaks":
        return ["betterleaks", "dir", str(root), "--report-path", str(output),
                "--report-format", "json", "--silent"]
    if engine == "osv-scanner":
        return ["osv-scanner", "scan", "--format", "json", "-r", str(root)]
    if engine == "trivy":
        return ["trivy", "fs", "--format", "json", "--output", str(output),
                "--scanners", "vuln,secret,misconfig", "--skip-dirs", ".defentail",
                str(root)]
    raise ValueError("Unknown engine")


def doctor() -> list[dict[str, Any]]:
    """Avoid executing external binaries just for installation detection."""
    return [{"engine": name, "installed": True if name == "builtin" else shutil.which(name) is not None}
            for name in ENGINES["full"]]


def parse_osv(data: Any, root: Path) -> list[dict[str, Any]]:
    """Parse v2 OSV-Scanner reports, retaining no advisory descriptions or source fragments."""
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("Invalid OSV report")
    findings = []
    for result in data["results"]:
        if not isinstance(result, dict):
            continue
        source = result.get("source") or {}
        for pkg in result.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            package = pkg.get("package") or {}
            for vuln in pkg.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                ids = [vuln.get("id")] + (vuln.get("aliases") or [])
                ids = [x for x in ids if isinstance(x, str) and len(x) < 80]
                rule = next((x for x in ids if x.startswith("CVE-")), (ids[0] if ids else "OSV-unknown"))
                item = _finding("osv-scanner", rule, source.get("path"), 0,
                                "UNKNOWN", "Known vulnerability in a dependency", root)
                item["package"] = str(package.get("name", "unknown"))[:100]
                item["package_version"] = str(package.get("version", "unknown"))[:60]
                item["advisory_ids"] = ids[:8]
                item["reference"] = "https://osv.dev/vulnerability/" + rule if rule != "OSV-unknown" else "https://osv.dev"
                item["simple_explanation"] = "One of your building blocks may have a known security flaw."
                item["suggested_action"] = "Review the advisory, then upgrade to a patched dependency version."
                findings.append(item)
    return findings


def _scanner_run(name: str, root: Path, output: Path, timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    if shutil.which(name) is None:
        return {"engine": name, "status": "unavailable", "findings": [],
                "duration_ms": 0, "reason": "Executable not found on PATH"}
    cmd = build_command(name, root, output)
    try:
        # Deliberately never capture stdout or stderr: scanners may print secrets.
        if name == "osv-scanner":
            # Capture JSON stdout only. Do not store stderr, which might contain paths.
            completed = subprocess.run(cmd, cwd=str(root), shell=False, timeout=timeout,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, check=False)
            if len(completed.stdout) > 30_000_000:
                raise ValueError("OSV report exceeded 30 MiB")
            output.write_bytes(completed.stdout)
        else:
            completed = subprocess.run(cmd, cwd=str(root), shell=False, timeout=timeout,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired:
        return {"engine": name, "status": "timeout", "findings": [],
                "duration_ms": round((time.monotonic()-started)*1000), "reason": "Scanner timed out"}
    except (OSError, ValueError):
        return {"engine": name, "status": "error", "findings": [],
                "duration_ms": round((time.monotonic()-started)*1000), "reason": "Scanner could not start"}
    duration = round((time.monotonic() - started) * 1000)
    # Semgrep, OSV and secret scanners can return 1 to indicate findings.
    # Accept exit 1 ONLY when a parseable report is present; higher/other codes are failures.
    if completed.returncode not in (0, 1):
        return {"engine": name, "status": "error", "findings": [], "duration_ms": duration,
                "reason": f"Scanner exited {completed.returncode}; results not trusted."}
    if not output.is_file():
        return {"engine": name, "status": "error", "findings": [], "duration_ms": duration,
                "reason": "Scanner produced no report"}
    try:
        if output.stat().st_size > 30_000_000:
            raise ValueError("Report exceeds 30MB size limit")
        data = json.loads(output.read_text(encoding="utf-8"))
        parser = {"semgrep": parse_semgrep, "betterleaks": parse_betterleaks, "trivy": parse_trivy, "osv-scanner": parse_osv}[name]
        findings = parser(data, root)
        # Exit 1 without any finding is ambiguous, not a clean result.
        if completed.returncode == 1 and not findings:
            return {"engine": name, "status": "error", "findings": [], "duration_ms": duration,
                    "reason": "Scanner failed or exit code 1 without recognized findings"}
        # Each known finding is retained, but title and raw secret match omitted.
        return {"engine": name, "status": "complete", "findings": findings,
                "duration_ms": duration, "reason": ""}
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return {"engine": name, "status": "error", "findings": [], "duration_ms": duration,
                "reason": "Scanner report could not be parsed"}


def scan(root: Path, *, profile: str = "quick", timeout: int = 180) -> dict[str, Any]:
    if profile not in ENGINES:
        raise ValueError("profile must be basic, quick or full")
    root = Path(root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("workspace must be a directory")
    if timeout < 1 or timeout > 900:
        raise ValueError("timeout must be 1..900 seconds")
    from .builtin import builtin_scan
    from .intelligence import kev_status, known_exploited_ids

    results = []
    with tempfile.TemporaryDirectory(prefix="defentail-") as td:
        for engine in ENGINES[profile]:
            if engine == "builtin":
                results.append(builtin_scan(root, _finding))
            else:
                output = Path(td) / f"{engine}.json"
                results.append(_scanner_run(engine, root, output, timeout))
    found = [issue for item in results for issue in item["findings"]]
    exploited = known_exploited_ids()
    for issue in found:
        cv = issue.get("incident_id", issue.get("rule_id", ""))
        ids = set(issue.get("advisory_ids", [])) | {cv}
        if ids & exploited:
            issue["known_exploited"] = True
            if issue["severity"] in ("UNKNOWN", "LOW", "MEDIUM", "INFO"):
                issue["severity"] = "HIGH"
    # Deduplicate within identical engine/rule/path/line. Cross-engine correlation is a future feature.
    found = list({issue["fingerprint"]: issue for issue in found}.values())
    found.sort(key=lambda item: (item["engine"], item["path"], item["line"], item["rule_id"]))
    checks = [{k: item[k] for k in ("engine", "status", "duration_ms", "reason")} for item in results]
    # Never treat a missing, timed-out, or failed scanner as a clean scan.
    incomplete = [r["engine"] for r in results if r["status"] != "complete"]
    serious = [i["fingerprint"] for i in found if i["severity"] in ("CRITICAL", "HIGH")]
    # Unknown-severity findings must be triaged; otherwise a new advisory can silently pass.
    untriaged = [i["fingerprint"] for i in found if i["severity"] == "UNKNOWN"]
    # Fail closed for both blocking findings and incomplete required scans.
    result = {
        "schema": SCHEMA, "profile": profile,
        "workspace_name": root.name, "generated_utc": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(),
        "checks": checks, "findings": found, "intelligence": kev_status(),
        "assurance": "limited" if profile == "basic" else ("partial" if incomplete or untriaged else "scanned"),
        "gate": {"passed": not incomplete and not serious and not untriaged,
                 "blocked_by": {"incomplete_engines": incomplete,
                                "high_or_critical_fingerprints": serious,
                                "unknown_severity_fingerprints": untriaged}},
        "limitations": [
            "Evidence contains no signature and is not a security certification.",
            "This scan is static only and cannot prove exploitability or absence of bugs.",
            "The basic profile checks only selected local patterns; quick scans require external scanners.",
            "OSV may use internet services to look up dependency vulnerabilities. Configure offline mode separately if required.",
            "Semgrep's included rules are a minimal starter set, not full SAST coverage.",
            "Trivy full scans may download public vulnerability databases; internet access and a trusted binary may be needed.",
            "Dependency scanners may send package or advisory metadata to online services; basic scans are local-only.",
        ],
    }
    return seal(result)


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if before.get("schema") != SCHEMA or after.get("schema") != SCHEMA:
        raise ValueError("Both inputs must be DefenTail scan reports")
    if not digest_valid(before) or not digest_valid(after):
        raise ValueError("Report digest mismatch. Evidence may have changed.")
    if before.get("workspace_name") != after.get("workspace_name"):
        raise ValueError("Reports do not refer to the same named workspace")
    old_ok = {r["engine"] for r in before["checks"] if r["status"] == "complete"}
    new_ok = {r["engine"] for r in after["checks"] if r["status"] == "complete"}
    overlap = old_ok & new_ok
    b = {f["fingerprint"]: f for f in before["findings"] if f["engine"] in overlap}
    a = {f["fingerprint"]: f for f in after["findings"] if f["engine"] in overlap}
    return seal({
        "schema": COMPARISON_SCHEMA,
        "comparable_engines": sorted(overlap),
        "unverified_engines": sorted((old_ok | new_ok) - overlap),
        "removed_from_scan": [b[x] for x in sorted(b.keys() - a.keys())],
        "new_in_scan": [a[x] for x in sorted(a.keys() - b.keys())],
        "still_present": [a[x] for x in sorted(a.keys() & b.keys())],
        "verification_note": "Removed from scan does not prove a vulnerability was exploited or fixed. "
                             "Targeted regression tests and independent review are still required.",
    })


def read_report(path: Path) -> dict[str, Any]:
    result = json.loads(path.read_text(encoding="utf-8"))
    if not digest_valid(result):
        raise ValueError("Invalid report digest")
    return result


def write_report(path: Path, report: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Restrictive best-effort permissions for report with code paths/rule metadata.
    body = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(body)
