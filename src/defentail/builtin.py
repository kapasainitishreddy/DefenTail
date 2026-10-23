"""Conservative local safety checks. No source text or raw secret values in reports."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Callable, Any

# Small checks are educational signals, not a substitute for deep security testing.
SKIP_DIRS = {".git", "node_modules", ".next", ".venv", "venv", "dist", "build",
             "coverage", "vendor", "__pycache__", ".defentail", ".turbo"}
CODE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".java", ".rb", ".php", ".c", ".cpp"}
MAX_FILES = 5000
MAX_BYTES = 600_000
MAX_FINDINGS = 300

PATTERNS = [
    ("DT-TLS-VERIFY-DISABLED", "HIGH", "TLS certificate checking looks disabled.",
     "It's like accepting a fake ID without checking the photo.",
     "Re-enable certificate validation. Investigate local test-only exceptions separately.",
     re.compile(r"\bverify\s*=\s*False\b|\brejectUnauthorized\s*:\s*false\b", re.I)),
    ("DT-PY-SHELL-TRUE", "MEDIUM", "A Python process uses shell=True.",
     "Passing text to a command shell can be risky if people can control that text.",
     "Prefer subprocess.run([...], shell=False), and validate any input.",
     re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^\n]*\bshell\s*=\s*True", re.I)),
    ("DT-PRIVATE-KEY-IN-FILE", "HIGH", "A private-key marker was found (secret not shown).",
     "A private key is like a master door key. It must not be stored in public code.",
     "Remove the private key from version control, rotate if exposed, and use a secret manager.",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("DT-AWS-KEY-PATTERN", "HIGH", "A possible cloud access key was found (value hidden).",
     "Someone who sees a working access key might be able to use your cloud account.",
     "Investigate whether this is real; if exposed, revoke and rotate it.",
     re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
]


def _semver(version: object) -> tuple[int, int, int] | None:
    if not isinstance(version, str):
        return None
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        return None  # Pre-release/build metadata requires a proper semver library.
    return tuple(int(v) for v in version.split("."))


def _vulnerable_next(version: str) -> bool:
    v = _semver(version)
    if v is None:
        return False
    major = v[0]
    return major in {12, 13, 14, 15} and v < {
        12: (12, 3, 5), 13: (13, 5, 9), 14: (14, 2, 25), 15: (15, 2, 3)
    }[major]


def _node_lock_packages(lockfile: Path) -> dict[str, str]:
    if lockfile.stat().st_size > 12_000_000:
        raise ValueError("Lockfile too large for the basic built-in check")
    content = json.loads(lockfile.read_text(encoding="utf-8"))
    found = {}
    # npm lockfile v2/v3
    for location, item in (content.get("packages") or {}).items():
        if isinstance(location, str) and location.startswith("node_modules/") and isinstance(item, dict):
            version = item.get("version")
            if isinstance(version, str):
                found[location.rsplit("node_modules/", 1)[-1]] = version
    # npm lockfile v1: recursively inspect resolved exact package versions.
    def walk(items: Any) -> None:
        if not isinstance(items, dict):
            return
        for name, obj in items.items():
            if not isinstance(obj, dict):
                continue
            v = obj.get("version")
            if isinstance(v, str):
                found.setdefault(name, v)
            walk(obj.get("dependencies"))
    walk(content.get("dependencies"))
    return found


def builtin_scan(root: Path, make_finding: Callable[..., dict]) -> dict:
    """Always exits with an honest status. Bounded scan that ignores symlinks and large files."""
    found = []
    files_seen = 0
    skipped = 0
    partial = False
    ignored_by_symlink = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(current) / d).is_symlink()]
        for name in files:
            file = Path(current) / name
            if file.is_symlink():
                ignored_by_symlink += 1
                continue
            if file.suffix.lower() not in CODE_EXTS and name not in {".env", ".env.production", ".env.local"}:
                continue
            files_seen += 1
            if files_seen > MAX_FILES:
                partial = True
                break
            try:
                if file.stat().st_size > MAX_BYTES:
                    skipped += 1
                    partial = True
                    continue
                content = file.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeError):
                skipped += 1
                partial = True
                continue
            for i, line in enumerate(content.splitlines(), start=1):
                for rule, severity, title, plain, remedy, pattern in PATTERNS:
                    if (file.suffix.lower() in CODE_EXTS or name.startswith('.env')) and pattern.search(line):
                        item = make_finding("builtin", rule, str(file), i, severity, title, root)
                        item.update({"simple_explanation": plain, "suggested_action": remedy,
                                     "confidence": "pattern-match", "evidence_kind": "local-pattern"})
                        found.append(item)
                        if len(found) >= MAX_FINDINGS:
                            partial = True
                            break
                if len(found) >= MAX_FINDINGS:
                    break
            if len(found) >= MAX_FINDINGS:
                break
        if partial and (files_seen > MAX_FILES or len(found) >= MAX_FINDINGS):
            break
    # Recognize specific known package vulnerabilities from exact npm lockfile versions.
    # Package manifest version ranges alone are NOT reliable evidence of installed versions.
    lockfiles = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(current) / d).is_symlink()]
        if "package-lock.json" in names:
            lockfiles.append(Path(current) / "package-lock.json")
        if len(lockfiles) >= 100:
            partial = True
            break
    for path in lockfiles:
        if path.is_symlink():
            continue
        try:
            packages = _node_lock_packages(path)
        except (OSError, ValueError, TypeError, KeyError):
            partial = True
            continue
        v = packages.get("next")
        if v and _vulnerable_next(v):
            item = make_finding("builtin", "DT-NEXT-KNOWN-VERSION", str(path), 0, "CRITICAL",
                               "Installed Next.js version has a known authorization bypass advisory.", root)
            item.update({"incident_id": "CVE-2025-29927", "package_version": v,
                         "simple_explanation": "An old lock on some routes may be bypassed.",
                         "suggested_action": "Upgrade Next.js to an appropriate patched release, then test authorization at every route.",
                         "reference": "https://github.com/advisories/GHSA-f82v-jwr5-mffw"})
            found.append(item)
        for pack in ("react-server-dom-webpack", "react-server-dom-parcel", "react-server-dom-turbopack"):
            v = packages.get(pack)
            if v in {"19.0.0", "19.1.0", "19.1.1", "19.2.0"}:
                item = make_finding("builtin", "DT-REACT-RSC-KNOWN-VERSION", str(path), 0,
                                    "CRITICAL", "React Server Components dependency matches a vulnerable release.", root)
                item.update({"incident_id": "CVE-2025-55182", "package": pack, "package_version": v,
                             "simple_explanation": "A dangerous bug in an old component can let a stranger give the server instructions.",
                             "suggested_action": "Upgrade the affected package and its framework to the latest patched security release.",
                             "reference": "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components"})
                found.append(item)
    # Review-only lesson from 2025 npm supply chain; not a confirmed compromise.
    pkg = root / "package.json"
    if pkg.is_file() and not pkg.is_symlink():
        try:
            manifest = json.loads(pkg.read_text(encoding="utf-8"))
            scripts = manifest.get("scripts", {})
            if isinstance(scripts, dict) and any(k in scripts for k in ("preinstall", "install", "postinstall")):
                item = make_finding("builtin", "DT-NPM-LIFECYCLE-REVIEW", str(pkg), 0, "INFO",
                                    "Review npm install-time scripts and their privileges.", root)
                item.update({"incident_id": "CISA-2025-SHAI-HULUD",
                             "simple_explanation": "Packages can run extra steps during installation. Review them before trusting them.",
                             "suggested_action": "Review package provenance, install scripts, and permissions. A script is not evidence of malware."})
                found.append(item)
        except (OSError, UnicodeError, ValueError, TypeError):
            partial = True
    return {"engine": "builtin", "status": "partial" if partial else "complete", "findings": found,
            "duration_ms": 0, "reason": (f"Inspected at most {files_seen} files; {skipped} unreadable/oversized and "
                                     f"{ignored_by_symlink} symlink files skipped") if partial else "Conservative checks only; not a comprehensive security scan"}
