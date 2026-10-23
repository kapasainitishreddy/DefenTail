"""Curated incident lessons and opt-in feed updater (never evaluates feed text)."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from importlib import resources

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
MAX_FEED_BYTES = 16 * 1024 * 1024


def bundled_data(name: str) -> dict:
    if name not in ("incidents.json", "policies.json"):
        raise ValueError("Unknown bundled data file")
    data = resources.files("defentail").joinpath("data", name).read_text(encoding="utf-8")
    return json.loads(data)


def intel_file() -> Path:
    return Path(os.environ.get("DEFENTAIL_DATA_HOME", str(Path.home() / ".defentail"))).expanduser() / "intel" / "cisa-kev.json"


def kev_status() -> dict:
    path = intel_file()
    if not path.is_file():
        return {"status": "missing", "record_count": 0, "message": "No downloaded CISA KEV catalog yet. Run 'defentail update-intel' when online."}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        count = len(data["vulnerabilities"])
        date = dt.datetime.fromisoformat(data["retrieved_utc"])
        age = (dt.datetime.now(dt.timezone.utc) - date).total_seconds() / 86400
        return {"status": "fresh" if age <= 7 else "stale", "record_count": count,
                "retrieved_utc": data["retrieved_utc"], "sha256": data["sha256"], "age_days": round(age, 1)}
    except (OSError, KeyError, TypeError, ValueError):
        return {"status": "invalid", "record_count": 0, "message": "Downloaded intelligence file failed validation"}


def _validate_kev(data: object) -> list[dict]:
    if not isinstance(data, dict):
        raise ValueError("KEV catalog is not an object")
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities or len(vulnerabilities) > 100_000:
        raise ValueError("KEV catalog is empty or too large")
    seen = set()
    cleaned = []
    for rec in vulnerabilities:
        if not isinstance(rec, dict):
            raise ValueError("Invalid KEV entry")
        cve = rec.get("cveID")
        if not isinstance(cve, str) or not cve.startswith("CVE-") or len(cve) > 35:
            raise ValueError("Invalid CVE field")
        if cve in seen:
            continue
        seen.add(cve)
        cleaned.append({"cveID": cve, "dateAdded": str(rec.get("dateAdded", ""))[:10],
                        "vendorProject": str(rec.get("vendorProject", ""))[:100],
                        "product": str(rec.get("product", ""))[:120]})
    return cleaned


def update_kev(timeout: int = 20) -> dict:
    """Opt-in TLS download. Enforces small response and schema, atomic last-good cache."""
    raw = None
    selected_url = None
    cleaned = None
    # An invalid or truncated primary feed should also try the official CISA GitHub mirror.
    for candidate in (KEV_URL, KEV_MIRROR):
        req = urllib.request.Request(candidate, headers={"User-Agent": "Syrava-DefenTail/0.2 (+local defense feed)"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as res:
                final = urllib.parse.urlsplit(res.geturl())
                if final.scheme != "https":
                    raise ValueError("Source redirected to non-HTTPS")
                candidate_raw = res.read(MAX_FEED_BYTES + 1)
            if len(candidate_raw) > MAX_FEED_BYTES:
                raise ValueError("Catalog exceeded 16 MiB download limit")
            candidate_cleaned = _validate_kev(json.loads(candidate_raw.decode("utf-8")))
            raw, cleaned, selected_url = candidate_raw, candidate_cleaned, candidate
            break
        except (OSError, TimeoutError, ValueError, UnicodeError):
            continue
    if raw is None or selected_url is None or cleaned is None:
        raise ValueError("Official CISA feeds unavailable or invalid; existing local data was preserved")
    payload = {"schema": "defentail.kev.snapshot.v1", "source": selected_url,
               "retrieved_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
               "sha256": hashlib.sha256(raw).hexdigest(), "vulnerabilities": cleaned}
    path = intel_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix="kev-", suffix=".tmp", delete=False) as f:
            tmp_path = Path(f.name)
            json.dump(payload, f, separators=(",", ":"))
        os.replace(tmp_path, path)
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
    return kev_status()


def known_exploited_ids() -> set[str]:
    path = intel_file()
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {rec["cveID"] for rec in data["vulnerabilities"] if isinstance(rec.get("cveID"), str)}
    except (KeyError, OSError, ValueError, TypeError):
        return set()
