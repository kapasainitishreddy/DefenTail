"""Opt-in source-change alerts for official policy pages, not automatic rule updates."""
from __future__ import annotations

import datetime as dt
import hashlib
import html.parser
import json
import os
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

from .intelligence import bundled_data, intel_file

MAX_PAGE_BYTES = 2 * 1024 * 1024


class PageText(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skip = 0
        self.text = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "svg"):
            self.skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "svg"):
            self.skip = max(self.skip - 1, 0)

    def handle_data(self, data):
        if not self.skip and data.strip():
            self.text.append(data.strip())


def normalized_html_digest(raw: bytes) -> str:
    parser = PageText()
    parser.feed(raw.decode("utf-8", errors="replace"))
    normalized = " ".join(" ".join(parser.text).split())
    if len(normalized) < 400:
        raise ValueError("Policy page contained insufficient text to compare")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def monitor_file() -> Path:
    return intel_file().with_name("policy-source-hashes.json")


def monitor_policies() -> list[dict]:
    """Fetch known official URLs over HTTPS, signal content changes and preserve last baseline."""
    originals = {p["source"] for p in bundled_data("policies.json")["policies"]}
    target = monitor_file()
    try:
        prior = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(prior, dict):
            prior = {}
    except (OSError, ValueError, TypeError):
        prior = {}
    new = dict(prior)
    alerts = []
    for url in sorted(originals):
        if urllib.parse.urlsplit(url).scheme != "https":
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Syrava-DefenTail/0.2 policy-watch"})
            with urllib.request.urlopen(req, timeout=16) as res:
                final = urllib.parse.urlsplit(res.geturl())
                original = urllib.parse.urlsplit(url)
                if final.scheme != "https" or final.hostname != original.hostname:
                    raise ValueError("Official policy page redirected to an unexpected origin")
                raw = res.read(MAX_PAGE_BYTES + 1)
            if len(raw) > MAX_PAGE_BYTES:
                raise ValueError("Policy response larger than the safety limit")
            digest = normalized_html_digest(raw)
            last = prior.get(url, {}) if isinstance(prior.get(url, {}), dict) else {}
            status = "unchanged" if last.get("digest") == digest else "possible-change" if last.get("digest") else "baseline-created"
            record = {"digest": digest, "checked_utc": dt.datetime.now(dt.timezone.utc).isoformat()}
            new[url] = record
            alerts.append({"source": url, "status": status, "note": "A changed page requires manual policy review, not an automatic compliance rule."})
        except (OSError, ValueError, UnicodeError) as exc:
            alerts.append({"source": url, "status": "unavailable", "note": "Could not verify remote source; saved baseline was kept"})
    if new != prior:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent,
                                             prefix="policies-", suffix=".tmp", delete=False) as f:
                tmp = Path(f.name)
                json.dump(new, f, indent=2)
            os.replace(tmp, target)
        finally:
            if tmp is not None:
                tmp.unlink(missing_ok=True)
    return alerts
