"""Lightweight polling watch. Static source reads only; no project code execution."""
from __future__ import annotations

import os
import time
from pathlib import Path
from .core import scan
from .builtin import CODE_EXTS, SKIP_DIRS


def _snapshot(root: Path) -> tuple:
    entries = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS and not (Path(current) / name).is_symlink()]
        for name in names:
            file = Path(current) / name
            if file.is_symlink() or file.suffix.lower() not in CODE_EXTS and name not in ("package-lock.json", "package.json"):
                continue
            try:
                stat = file.stat()
                entries.append((str(file.relative_to(root)), stat.st_size, stat.st_mtime_ns))
            except OSError:
                continue
    return tuple(sorted(entries))


def watch_project(path: Path, interval: int = 3) -> None:
    root = Path(path).expanduser().resolve(strict=True)
    if interval < 1 or interval > 300 or not root.is_dir():
        raise ValueError("Choose an existing project folder and interval 1..300 seconds")
    print(f"Watching {root.name} for code changes. Scans use BASIC safety checks only. Ctrl+C to stop.", flush=True)
    prev = None
    try:
        while True:
            now = _snapshot(root)
            if now != prev:
                prev = now
                result = scan(root, profile="basic")
                print(f"[{result['generated_utc']}] {len(result['findings'])} findings (limited basic checks)", flush=True)
                for item in result["findings"][:12]:
                    print(f"  [{item['severity']}] {item['path']}:{item['line']} {item['title']}", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Stopped.")
