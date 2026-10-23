"""One-command installation of DefenTail as a plugin for AI coding agents.

Every AI model reaches tools in a different way: some speak MCP over JSON config,
Codex uses TOML, VS Code uses a project file, and some only read instruction
markdown. This module writes the smallest correct entry for each, never touches
keys or files it does not own, backs up any user configuration it edits, and
refuses to overwrite a config it cannot parse.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

SERVER_NAME = "defentail"
MODULE = ["-m", "defentail.mcp_server"]
BACKUP_SUFFIX = ".defentail-backup"

# name -> (human label, config path relative to home, format, detection markers)
AGENTS: dict[str, dict[str, Any]] = {
    "claude": {
        "label": "Claude Code / Claude Desktop",
        "path": Path(".claude.json"),
        "format": "json",
        "key": "mcpServers",
        "markers": [Path(".claude"), Path(".claude.json")],
    },
    "cursor": {
        "label": "Cursor",
        "path": Path(".cursor/mcp.json"),
        "format": "json",
        "key": "mcpServers",
        "markers": [Path(".cursor")],
    },
    "windsurf": {
        "label": "Windsurf",
        "path": Path(".codeium/windsurf/mcp_config.json"),
        "format": "json",
        "key": "mcpServers",
        "markers": [Path(".codeium/windsurf")],
    },
    "gemini": {
        "label": "Gemini CLI",
        "path": Path(".gemini/settings.json"),
        "format": "json",
        "key": "mcpServers",
        "markers": [Path(".gemini")],
    },
    "codex": {
        "label": "Codex CLI",
        "path": Path(".codex/config.toml"),
        "format": "toml",
        "key": "mcp_servers",
        "markers": [Path(".codex")],
    },
}

CURSOR_RULE = """---
description: Run DefenTail security checks before finishing a change
alwaysApply: true
---

# DefenTail security gate

Before you report a coding task as complete, run the security guard and report
its real result:

```bash
defentail guard --path . --json
```

Rules for using it:

1. If the guard says BLOCK, do not describe the work as finished. Explain the
   blocking finding in everyday words and propose the smallest safe fix.
2. Never silence a finding by disabling TLS checks, weakening authorization, or
   adding an ignore rule without the user's explicit approval.
3. A passing result only covers the checks that actually ran. Say which scanners
   were unavailable instead of implying the app is secure.
4. Never print secret values, and never send source code to a third-party service
   from this project.
5. A finding removed from a scan is not proof it was fixed: rerun the affected
   tests and show the evidence.
"""

AGENT_RULES = """# DefenTail security rules for any AI coding agent

This project uses DefenTail. Any model that can run a shell command can use it —
no MCP, account, or paid API is required.

## Before you finish a change

```bash
defentail guard --path . --json
```

- `BLOCK` means a high/critical finding, an untriaged finding, or a scanner that
  was required but did not run. Do not call the task complete.
- `PASS_SELECTED_CHECKS` only covers the checks that actually ran. Never restate
  it as "secure", "unhackable", or "compliant".

## Verify a fix

```bash
defentail scan --path . --profile basic --output defentail-before.json
# ...apply the fix, run the relevant tests...
defentail scan --path . --profile basic --output defentail-after.json
defentail compare defentail-before.json defentail-after.json
```

A disappearance from the scan is evidence to review, not proof of a fix.

## Hard rules

- Never print, log, or commit secret values found by a scan.
- Never disable certificate validation, weaken authorization, or add a blanket
  ignore just to make the gate green without the user's explicit approval.
- Never claim compliance certification or store approval.
"""

VSCODE_MCP_NOTE = "VS Code reads this file for agent mode (Copilot)."


def python_command() -> str:
    """Return the interpreter that can import DefenTail, fallback to 'python'."""
    exe = sys.executable
    return exe if isinstance(exe, str) and exe else "python"


def server_entry(*, vscode: bool = False) -> dict[str, Any]:
    entry: dict[str, Any] = {"command": python_command(), "args": list(MODULE)}
    if vscode:
        return {"type": "stdio", **entry}
    return entry


def detect_agents(home: Path) -> dict[str, bool]:
    found = {}
    for name, spec in AGENTS.items():
        found[name] = any((home / marker).exists() for marker in spec["markers"])
    return found


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("top level is not an object")
    return data


def _unsafe_target(path: Path) -> bool:
    """Never write through a symlink: a linked config could redirect the write elsewhere."""
    return path.is_symlink()


def _write_text(path: Path, body: str, *, dry_run: bool, backup: bool = True) -> None:
    if dry_run:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if backup and path.is_file():
        # Keep the user's original file. Never let a later run overwrite that snapshot.
        target = path.with_name(path.name + BACKUP_SUFFIX)
        if not target.exists():
            shutil.copy2(path, target)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".defentail-", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(body)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _toml_string(value: str) -> str:
    # JSON escaping (backslashes, quotes) is valid TOML basic-string escaping.
    return json.dumps(value, ensure_ascii=True)


def _toml_block() -> str:
    return (
        "\n[mcp_servers.defentail]\n"
        "# Added by Syrava DefenTail. Remove this section to uninstall.\n"
        f"command = {_toml_string(python_command())}\n"
        'args = ["-m", "defentail.mcp_server"]\n'
        "\n[mcp_servers.defentail.env]\n"
        "# Optional: set DEFENTAIL_WORKSPACE to pin scans to one project folder.\n"
        'DEFENTAIL_WORKSPACE = ""\n'
    )


def _strip_toml_section(text: str) -> str:
    lines = text.splitlines(keepends=True)
    kept: list[str] = []
    skipping = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and not stripped.startswith("[" + "["):
            header = stripped.strip("[]").strip()
            skipping = header == "mcp_servers.defentail" or header.startswith("mcp_servers.defentail.")
        if not skipping:
            kept.append(line)
    return "".join(kept)


def _install_json(path: Path, *, key: str, entry: dict[str, Any], dry_run: bool) -> str:
    if _unsafe_target(path):
        return "skipped-symlink"
    try:
        data = _load_json(path)
    except (OSError, UnicodeError, ValueError):
        return "skipped-unreadable-config"
    servers = data.get(key)
    if servers is None:
        servers = {}
        data[key] = servers
    if not isinstance(servers, dict):
        return "skipped-conflicting-key"
    if servers.get(SERVER_NAME) == entry:
        return "already-configured"
    ours_already = SERVER_NAME in servers
    servers[SERVER_NAME] = entry
    # No backup is needed when the only thing being replaced is our own previous entry.
    _write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                dry_run=dry_run, backup=not ours_already)
    return "configured"


def _install_toml(path: Path, *, dry_run: bool) -> str:
    if _unsafe_target(path):
        return "skipped-symlink"
    try:
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
    except (OSError, UnicodeError):
        return "skipped-unreadable-config"
    if "[mcp_servers.defentail]" in text:
        return "already-configured"
    prefix = "" if not text or text.endswith("\n") else "\n"
    _write_text(path, text + prefix + _toml_block(), dry_run=dry_run)
    return "configured"


def _remove_json(path: Path, *, key: str, dry_run: bool) -> str:
    if _unsafe_target(path):
        return "skipped-symlink"
    if not path.is_file():
        return "not-present"
    try:
        data = _load_json(path)
    except (OSError, UnicodeError, ValueError):
        return "skipped-unreadable-config"
    servers = data.get(key)
    if not isinstance(servers, dict) or SERVER_NAME not in servers:
        return "not-present"
    servers.pop(SERVER_NAME)
    # A file that now holds nothing but an empty container was created for us: remove it.
    if list(data) == [key] and data[key] == {}:
        if not dry_run:
            path.unlink()
        return "removed"
    _write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n", dry_run=dry_run, backup=False)
    return "removed"


def _remove_toml(path: Path, *, dry_run: bool) -> str:
    if _unsafe_target(path):
        return "skipped-symlink"
    if not path.is_file():
        return "not-present"
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "skipped-unreadable-config"
    if "[mcp_servers.defentail]" not in text:
        return "not-present"
    _write_text(path, _strip_toml_section(text), dry_run=dry_run, backup=False)
    return "removed"


def _project_targets(workspace: Path) -> list[tuple[str, Path, str]]:
    """Project-scoped surfaces usable without touching the user's home folder."""
    return [
        ("claude-project", workspace / ".mcp.json", "json"),
        ("vscode-project", workspace / ".vscode" / "mcp.json", "vscode"),
        ("cursor-rule", workspace / ".cursor" / "rules" / "defentail.mdc", "text"),
        ("agent-rules", workspace / ".defentail" / "AGENT_RULES.md", "text"),
    ]


def _selected(targets: str | list[str] | tuple[str, ...], detected: dict[str, bool]) -> list[str]:
    if isinstance(targets, str):
        targets = [part.strip() for part in targets.split(",") if part.strip()]
    if any(t in ("all", "*") for t in targets):
        chosen = [name for name, present in detected.items() if present]
        return chosen or list(AGENTS)
    unknown = [t for t in targets if t not in AGENTS]
    if unknown:
        raise ValueError("Unknown target(s): " + ", ".join(unknown) + ". Choose from: " + ", ".join(AGENTS))
    return list(dict.fromkeys(targets))


def install(workspace: Path, *, targets: str | list[str] = "all", home: Path | None = None,
            project_files: bool = True, dry_run: bool = False) -> dict[str, Any]:
    workspace = Path(workspace).expanduser().resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError("workspace must be an existing directory")
    home = Path(home).expanduser() if home is not None else Path.home()
    detected = detect_agents(home)
    chosen = _selected(targets, detected)
    actions: list[dict[str, Any]] = []
    for name in chosen:
        spec = AGENTS[name]
        path = home / spec["path"]
        if not detected[name] and isinstance(targets, str) and targets.strip() in ("all", "*"):
            actions.append({"target": name, "label": spec["label"], "path": str(path),
                            "outcome": "not-detected"})
            continue
        if spec["format"] == "toml":
            outcome = _install_toml(path, dry_run=dry_run)
        else:
            outcome = _install_json(path, key=spec["key"], entry=server_entry(), dry_run=dry_run)
        actions.append({"target": name, "label": spec["label"], "path": str(path), "outcome": outcome})
    if project_files:
        wanted = {name: (path, kind) for name, path, kind in _project_targets(workspace)}
        for name in ("claude-project", "vscode-project"):
            path, kind = wanted[name]
            outcome = _install_json(path, key="servers" if kind == "vscode" else "mcpServers",
                                    entry=server_entry(vscode=(kind == "vscode")), dry_run=dry_run)
            actions.append({"target": name, "path": str(path), "outcome": outcome})
        for name, body in (("cursor-rule", CURSOR_RULE), ("agent-rules", AGENT_RULES)):
            path, _ = wanted[name]
            if _unsafe_target(path):
                actions.append({"target": name, "path": str(path), "outcome": "skipped-symlink"})
                continue
            if path.is_file() and path.read_text(encoding="utf-8", errors="replace") == body:
                outcome = "already-configured"
            else:
                _write_text(path, body, dry_run=dry_run)
                outcome = "configured"
            actions.append({"target": name, "path": str(path), "outcome": outcome})
    warnings = []
    if importlib.util.find_spec("mcp") is None:
        warnings.append(
            "The 'mcp' package is not installed for this Python, so MCP clients cannot start the "
            "server. Install it with: " + f'"{python_command()}" -m pip install "syrava-defentail[mcp]"'
            + "; or use `defentail guard --path . --json`, which needs no SDK."
        )
    return {
        "workspace": str(workspace),
        "dry_run": dry_run,
        "actions": actions,
        "changed": sum(1 for a in actions if a["outcome"] == "configured"),
        "warnings": warnings,
        "next_steps": [
            "Restart or reload your AI agent so it picks up the new server.",
            "In a chat, ask the model to call defentail_guard before finishing a change.",
            "No MCP support? Any model can run: defentail guard --path . --json",
        ],
    }


def uninstall(workspace: Path, *, targets: str | list[str] = "all", home: Path | None = None,
              project_files: bool = True, dry_run: bool = False) -> dict[str, Any]:
    workspace = Path(workspace).expanduser().resolve(strict=True)
    home = Path(home).expanduser() if home is not None else Path.home()
    detected = detect_agents(home)
    chosen = _selected(targets, detected)
    actions: list[dict[str, Any]] = []
    for name in chosen:
        spec = AGENTS[name]
        path = home / spec["path"]
        if spec["format"] == "toml":
            outcome = _remove_toml(path, dry_run=dry_run)
        else:
            outcome = _remove_json(path, key=spec["key"], dry_run=dry_run)
        actions.append({"target": name, "label": spec["label"], "path": str(path), "outcome": outcome})
    if project_files:
        for name, path, kind in _project_targets(workspace):
            if kind == "text":
                if _unsafe_target(path):
                    actions.append({"target": name, "path": str(path), "outcome": "skipped-symlink"})
                    continue
                if path.is_file():
                    if not dry_run:
                        path.unlink()
                    outcome = "removed"
                else:
                    outcome = "not-present"
            else:
                outcome = _remove_json(path, key="servers" if kind == "vscode" else "mcpServers",
                                       dry_run=dry_run)
            actions.append({"target": name, "path": str(path), "outcome": outcome})
    return {"workspace": str(workspace), "dry_run": dry_run, "actions": actions,
            "changed": sum(1 for a in actions if a["outcome"] == "removed")}
