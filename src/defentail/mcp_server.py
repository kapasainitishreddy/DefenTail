"""Optional MCP interface. Install with: pip install -e '.[mcp]' then `defentail install`.

Workspace rules: DEFENTAIL_WORKSPACE pins one folder. Without it the server scans
the process working directory, which MCP clients set to the open project. MCP
clients cannot supply arbitrary filesystem roots, so every tool stays inside the
folder the user launched their agent in.
"""
from __future__ import annotations

import os
from pathlib import Path

from .compliance import soc2_evidence
from .core import doctor, guard, scan
from .intelligence import bundled_data, kev_status
from .memory import summary as memory_summary


def workspace_path() -> Path:
    raw = os.environ.get("DEFENTAIL_WORKSPACE") or os.getcwd()
    root = Path(raw).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("Workspace is not an existing directory")
    if root.parent == root:
        # An agent launched at a drive root would walk the whole filesystem.
        raise ValueError("Refusing to scan a filesystem root; open a project folder")
    return root


def main() -> None:
    try:
        # MCP Python SDK 2.x
        from mcp.server import MCPServer
    except ImportError:
        # MCP Python SDK 1.x
        from mcp.server.fastmcp import FastMCP as MCPServer

    app = MCPServer("Syrava DefenTail")

    @app.tool()
    def defentail_guard(profile: str = "basic") -> dict:
        """Call this before telling the user a task is finished.

        Returns a short BLOCK/PASS verdict for the open project, the blocking
        findings in plain language, and what still needs review. A PASS covers
        only the checks listed in coverage; it is never proof the app is secure.
        """
        if profile not in ("basic", "quick", "full"):
            raise ValueError("Invalid profile")
        return guard(workspace_path(), profile=profile)

    @app.tool()
    def defentail_memory() -> dict:
        """This project's Attack Memory: how often each finding was seen before, and
        which ones came back after looking clear. Use it to avoid re-litigating an old issue.
        """
        return memory_summary(workspace_path())

    @app.tool()
    def defentail_soc2(profile: str = "basic") -> dict:
        """SOC 2 technical evidence for the open project: per-criterion support, what ran,
        and what a human still has to provide. This is evidence, never a certification.
        """
        if profile not in ("basic", "quick", "full"):
            raise ValueError("Invalid profile")
        return soc2_evidence(workspace_path(), profile=profile)

    @app.tool()
    def defentail_doctor() -> dict:
        """Check installed local security engines without executing them."""
        return {"tools": doctor(), "workspace": workspace_path().name}

    @app.tool()
    def defentail_lessons() -> dict:
        """Sourced and curated lessons from real-world security incidents."""
        return bundled_data("incidents.json")

    @app.tool()
    def defentail_policies(platform: str = "all") -> dict:
        """Policy evidence checklist. This cannot certify compliance."""
        if platform not in {"all", "ios", "android", "web"}:
            raise ValueError("Invalid platform")
        data = bundled_data("policies.json")
        return {"as_of": data["as_of"], "disclaimer": data["disclaimer"],
                "policies": [p for p in data["policies"] if platform in ("all", p["platform"])],
                "intelligence_status": kev_status()}

    @app.tool()
    def defentail_scan(profile: str = "basic") -> dict:
        """Full scan report for the open project with an evidence digest.
        Missing scanners make coverage incomplete and the gate fail closed.
        """
        if profile not in ("basic", "quick", "full"):
            raise ValueError("Invalid profile")
        return scan(workspace_path(), profile=profile)

    app.run(transport="stdio")


if __name__ == "__main__":
    main()
