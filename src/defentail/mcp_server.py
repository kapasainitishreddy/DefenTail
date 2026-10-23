"""Optional MCP interface. Install with: pip install -e '.[mcp]'.

Only scans DEFENTAIL_WORKSPACE. MCP clients cannot supply arbitrary filesystem roots.
"""
from __future__ import annotations

import os
from pathlib import Path
from .core import doctor, scan
from .intelligence import bundled_data, kev_status


def main() -> None:
    try:
        # MCP Python SDK 2.x
        from mcp.server import MCPServer
    except ImportError:
        # MCP Python SDK 1.x
        from mcp.server.fastmcp import FastMCP as MCPServer

    app = MCPServer("Syrava DefenTail")
    workspace = Path(os.environ.get("DEFENTAIL_WORKSPACE", ".")).resolve()

    @app.tool()
    def defentail_doctor() -> dict:
        """Check installed local security engines without executing them."""
        return {"tools": doctor(), "workspace": workspace.name}

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
        """Scan the authorized workspace with quick or full security checks.
        Missing scanners make coverage incomplete and gate fail closed.
        """
        if profile not in ("basic", "quick", "full"):
            raise ValueError("Invalid profile")
        return scan(workspace, profile=profile)

    app.run(transport="stdio")


if __name__ == "__main__":
    main()
