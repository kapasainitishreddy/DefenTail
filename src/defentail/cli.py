"""DefenTail command-line entrypoint."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .core import compare, doctor, read_report, scan, write_report
from .intelligence import bundled_data, kev_status, update_kev


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="defentail", description="Local-first security assistant. No source uploads by DefenTail.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Check which open-source scanners are available")
    scan_cmd = sub.add_parser("scan", help="Scan a project folder")
    scan_cmd.add_argument("--path", type=Path, default=Path.cwd())
    scan_cmd.add_argument("--profile", choices=["basic", "quick", "full"], default="basic")
    scan_cmd.add_argument("--timeout", type=int, default=180)
    scan_cmd.add_argument("--output", type=Path, help="Save a machine-readable JSON evidence report")
    scan_cmd.add_argument("--json", action="store_true", help="Print JSON report, not a human summary")
    ui_cmd = sub.add_parser("ui", help="Start the private beginner-friendly browser UI")
    ui_cmd.add_argument("--path", type=Path, default=Path.cwd())
    ui_cmd.add_argument("--port", type=int, default=0)
    ui_cmd.add_argument("--no-browser", action="store_true")
    watch = sub.add_parser("watch", help="Repeat basic checks when project code changes")
    watch.add_argument("--path", type=Path, default=Path.cwd())
    watch.add_argument("--interval", type=int, default=3)
    cmp_cmd = sub.add_parser("compare", help="Compare signed-by-digest (not cryptographically signed) scan reports")
    cmp_cmd.add_argument("before", type=Path)
    cmp_cmd.add_argument("after", type=Path)
    cmp_cmd.add_argument("--output", type=Path)
    sub.add_parser("update-intel", help="Explicitly download recent CISA exploited-vulnerability data (requires internet)")
    sub.add_parser("intel-status", help="See how old the local exploit-intelligence snapshot is")
    sub.add_parser("check-policies", help="Opt-in check official policy sites for possible changes (requires internet)")
    lesson_cmd = sub.add_parser("lessons", help="Show curated real incident lessons with links")
    lesson_cmd.add_argument("--json", action="store_true")
    policy_cmd = sub.add_parser("policies", help="Show versioned compliance checklists (not certification)")
    policy_cmd.add_argument("--platform", choices=["ios", "android", "web", "all"], default="all")
    policy_cmd.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            print(json.dumps({"tools": doctor(), "cisa_feed": kev_status()}, indent=2))
            return 0
        if args.command == "scan":
            result = scan(args.path, profile=args.profile, timeout=args.timeout)
            if args.output:
                write_report(args.output, result)
                if not args.json:
                    print(f"Report saved: {args.output}")
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print("Coverage: " + ", ".join(f"{x['engine']}={x['status']}" for x in result["checks"]))
                print(f"Findings: {len(result['findings'])}")
                for i in result["findings"][:12]:
                    print(f"  [{i['severity']}] {i['path']}:{i['line']} - {i['title']}")
                if result["profile"] == "basic":
                    print("BASIC CHECKS ONLY. This cannot verify the app is secure.")
                print("Gate: PASS FOR SELECTED CHECKS" if result["gate"]["passed"] else "Gate: BLOCKED or UNVERIFIED")
            return 0 if result["gate"]["passed"] else 2
        if args.command == "compare":
            result = compare(read_report(args.before), read_report(args.after))
            if args.output:
                write_report(args.output, result)
            print(json.dumps({k: v for k, v in result.items()
                              if k not in {"still_present", "removed_from_scan", "new_in_scan"}}, indent=2))
            print(f"Removed from scan: {len(result['removed_from_scan'])}; New: {len(result['new_in_scan'])}")
            return 0 if not result["new_in_scan"] and bool(result["comparable_engines"]) else 2
        if args.command == "ui":
            from .ui import serve
            if not 0 <= args.port <= 65535:
                raise ValueError("Port out of range")
            serve(args.path, port=args.port, launch=not args.no_browser)
            return 0
        if args.command == "watch":
            from .watch import watch_project
            watch_project(args.path, interval=args.interval)
            return 0
        if args.command == "update-intel":
            status = update_kev()
            print(json.dumps(status, indent=2))
            return 0
        if args.command == "check-policies":
            from .policy_monitor import monitor_policies
            items = monitor_policies()
            print(json.dumps(items, indent=2))
            return 2 if any(x["status"] in ("possible-change", "unavailable") for x in items) else 0
        if args.command == "intel-status":
            print(json.dumps(kev_status(), indent=2))
            return 0
        if args.command == "lessons":
            data = bundled_data("incidents.json")
            if args.json:
                print(json.dumps(data, indent=2))
            else:
                for i in data["incidents"]:
                    print(f"{i['id']}: {i['title']}\n  In simple words: {i['plain_english']}\n"
                          f"  Prevention: {i['technical_lesson']}\n  How to test: {i['test_plan']}\n"
                          f"  Source: {i['sources'][0]}\n")
            return 0
        if args.command == "policies":
            data = bundled_data("policies.json")
            entries = [p for p in data["policies"] if args.platform in ("all", p["platform"])]
            if args.json:
                print(json.dumps({"disclaimer": data["disclaimer"], "entries": entries}, indent=2))
            else:
                print(f"Policy snapshot: {data['as_of']}\n{data['disclaimer']}\n")
                for p in entries:
                    print(f"[{p['platform']}] {p['title']} ({p['source_section']})\n"
                          f"  In simple words: {p['simple']}\n  Review evidence: {', '.join(p['evidence'])}\n"
                          f"  Source: {p['source']} (checked {p['reviewed']})\n")
            return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"DefenTail error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
