"""DefenTail command-line entrypoint."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .compliance import soc2_evidence
from .core import compare, doctor, guard, read_report, scan, write_report
from .intelligence import bundled_data, kev_status, update_kev
from .memory import record_scan
from .memory import summary as memory_summary
from .plugin import AGENTS, detect_agents, install, uninstall


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
    guard_cmd = sub.add_parser("guard", help="Short shipping verdict for an AI agent (block or pass)")
    guard_cmd.add_argument("--path", type=Path, default=Path.cwd())
    guard_cmd.add_argument("--profile", choices=["basic", "quick", "full"], default="basic")
    guard_cmd.add_argument("--json", action="store_true", help="Print the compact JSON verdict")
    install_cmd = sub.add_parser("install", help="Install DefenTail as a plugin for every AI coding agent")
    install_cmd.add_argument("--path", type=Path, default=Path.cwd(), help="Project folder the plugin should protect")
    install_cmd.add_argument("--target", default="all",
                             help="all, or a comma-separated list: " + ",".join(AGENTS))
    install_cmd.add_argument("--no-project-files", action="store_true",
                             help="Only edit user-level agent configs, write nothing into the project")
    install_cmd.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    install_cmd.add_argument("--json", action="store_true")
    uninstall_cmd = sub.add_parser("uninstall", help="Remove the DefenTail plugin entries")
    uninstall_cmd.add_argument("--path", type=Path, default=Path.cwd())
    uninstall_cmd.add_argument("--target", default="all")
    uninstall_cmd.add_argument("--dry-run", action="store_true")
    sub.add_parser("agents", help="Show which AI agents were detected on this computer")
    memory_cmd = sub.add_parser("memory", help="Show this project's Attack Memory: scans, decisions, recurring findings")
    memory_cmd.add_argument("--path", type=Path, default=Path.cwd())
    memory_cmd.add_argument("--json", action="store_true")
    soc2_cmd = sub.add_parser("soc2", help="Build SOC 2 technical evidence for this project (not an audit)")
    soc2_cmd.add_argument("--path", type=Path, default=Path.cwd())
    soc2_cmd.add_argument("--profile", choices=["basic", "quick", "full"], default="basic")
    soc2_cmd.add_argument("--output", type=Path, help="Write the evidence pack JSON here")
    soc2_cmd.add_argument("--json", action="store_true")
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
            record_scan(args.path, result)
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
        if args.command == "guard":
            result = guard(args.path, profile=args.profile)
            if args.json:
                print(json.dumps(result, indent=2))
                return 0 if result["can_ship"] else 2
            print(f"Verdict: {result['verdict']} - {result['summary']}")
            for item in result["blocking"]:
                print(f"  [{item['severity']}] {item['path']}:{item['line']} {item['title']}")
                print(f"    Why it matters: {item['why_it_matters']}")
                print(f"    Next step: {item['next_step']}")
            print("Coverage: " + ", ".join(f"{c['engine']}={c['status']}" for c in result["coverage"]))
            print(result["honesty"])
            return 0 if result["can_ship"] else 2
        if args.command == "install":
            report = install(args.path, targets=args.target, project_files=not args.no_project_files,
                             dry_run=args.dry_run)
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print(f"Workspace: {report['workspace']}" + (" (dry run, nothing written)" if report["dry_run"] else ""))
                for action in report["actions"]:
                    label = action.get("label", action["target"])
                    print(f"  [{action['outcome']}] {label} -> {action['path']}")
                print(f"Changed: {report['changed']}")
                for warning in report.get("warnings", []):
                    print(f"  ! {warning}")
                for step in report["next_steps"]:
                    print(f"  - {step}")
            return 0
        if args.command == "uninstall":
            report = uninstall(args.path, targets=args.target, dry_run=args.dry_run)
            for action in report["actions"]:
                print(f"  [{action['outcome']}] {action.get('label', action['target'])} -> {action['path']}")
            return 0
        if args.command == "memory":
            data = memory_summary(args.path)
            if args.json:
                print(json.dumps(data, indent=2))
                return 0
            print(f"Memory file: {data['memory_file']}")
            print(f"Scans: {data['scans']} | Decisions: {data['decisions']} "
                  f"({data['blocked_decisions']} blocked, {data['passed_decisions']} passed)")
            if not data["recurring_findings"]:
                print("No recurring finding yet. Memory fills up as scans run.")
            for item in data["recurring_findings"]:
                mark = " returned after being clear;" if item.get("reappeared") else ""
                print(f"  [{item.get('severity')}] {item.get('path')}:{item.get('line')} "
                      f"{item.get('rule_id')} seen {item['times_seen']}x{mark}")
            print(data["note"])
            return 0
        if args.command == "soc2":
            pack = soc2_evidence(args.path, profile=args.profile)
            if args.output:
                write_report(args.output, pack)
            if args.json:
                print(json.dumps(pack, indent=2))
                return 0
            counts = pack["control_summary"]
            print(f"SOC 2 technical evidence for {pack['scope']['workspace_name']} ({args.profile})")
            for status, count in counts.items():
                print(f"  {status:32} {count}")
            for criterion in pack["criteria"]:
                print(f"  {criterion['id']:6} {criterion['title'][:42]:44} {criterion['status']}")
            print(f"Gaps recorded: {len(pack['gaps'])}")
            if args.output:
                print(f"Evidence pack saved: {args.output}")
            print("Technical evidence only. This is not an audit opinion or a SOC 2 certification.")
            return 0
        if args.command == "agents":
            home = Path.home()
            detected = detect_agents(home)
            for name, spec in AGENTS.items():
                state = "detected" if detected[name] else "not found"
                print(f"{state:10} {spec['label']:32} {home / spec['path']}")
            print("\nInstall for all detected agents: defentail install --path .")
            return 0
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
