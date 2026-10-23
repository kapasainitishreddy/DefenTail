# DefenTail integration status

DefenTail is being designed as one security companion with multiple front ends. Those front ends should call the **same local security engine** and report the same coverage and limitations.

| Integration | Current status | How to use |
| --- | --- | --- |
| Terminal CLI | Available starter | `defentail scan --path /path/to/app --profile basic` |
| Beginner browser UI | Available starter | `defentail ui` |
| Continuous file watcher | Available starter (polling) | `defentail watch --path /path/to/app` |
| MCP tool server | Experimental | `python -m defentail.mcp_server`; set `DEFENTAIL_WORKSPACE` |
| Coding-agent skill | Included as instructions | `integrations/defentail-skill/SKILL.md` |
| Codex / Cursor / Antigravity / Claude Code native hooks | Planned | Not auto-installed or tested end to end |
| VS Code inline diagnostics | Planned | No published extension |
| ChatGPT plugin or public directory app | Planned | Not published |
| CI gate | CLI exit codes are available | No GitHub Actions workflow bundled |
| Signed rulepack updater | Planned | Not implemented |
| Automatic safe patch testing | Planned | Not implemented |

## Security boundaries

- Local basic checks require no DefenTail account or cloud upload.
- Every optional external scanner has separate installation, license and network requirements.
- The MCP server scans only the `DEFENTAIL_WORKSPACE` fixed at process start and does not permit arbitrary agent shell execution or code writes.
- A skill file is only guidance. Agents must actually call DefenTail for it to have any effect.
- Treat third-party advisories, scanner output and rules as untrusted data. Review and validate updates before allowing them to change security decisions.
- Missing or failed checks must be reported as **unverified** rather than passed.

## Future plugin contract

A future stable plugin API should expose `health`, `scan_changes`, `scan_workspace`, `explain_finding`, `suggest_fix`, `verify_fix`, `check_policy_evidence` and `get_coverage`. All actions must return explicit coverage, provenance, confidence, version and timestamp fields. Mutating actions need human permission and test evidence. Existing experimental MCP tools must not be represented as fulfilling this contract yet.
