# DefenTail integration status

DefenTail is being designed as one security companion with multiple front ends. Those front ends should call the **same local security engine** and report the same coverage and limitations.

| Integration | Current status | How to use |
| --- | --- | --- |
| Terminal CLI | Available starter | `defentail scan --path /path/to/app --profile basic` |
| Beginner browser UI | Available starter | `defentail ui` |
| Continuous file watcher | Available starter (polling) | `defentail watch --path /path/to/app` |
| Plugin installer | Available starter | `defentail install --path .` writes the entry for every detected agent; `defentail agents` lists them; `defentail uninstall` reverses it |
| MCP tool server | Available starter (stdio) | Registered by `defentail install`, or run `python -m defentail.mcp_server`. Scans the launch folder, or `DEFENTAIL_WORKSPACE` when pinned |
| Agent guard verdict | Available starter | `defentail guard --path . --json` or the `defentail_guard` MCP tool; exits `2` on BLOCK |
| Attack Memory | Available starter | `.defentail/memory.jsonl`; `defentail memory --path .` or the `defentail_memory` tool |
| SOC 2 evidence pack | Available starter | `defentail soc2 --path . --output evidence/soc2.json` or `defentail_soc2` |
| Coding-agent skill | Included as instructions | `integrations/defentail-skill/SKILL.md` |
| Cursor project rule | Available starter | `.cursor/rules/defentail.mdc`, written by the installer |
| Universal agent instructions | Available starter | `.defentail/AGENT_RULES.md`, readable by any model |
| Native hooks beyond MCP | Partial | Config entries are installed for Claude Code, Cursor, Windsurf, Gemini CLI, Codex CLI and VS Code; per-edit hooks and inline diagnostics are still planned |
| VS Code inline diagnostics | Planned | No published extension |
| ChatGPT plugin, marketplace or IDE extension | Planned | Not published; the installer writes local config only |
| CI gate | CLI exit codes are available | No GitHub Actions workflow bundled |
| Signed rulepack updater | Planned | Not implemented |
| Automatic safe patch testing | Planned | Not implemented |

## Security boundaries

- Local basic checks require no DefenTail account or cloud upload.
- Every optional external scanner has separate installation, license and network requirements.
- The MCP server scans the folder it was launched in, or the `DEFENTAIL_WORKSPACE` pinned at process start. Tools cannot accept an arbitrary filesystem root, and the server never executes scanned project code or writes to it.
- The installer edits only its own keys and files, backs up a user config it modifies, and refuses to rewrite a config it cannot parse.
- A skill file is only guidance. Agents must actually call DefenTail for it to have any effect.
- Treat third-party advisories, scanner output and rules as untrusted data. Review and validate updates before allowing them to change security decisions.
- Missing or failed checks must be reported as **unverified** rather than passed.

## Future plugin contract

A future stable plugin API should expose `health`, `scan_changes`, `scan_workspace`, `explain_finding`, `suggest_fix`, `verify_fix`, `check_policy_evidence` and `get_coverage`. All actions must return explicit coverage, provenance, confidence, version and timestamp fields. Mutating actions need human permission and test evidence. Existing experimental MCP tools must not be represented as fulfilling this contract yet.
