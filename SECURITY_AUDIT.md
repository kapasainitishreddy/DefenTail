# DefenTail security audit

**Target:** DefenTail 0.3.0 (`kapasainitishreddy/DefenTail`, commit `ef79d3b` + local changes)
**Date:** 2026-10-22
**Method:** source review of every trust boundary, live probing of the local UI, a real MCP session, and a dogfood scan of this repository with locally installed scanners.
**Verdict:** no remotely exploitable vulnerability was found. Two serious *product* defects made the tool report dishonest results and were fixed. Six defects fixed in total, plus two risks accepted deliberately and documented below.

This is an internal audit by the author's tooling, **not** an independent penetration test or certification. Nothing here proves the software cannot be hacked.

## What was actually executed

| Activity | Result |
| --- | --- |
| Unit + integration suite | 36 tests, all passing |
| `defentail scan --profile full` on this repo | trivy 0.74.0 **complete**, osv-scanner **not-applicable** (no manifest), semgrep and betterleaks **unavailable** (not installed) |
| Local UI probes (curl, loopback) | foreign `Host` → 403, missing CSRF token → 403, foreign `Origin` → 403, valid POST → 200 |
| Response headers | CSP `default-src 'none'`, `nosniff`, `no-store`, `no-referrer` present |
| Evidence report | digest verifies; secret fixture strings absent from HTML and JSON |
| MCP stdio session (SDK 2.3.0, throwaway venv) | `initialize` → 5 tools → `defentail_guard` returned `BLOCK` on a planted defect |

Not performed: fuzzing, dependency-CVE review of the MCP SDK itself, macOS/Linux runs, testing every agent client, independent review, code signing.

## Findings

| ID | Severity | Area | Status |
| --- | --- | --- | --- |
| F-01 | High (correctness, fails closed) | Trivy integration | Fixed |
| F-02 | High (correctness, fails closed) | OSV-Scanner integration | Fixed |
| F-03 | Medium | Feed ingestion (CISA KEV) | Fixed |
| F-04 | Low | Local UI link rendering | Fixed |
| F-05 | Low | Plugin installer file writes | Fixed |
| F-06 | Low | MCP workspace resolution | Fixed |
| A-01 | Accepted | Local UI has no authentication | Documented risk |
| A-02 | Accepted | Scanner binaries are trusted | Documented risk |

### F-01 — A clean Trivy scan was reported as a failure

**Impact:** every Trivy run that found nothing was graded `error`, so the release gate blocked forever on a project that is actually clean. Users learn to distrust or bypass the gate.

**Evidence:** Trivy 0.74.0 writes no `Results` key at all when it has nothing to report:

```json
{ "SchemaVersion": 2, "Trivy": { "Version": "0.74.0" }, "ReportID": "…", "Metadata": { … } }
```

`parse_trivy` required `Results` to be a list and raised `Invalid Trivy report`, which `_scanner_run` converts to `status: "error"`.

**Fix:** `parse_trivy` now treats a missing or `null` `Results` as an empty list, while still rejecting a malformed non-list value. Regression test: `test_clean_trivy_report_is_not_a_failure`.

### F-02 — OSV-Scanner blocked every project with no dependency manifest

**Impact:** on a project without a lockfile or manifest, OSV-Scanner exits `128` ("No package sources found"). DefenTail recorded that as a failed scan, so the gate could never pass — a permanent false BLOCK.

**Evidence:** `scan --format json -r <repo>` → exit 128, empty stdout, stderr "No package sources found".

**Fix:** before launching OSV, DefenTail runs a bounded check for a supported manifest (`package-lock.json`, `yarn.lock`, `requirements.txt`, `poetry.lock`, `uv.lock`, `go.mod`, `Cargo.lock`, `pom.xml`, …). When there is none, the engine is recorded as **`not-applicable`** — visible in coverage, but not counted as an incomplete check. An absent manifest means there is nothing to scan, not that the scan failed. Regression tests: `test_dependency_free_project_is_not_a_coverage_gap`, `test_not_applicable_engine_does_not_block_the_gate`.

**Why this is safe:** the change removes a blocker only when the scanner has no input. Genuine scanner failures, timeouts, missing binaries and unparseable reports still block the gate.

### F-03 — Feed download followed a redirect to any HTTPS host

**Impact:** `update-intel` validated only that the final URL used HTTPS, not where it pointed. A compromised or misconfigured redirect could deliver a feed from an unexpected origin.

**Why it was limited:** the payload is validated as data (schema, CVE format, size cap) and is never executed; only CVE IDs, dates, vendors and products are retained.

**Fix:** redirects are now restricted to `www.cisa.gov`, `cisa.gov` and `raw.githubusercontent.com`, matching what `check-policies` already did for policy pages. Regression test: `test_untrusted_feed_redirect_is_rejected`.

### F-04 — Policy links were rendered without a scheme check

**Impact:** `render_page` built `<a href='…'>` from bundled policy data without validating the scheme, unlike the report renderer, which already allowed only three HTTPS prefixes.

**Fix:** a `safe_link()` helper renders only absolute `http(s)` URLs and omits the anchor otherwise. Regression test: `test_ui_only_links_to_real_schemes`.

### F-05 — Installer could write through a symlinked config

**Impact:** if `~/.cursor/mcp.json` (or any project target) was a symlink, the installer would write to whatever it pointed at — for example overwriting an unrelated file the user can write.

**Fix:** every install, uninstall and project-file write now refuses a symlinked target and reports `skipped-symlink` instead of following it. Regression test: `test_symlinked_config_is_never_written_through`.

### F-06 — MCP server would scan a filesystem root

**Impact:** an agent launched at `C:\` or `/` would make the server walk the whole filesystem — a self-inflicted denial of service on the user's machine, and a scan of files far outside any project.

**Fix:** `workspace_path()` now refuses a filesystem root and any path that is not an existing directory. The MCP tools still cannot accept a path argument, so a client cannot ask for a different root. Tests: `tests/test_mcp_workspace.py`.

## Accepted risks

### A-01 — The local browser UI has no authentication

DefenTail binds `127.0.0.1` only, validates the `Host` header against the exact loopback origin and port (DNS-rebinding defence), rejects a foreign `Origin` on POST, and requires a per-process CSRF token. All four checks were probed live and return 403 when violated. There is still no user authentication: **any local process or user on the machine can read reports and trigger a scan while the UI runs.** Accepted for a single-user local tool; the UI is started explicitly and stops with Ctrl+C.

### A-02 — Scanner binaries and `PATH` are trusted

DefenTail pins the executable `shutil.which()` resolves, but if an attacker can place a malicious `trivy`/`semgrep` earlier on `PATH`, that binary runs with the user's privileges. This is inherent to orchestrating external tools and is documented in `SECURITY.md`. DefenTail never runs scanned project code and never passes a user-supplied executable path.

### Known noise, not a vulnerability

Scanning DefenTail itself flags six HIGH findings: `requests.get(..., verify=False)` and a `-----BEGIN PRIVATE KEY-----` marker inside test fixtures. Both are deliberate test strings that never reach a real request or key. The built-in rules have no suppression mechanism yet, which is why the self-scan stays red — an honest red, not a hidden one.

## Residual limitations

- Evidence is protected by a SHA-256 digest, **not** a signature. It detects casual edits only.
- The basic profile is a small pattern set. Quick and Full depend on separately installed third-party scanners whose own coverage, licenses and network behaviour vary.
- No independent audit, no signed Windows/macOS installer, no fuzzing of the parsers, and no live matrix of agent clients.

## Reproducing this audit

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m defentail doctor
PYTHONPATH=src python -m defentail scan --path . --profile full --json
PYTHONPATH=src python -m defentail ui --path . --port 8791 --no-browser
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: evil.example:8791" http://127.0.0.1:8791/
```
