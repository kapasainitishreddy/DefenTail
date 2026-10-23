# Syrava DefenTail

**A friendly, local-first guardian for AI-generated apps.**

> Learn from real breaches. Spot preventable mistakes while coding. Explain risks to anyone. Keep a dated trail of what was tested and what still needs human review.

**Status: 0.2.0 experimental working starter, NOT an audited security product or a certified compliance service.**

DefenTail is an original MIT-licensed Python orchestrator and teaching interface. It does **not bundle third-party binaries, Semgrep community rules, proprietary AI models, account credentials or copyrighted incident articles**. Optional tools must be separately installed in accordance with their own licenses and notices.

## Fastest way to try it (Windows)

1. Extract this ZIP.
2. Install Python 3.10 or newer from https://www.python.org/downloads/ (if needed).
3. Double-click `START_HERE_WINDOWS.bat`.
4. A private local browser opens. Paste your app's folder and select **Basic**.
5. Read the explanations. Basic checks work without API keys, signups or installed scanners.

The batch file uses the Python packaging tools on your own machine. Inspect it before running it if you prefer. **Nothing needs to be submitted to Syrava.**

### Terminal commands (Windows, Mac, Linux)

From the extracted project folder:

```bash
python -m pip install --user --no-deps .
python -m defentail ui
```

With the CLI installed:

```bash
defentail doctor
defentail scan --path ./my-app --profile basic
defentail watch --path ./my-app
defentail lessons
defentail policies --platform android
defentail policies --platform ios
defentail intel-status
```

Run the dependency, secret, and configuration scanners **after independently installing the actual open-source tools**:

```bash
defentail scan --path ./my-app --profile quick --output before.json
defentail scan --path ./my-app --profile full --output after.json
defentail compare before.json after.json
```

Note: the scan command exits `2` when requested scanner coverage is missing, a scanner fails, or a critical/high/untriaged vulnerability is reported. It exits `0` only when its **selected checks** complete with no configured blockers. That does **not** mean the app is secure. The basic profile performs narrowly scoped heuristic checks; even a basic PASS is not a security pass.

## What works today

| Area | v0.2 implementation | Limits |
| --- | --- | --- |
| Noncoder-friendly UI | Local-only browser with "Check my app" and short explanations | No native desktop installer, no drag-and-drop yet |
| While editing | `watch` notices code/lockfile changes and repeats basic scans | Polling only; no native IDE inline diagnostics yet |
| Simple built-in checks | Searches source patterns, exact npm lockfile versions tied to 2025 advisories, and flags npm install-script review | Not a replacement for comprehensive SAST, SCA, DAST, app tests |
| Advanced scanner orchestration | CLI adapters for Semgrep CE, Betterleaks, OSV-Scanner v2; Trivy added for Full | Optional binaries are NOT included; integrations were unit-tested with mock outputs, not live scanner installations |
| Agent use | Optional MCP server with authorized workspace root, bundled example agent instruction and configuration | Requires `mcp` SDK and local MCP client setup; live end-to-end MCP client not verified |
| Attack memory | Sourced, versioned lessons: Next.js auth bypass, React RSC RCE, npm Shai-Hulud compromise | Three initial lessons, not all security incidents |
| Threat feed | Explicit CISA Known Exploited Vulnerabilities downloader and local cache | The feed identifies known-exploited CVEs; it is not automatically transformed into new scanning rules |
| Compliance | Dated Apple, Google Play and OWASP checklists with official links; opt-in content-change notifications | Manual evidence review required. Not certification, legal advice or store approval guarantee |
| Proof | JSON evidence digest; reports omit raw secret matches; before/after diff; missing scans block gates | Digest detects casual tampering only, NOT a digital signature; removal from a scan isn't proof the issue is fixed |

## How the levels work

- **Basic:** Runs our small built-in checks. Entirely local and offline. Starts immediately.
- **Developer / Quick:** Basic + Semgrep CE using only our own MIT-authored rules + Betterleaks + OSV-Scanner v2. The named executables need to be on `PATH`.
- **Full:** Quick + Trivy filesystem scanning for vulnerabilities, secrets and misconfigurations. May download public vulnerability/check databases. Only scan projects you own or are authorized to inspect.

**Network privacy:** DefenTail's own basic scanner never uploads source code. External tools are independent processes. OSV may contact a dependency advisory service, Trivy may download databases, and some scanners have optional network and telemetry settings. Review their privacy and configuration documentation for offline needs; do not assume selecting Quick or Full is air-gapped. The CISA feed updater and policy watcher are explicitly opt-in network commands.

**Conservative gates:** Missing, timed-out, or invalid scanner outputs are treated as **unverified**, never automatically passed. Findings lacking a severity need triage. A serious vulnerability blocks the configured gate.

## Real incidents become safe lessons, not untrusted commands

The incident library initially includes:

1. **CVE-2025-29927**: Next.js middleware authorization bypass. Every protected server operation needs authorization checks, not only middleware.
2. **CVE-2025-55182**: React Server Components remote code execution. Check actual installed versions and test upgraded framework code.
3. **2025 Shai-Hulud npm supply chain**: Review dependencies, lifecycle scripts, tokens and permissions in build environments.

Run `defentail lessons` to see links and human-readable explanations. Run `defentail update-intel` to fetch **CISA's official KEV catalog**, published under CC0, into your machine's cache (not into a proprietary cloud). We validate the expected schema and preserve the last good snapshot when a download fails.

**Future ingestion safety rule:** incident feeds are data, **never executable instructions**. New rules require primary-source references, human review, controlled fixtures, false-positive testing, version constraints and a signed release pipeline before distribution. Current starter ships only hand-curated incidents.

## Compliance is evidence, not a green checkmark

The included checklist references official source pages for Apple App Store Review Guidelines 5.1.1, Google Play User Data / account deletion and OWASP Top 10 (2025) examples. Each item shows what evidence humans should inspect and is marked *not automatically verifiable*. The `check-policies` command compares official page text to its previous snapshot and flags **possible changes**. It does not infer which policy text changed, nor silently rewrite compliance logic. Website structure, regional terms and deadlines may change independently.

Future modules can add explicit evidence schemas for Apple Privacy Nutrition Labels, Google Play Data safety and SDK disclosures, COPPA, GDPR, OWASP MASVS/ASVS, SOC 2, PCI DSS and other requirements **only when applicable to the app**, with version, jurisdiction, source and evidence mapping. No claim of blanket compliance should ever be made.

## Optional MCP setup for coding agents

Install the SDK separately:

```bash
python -m pip install "mcp>=1.0,<3"
```

Point an MCP-capable local coding agent at `python -m defentail.mcp_server` with the `DEFENTAIL_WORKSPACE` environment variable set to an authorized local directory. See `integrations/mcp-config.example.json`. The MCP interface reads one fixed workspace and intentionally has **no auto-fix, system shell execution, arbitrary file modification or user-supplied scan paths**. Each client manages installation and permissions differently, so this JSON is an example, not a one-click integration promise.

For a plain coding agent without MCP, paste `integrations/AGENTS.md` instructions into your app project and run the CLI separately.

## Commercial-use licensing policy

DefenTail's original orchestration, demo UI, rules and authored checklist structure are **MIT**. Optional software is not embedded in this ZIP; each tool must be assessed again at the exact version distributed. This table is a starting point for legal and engineering review, not a legal opinion.

| Optional tool | Repository | License | Integrated now? | Commercial distribution precautions |
| --- | --- | --- | --- | --- |
| Semgrep Community Edition **engine** | https://github.com/semgrep/semgrep | LGPL-2.1 | CLI adapter | Keep as separate tool; satisfy LGPL terms and provide notices if redistributing. **DO NOT copy Semgrep's registry/community rules**. Those rules have separate, non-redistributable use restrictions. Only our own MIT rules ship. |
| Betterleaks | https://github.com/betterleaks/betterleaks | MIT | CLI adapter | Retain required license/copyright notices when bundled later. |
| OSV-Scanner | https://github.com/google/osv-scanner | Apache-2.0 | CLI adapter | Retain license/NOTICE obligations and verify external OSV service terms. |
| Trivy | https://github.com/aquasecurity/trivy | Apache-2.0 | CLI adapter | Retain license/NOTICE obligations and account for vulnerability database/feed terms. |
| OWASP ZAP | https://github.com/zaproxy/zaproxy | Apache-2.0 | **Planned, not integrated** | Only test authorized applications. Do not scan public endpoints without consent. |
| CISA KEV data | https://github.com/cisagov/kev-data | CC0-1.0 | Feed download | Data reusable; third-party links can have different licenses; no CISA/DHS endorsement or logos. |
| Official MCP Python SDK | https://github.com/modelcontextprotocol/python-sdk | MIT | Optional integration | SDK must be installed separately; attribution required if distributed. |

**Explicitly excluded from commercial core:** Proprietary Aikido / CodeRabbit cloud services; Semgrep registry rules; Snyk Agent Scan API-backed analysis without an appropriate commercial authorization; copied screenshots, paid training content, leaked code samples or copyrighted news text. A project's repository being public is **not** sufficient evidence of a right to sell or redistribute it.

## Roadmap: what would make this genuinely unique

The value proposition is not "all scanners in one dashboard". The differentiated workflow should be **Incident → Safe Guardrail → Contextual Detection → Plain-English Guidance → Verified Regression → Release Evidence**. The shipped v0.2 product is only the foundation.

- **V1 Incident-to-Guardrail:** authenticated, reviewed incident feed; vulnerable-version checks; MIT-authored tests; sandboxed reproducibility proofs; signed rulepacks; transparency around unknown cases.
- **V1.1 Accurate multi-scanner correlations:** normalize to CWE / OSV / CVE; stable fingerprints across moves; reduce duplicates; coverage-by-language; prioritize reachable auth and data-exposure flaws.
- **V1.2 Truly easy installation:** signed Windows installer, macOS package, VS Code / Cursor / Antigravity extensions, Codex / Claude Code hooks, fully offline mode with separately cached databases.
- **V1.3 Safe remediation:** suggest a tiny patch; review changes; run an authorized targeted regression; compare before/after; never bypass tests or weaken auth to silence scanners.
- **V1.4 Verified policy evidence:** store metadata checks, tested account deletion, privacy/SDK evidence, human approval trails, app-scoped regulatory applicability.
- **V2 Security coaching:** kid-friendly stories, accessible vocabulary, multi-language learning, question-and-answer mentor, no fake "100% secure" badges.

## Validate the starter

```bash
python -m unittest discover -s tests -v
python -m defentail doctor
python -m defentail lessons
python -m defentail policies --platform android
```

For developers running directly from the unpacked tree without installing:

```bash
# macOS/Linux
PYTHONPATH=src python -m defentail doctor
# Windows PowerShell
$env:PYTHONPATH = "src"; python -m defentail doctor
```

## Security boundaries and honesty

- Scan only projects you own or are permitted to audit.
- DefenTail itself doesn't execute scanned project scripts, invoke untrusted MCP servers, install packages, rotate tokens, or automatically deploy fixes.
- Local malicious scanners can still execute arbitrary code; install only authentic binaries from verified publishers.
- No scanner, static analysis, AI system, or checklist can guarantee that software cannot be hacked or modified.
- This initial version has **mocked scanner adapter tests and built-in end-to-end tests**, not production penetration testing, verified Microsoft code signing, real cloud workflows, complete mobile app review, or live third-party scanner binary tests.

Copyright 2026 Syrava. MIT License. Working product name **DefenTail** is provisional until trademark clearance.
