# Syrava DefenTail product strategy

## Positioning

**Learning security, at the moment of building.**

Audience: citizen developers, students, nontechnical founders, AI coding agents, indie developers and small businesses shipping web/mobile apps.

## The five differentiated reasons to buy

1. **Incident-to-Guardrail:** When a major incident is verified, the maintainer writes a scoped check and a regression fixture that independently verifies prevention, with a traceable source and last review date.
2. **Understandable risk:** "A private door depends on a hallway guard" rather than "CWE-862 authorization bypass" alone, plus what action to take and what test demonstrates the fix.
3. **Evidence not buzzwords:** Disclose which scanners ran, what was skipped, test status, detected app surfaces and the confidence of every finding.
4. **Store-readiness and code security together:** Highlight possible Google Play / Apple App Store policy problems and show evidence requirements, without misrepresenting approvals or certifications.
5. **No lock-in, easy integration:** Free MIT core with separate commercially permissible local scanner CLIs, MCP endpoint and optional IDE workflows. Paid potential: managed policy intelligence, team attestations, shared evidence rooms, support and collaboration, but never lock core security checks behind a misleading "secure" badge.

## Beginner design example

Title: **Someone might open another person's account.**

What happened: **The app only checked access at the front entrance. Another path could skip that check.**

What to do: **Make every private server request verify the signed-in user is allowed to see this exact record.**

How we know: **A cross-user test tried accessing someone else's record and received an expected "not allowed" response, after the patch.**

Status: **Not tested** / **Check found a problem** / **Fix suggested** / **Test passed for this case**. Never **Hacker-proof**.

## Product milestones

- v0.2: Local prototype with basic checks, incident memory, dated policy review, optional scanner adapters, local UI, mock tests and experimental MCP server.
- v0.3: Verify the CLI with real scanner binaries on Windows/macOS/Linux, use a sanitized baseline test corpus, document false-positive rates, sign releases.
- v0.4: Rule authoring library: 20 trusted attack patterns and >100 safe regression fixtures, peer review and versioning.
- v0.5: One-click installers, live IDE diagnostics, authenticated source updates, offline advisory cache.
- v0.6: Secure remediation sandbox, differential tests, permission-aware CI and release evidence.
- v1.0: External pentest of orchestrator, customer pilot, published coverage accuracy, legal review, license BOM and storefront requirements.

## Non-negotiables

- No unauthorized offensive testing, stealth scanning, or exploit execution against public services.
- No deceptive "automatically compliant", "unhackable", "100% security" claims.
- No user code sent to our server by default; network actions explicit and disclosed.
- Never incorporate restricted Semgrep rulepacks or depend on noncommercial APIs in the sellable core.
- No autonomous changes to source files or risky dependency upgrades without approval and regression testing.
