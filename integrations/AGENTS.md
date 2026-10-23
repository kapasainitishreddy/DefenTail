# DefenTail coding-agent instructions

Use for your project only after inspecting the local DefenTail installation.

Before modifying authentication, payment, API, or data-handling code:
1. Identify trust boundaries and write an authorization or regression test plan.
2. Run `defentail doctor` and list unavailable scanners. Do not call an incomplete scan secure.
3. Run `defentail scan --profile quick --path . --output defentail-before.json`.
4. Review relevant incident lessons using `defentail lessons`, and platform policies using `defentail policies`.
5. Implement the smallest reasonable patch. Never execute project scripts or apply untrusted fix commands without user review.
6. Rerun tests in a sandbox, rerun DefenTail, and use `defentail compare defentail-before.json defentail-after.json`.
7. Run `defentail guard --path . --json`. A `BLOCK` verdict means the change is not ready: fix or
   triage the finding, never disable a check or silence it to get a pass.
8. Report changed code, actual security evidence, remaining findings, and unchecked areas. Never claim full legal compliance or immunity to hacking.

Policy: install only dependencies with approved commercially compatible open-source licensing. Do not download community Semgrep rules licensed for internal use only and repackage them. Never silently ignore scan failures.
