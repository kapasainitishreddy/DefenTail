# Open-source and data licensing notes

DefenTail is MIT-licensed original orchestration and original educational content.

No scanner executable is bundled in the source ZIP or Python wheel. Third-party binaries are installed independently by users.

Current external adapters: Semgrep Community Edition engine (LGPL-2.1, with obligations), Betterleaks (MIT), OSV-Scanner (Apache-2.0), Trivy (Apache-2.0). Optional MCP Python SDK is MIT. Official CISA KEV data is CC0-1.0.

**Important split:** Semgrep's community/registry *rules* are available under a separate restricted license and must not be embedded in or redistributed as part of DefenTail. The supplied `rules.yml` is original and MIT-licensed. Do not copy registry patterns verbatim into that file.

The public GitHub repository alone does not grant sublicensing rights. Before bundling any dependencies, fonts, models, rules, incident corpora, screenshots or network feeds into a commercial application, inspect each exact version's LICENSE, NOTICE, model restrictions, dataset license, patent terms and trademark rules.

Services can have terms and quotas separate from the project's source-code license. Example: Snyk Agent Scan source is Apache-2.0, but its hosted analysis API requires a token and prohibits unauthorized large-scale reuse. That makes it **unsuitable as a default service dependency for this commercial product**.

External incident advisories are linked and summarized in original language rather than copied in full. Policies are linked to their owners' sites. Brand name **DefenTail** has only had a preliminary internet search; trademark clearance remains necessary.
