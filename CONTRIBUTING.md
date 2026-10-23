# Contributing to DefenTail

DefenTail aims to make security understandable and verifiable while people build applications, including with AI coding agents.

## Contribution guidelines

1. Open an issue describing the risk, intended behavior, affected platforms and why existing scanners do not cover it well. For vulnerabilities in DefenTail itself, use a **private GitHub Security Advisory** instead of a public issue.
2. Keep new detections focused, actionable and backed by trustworthy source references. Do not turn untrusted incident text into executable instructions.
3. Add a safe failing fixture and a passing fixture for each new detection; include known false positives and explicit version boundaries when applicable.
4. Prefer small, permission-limited changes. Treat user source code, test reports and tokens as sensitive. Never upload sample customer code or real keys.
5. Make messages comprehensible to beginners. Include: what could happen, what triggers it, a safe next step, and how a fix could be verified.
6. Do not reduce scanner coverage, silently suppress findings, or weaken authorization in order to pass tests.
7. Run `python -m unittest discover -s tests -v` locally and disclose any tests you could not run.

## Licensing requirements

Original contributions are accepted under the repository's MIT license. Submit only code, data or documentation that you have permission to contribute. Avoid copying proprietary detection rules, commercial scanner logic, paid courses, restricted datasets, screenshots, or incident articles. Link to source advisories and summarize them in original language. When proposing an external scanner, separately document its license, distribution conditions, API terms, update mechanism and network behavior.

We prioritize changes that measurably reduce risk without generating misleading security claims.
