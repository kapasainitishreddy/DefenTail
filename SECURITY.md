# Security model (experimental)

DefenTail is a *local* scanner coordinator. The trust boundary is the supplied project folder, the local Python interpreter, separately installed scanner executables, the local CISA feed, and the browser interface. It does not require account creation.

## Safe behavior we aim to enforce

- All external commands use `shell=False` with fixed executable names and fixed arguments.
- The built-in scanner reads source text, lockfiles and manifests without executing their contents.
- The optional MCP server is restricted to a single `DEFENTAIL_WORKSPACE` root. It does not expose shell access or arbitrary filesystem traversal tools.
- The local browser binds to 127.0.0.1, validates the Host and Origin where available, uses a CSRF token for POST, escapes all HTML, and does not serve project files.
- Reports omit raw secret match strings and contain a SHA256 integrity digest, **not a cryptographic attestation signature**.
- An unavailable scanner, unexpected output, or timed-out check must fail the selected security gate closed.
- Remote incident feeds are treated only as untrusted data, not as shell instructions or code.

## Threats and remaining gaps

- A malicious scanner installed earlier on PATH is executable and may read source. Verify publishers and binary signatures independently. We have no sandbox yet.
- File-path races, symlink changes, extensive monorepos, unusual lockfile formats and archive bombs can affect completeness. The built-in scanner has size and symlink limits; external scanners have their own limits.
- Source reads can still disclose sensitive paths and vulnerability metadata in reports. Store reports securely.
- Some third-party scanners use network feeds; this build is not air-gapped outside the Basic profile.
- Authentication, payment logic and cross-account authorization require runtime tests and human review.
- A successful scan says only that selected checks completed; it does not prove protection from attacks or meet regulatory compliance.

To report a vulnerability in a future public repository, use a private security advisory rather than posting exploit details publicly.
