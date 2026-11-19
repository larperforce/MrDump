# MrDump 0.4.0 — Security notes

- Target files are read as data; MrDump never executes them and static analysis does not modify them.
- Files up to 128 MiB are read in full. Larger files are sampled at the start and end; the SHA-256 is streamed across the complete file.
- PE parsing requires a valid PE signature and the optional `pefile` dependency. PE structural parsing is skipped in sampled mode.
- ZIP entries are inspected from central-directory metadata. Archive members are never extracted or executed.
- Malware checks are static heuristics, not a definitive verdict or automatic remediation.
- ClamAV is an optional external local scanner. Its availability and detection results depend on installation and current signatures.
- VirusTotal lookup sends the SHA-256 identifier only, not the file itself. Online providers have their own terms, quotas, and retention policies.
- Network scans are TCP connect checks limited to private, loopback, and link-local IPv4 addresses. No exploit, credentials, or brute force is attempted.
- Text report export refuses to overwrite the inspected target and refuses to overwrite any existing file.
- MrDump is not a replacement for a maintained antivirus/EDR, full vulnerability scanner, or incident-response process.
