# Security Policy

Laravel LeakProof helps identify certain sensitive fields in serialized JSON API responses. It is a defensive test aid, **not** a complete data-loss prevention or authorization system.

## Supported versions

| Version | Security fixes |
| --- | --- |
| Latest 1.x release | Supported |
| Older 1.x patch releases | Upgrade to the latest |
| Pre-1.0 versions | Unsupported |

## Reporting a vulnerability

Please avoid filing public issues with working exploits, production response payloads, personal information, private keys, or live tokens.

If **Private vulnerability reporting** is enabled on this repository, use GitHub's **Security → Report a vulnerability** feature to contact the maintainer privately. If it is not enabled, request a private reporting channel from the repository owner without disclosing the vulnerability details in public.

Include the affected version, minimal reproduction with *synthetic* data, expected vs. actual behavior, and the potential impact. Do not run scans against systems you do not own or have permission to assess.

For assumptions, limits, and known blind spots, see [Security design](docs/SECURITY.md).

## Responsible usage

Run the package in tests or on explicitly configured routes. The optional middleware is off by default. Secret-value detection is intentionally conservative and may miss unrecognized credential formats or personal information.
