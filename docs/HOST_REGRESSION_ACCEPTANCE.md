# Host regression and security acceptance

This checklist supplements the package's existing tests and does not assert that any external host has passed acceptance.

## Sensitive JSON regression acceptance

Exercise nested JSON API Resources, arrays, field-name detections and synthetic provider-shaped tokens. Verify the scanner reports JSON paths/rule identifiers without credential values. Test benign strings to monitor false positives, and ensure the optional middleware is not accidentally enabled on production traffic.

## Verification record

Record the exact package tag and source SHA, PHP and Laravel versions, database driver/version, test command, sanitized pass/fail output, and relevant host commit. Do not publish secrets or real customer data.

## Laravel framework security baseline (October 2026)

For any host using Laravel's built-in token-based API guard, review [GHSA-f9x3-7vq9-cph6](https://github.com/laravel/framework/security/advisories/GHSA-f9x3-7vq9-cph6). The advisory identifies patched framework versions **12.68.0+** and **13.29.0+**. Check the host's resolved Composer lockfile and guard configuration; this is not evidence that this package itself contains the vulnerability.

## Completion policy

- Add executable regression tests and link passing CI evidence before claiming code remediation.
- Distinguish package-level behavior from host-owned authentication, authorization, external provider and deployment responsibilities.
- Do not claim independent security approval or production readiness without independently supplied evidence.
