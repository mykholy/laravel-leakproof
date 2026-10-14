# Changelog

## 1.0.1 - 2026-10-14

- Security: redact arbitrary identifier-shaped JSON object keys from finding paths to avoid accidental personal-data disclosure.
- Add regression tests for alphanumeric identifiers and unknown object keys.
- Clarify Packagist installation and staging middleware deployment guidance.

## Unreleased

- Sensitive JSON field and high-confidence credential pattern inspection.
- Nested sanitized paths, scoped allowlist rules, bounded traversal.
- Laravel feature-test assertions, local fixture scanner, opt-in HTTP middleware.
- GitHub Actions compatibility matrix for PHP and Laravel.

Stable tags require passing CI.
