# Changelog

All notable user-facing changes are recorded here. Releases are listed newest first.

## Unreleased

- Extend the PHP/Laravel CI matrix to test PHP 8.5 with Laravel 12 and 13.
- Update GitHub Actions checkout from v4 to v7 after the compatibility test matrix passed.
- Correct the chronological release notes and remove an invalid Dependabot label configuration.

## 1.1.0 - 2026-10-14

- Detect selected OpenAI, Anthropic, Gemini/Google, Hugging Face, Groq, Replicate, Pinecone, Perplexity, OpenRouter, NVIDIA NGC and Tavily API key formats within JSON strings.
- Identify provider-specific AI credential field names for services without reliable key prefixes.
- Add selectable built-in value rules, regression tests, a synthetic inspection benchmark, and a consumer Laravel installation smoke test.
- Configure Dependabot for Composer and GitHub Actions updates.

## 1.0.2 - 2026-10-14

- Add lightweight, descriptive README hero banner and discoverability badges.
- Improve README quick start, navigation, detection examples and package keywords.
- Exclude marketing artwork from Composer distribution archives.

## 1.0.1 - 2026-10-14

- Security: redact arbitrary identifier-shaped JSON object keys from finding paths to avoid accidental personal-data disclosure.
- Add regression tests for alphanumeric identifiers and unknown object keys.
- Clarify Packagist installation and staging middleware deployment guidance.

## 1.0.0 - 2026-10-14

- Introduce sensitive JSON field and high-confidence credential pattern inspection.
- Add nested sanitized paths, scoped allowlist rules and bounded traversal.
- Add Laravel feature-test assertions, a local fixture scanner and opt-in HTTP middleware.
- Establish GitHub Actions compatibility checks for PHP and supported Laravel versions.

Releases are published only after their CI requirements succeed. Git tags remain immutable.
