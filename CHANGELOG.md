# Changelog

## 1.0.1 - 2026-10-14

- Security: redact arbitrary identifier-shaped JSON object keys from finding paths to avoid accidental personal-data disclosure.
- Add regression tests for alphanumeric identifiers and unknown object keys.
- Clarify Packagist installation and staging middleware deployment guidance.

## Unreleased

- Detect selected OpenAI, Anthropic, Gemini/Google, Hugging Face, Groq, Replicate, Pinecone and Perplexity API key formats within JSON strings.
- Identify provider-specific AI credential field names for services without reliable key prefixes.
- Add selectable built-in value rules, regression tests, a synthetic inspection benchmark, and a consumer Laravel installation smoke test.
- Configure Dependabot for Composer and GitHub Actions updates.



## 1.0.2 - 2026-10-14

- Add lightweight, descriptive README hero banner and discoverability badges.
- Improve README quick start, navigation, detection examples and package keywords.
- Exclude marketing artwork from Composer distribution archives.


- Sensitive JSON field and high-confidence credential pattern inspection.
- Nested sanitized paths, scoped allowlist rules, bounded traversal.
- Laravel feature-test assertions, local fixture scanner, opt-in HTTP middleware.
- GitHub Actions compatibility matrix for PHP and Laravel.

Stable tags require passing CI.
