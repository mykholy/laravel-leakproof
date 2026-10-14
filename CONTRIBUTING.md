# Contributing

Open an issue describing a reproducible use case. Submit focused changes with tests that protect against false positives and false negatives.

Run `composer test`, `composer analyse`, `composer format-check`, and `composer smoke`.

Use Testbench tests for Laravel integration. Never place real tokens, response bodies, or personal data in fixtures or diagnostics.

Security changes must fail safely instead of silently treating incomplete inspection as success.
