# Security design

LeakProof detects accidental JSON serialization leaks. It does not replace authorization tests, secure API Resources, encryption, or static analysis.

Invalid input and traversal budget exhaustion never count as a clean inspection. Middleware is opt-in and off by default. Findings contain sanitized paths and rule names, not response values.

Non-identifier, credential-shaped, and very long JSON keys are redacted in diagnostic paths. Simple identifiers may still be user-controlled; avoid dynamically named sensitive fields.

Credential value detection targets only selected high-confidence formats. Unknown or encoded secret formats, data embedded in text, and authorization issues can remain undetected.

Avoid broad allowlist exceptions. Use staging to validate blocking mode before enabling it in production.

Report vulnerabilities privately using GitHub Security Advisories. Never include real credentials in issues.
