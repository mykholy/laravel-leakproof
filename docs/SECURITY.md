# Security design

LeakProof detects accidental JSON serialization leaks. It does not replace authorization tests, secure API Resources, encryption, or static analysis.

Invalid input and traversal budget exhaustion never count as a clean inspection. Middleware is opt-in and off by default. Findings contain sanitized paths and rule names, not response values.

Only an intentionally small allowlist of structural and sensitive field names is displayed in diagnostic paths. Other object keys, including short identifier-shaped keys, are redacted. Names on the display allowlist can still be user-controlled, so do not treat diagnostic paths as suitable for unrestricted public logging.

Credential value detection targets only selected high-confidence formats. Unknown or encoded secret formats, data embedded in text, and authorization issues can remain undetected.

Avoid broad allowlist exceptions. Use staging to validate blocking mode before enabling it in production.

Report vulnerabilities privately using GitHub Security Advisories. Never include real credentials in issues.
