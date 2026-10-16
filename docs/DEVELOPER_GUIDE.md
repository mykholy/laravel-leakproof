# LeakProof: developer field guide

Use LeakProof as a **regression tripwire on actual JSON responses**. It reports selected risky keys and recognizable credential formats without echoing the credential. It does not prove the endpoint is authorized or replace a security review.

## First 15 minutes

1. Install in an application using `composer require --dev mykholy/laravel-leakproof:^1.1`.
2. Pick a real endpoint whose JSON structure is important (profile, billing, integration settings).
3. Add a feature test that asserts the response succeeds **and** contains no flagged fields.
4. Deliberately add a **synthetic** forbidden key in a disposable test fixture; prove the test fails, then remove it.
5. Put the feature test into CI.

```php
use Mykholy\LeakProof\Testing\Concerns\AssertsNoSensitiveData;

final class ProfileResponseTest extends TestCase
{
    use AssertsNoSensitiveData;

    public function test_user_profile_does_not_expose_sensitive_fields(): void
    {
        $response = $this->actingAs($this->userFixture())->getJson('/api/me');
        $response->assertOk();

        $this->assertNoSensitiveData($response);
    }
}
```

`userFixture()` is an illustration; use your application's existing factory/helper. The test should run against disposable data and may need role/tenant fixtures.

## Common choices

| Question | Recommended approach |
| --- | --- |
| Does serialization expose `password` or `api_key`? | Assert against the actual Laravel `TestResponse` |
| Is the response fixture itself safe? | `php artisan leakproof:scan tests/Fixtures/response.json` |
| Is an access token intentional on login? | Add an **exact** allow path for only that named endpoint |
| Are there AI model-provider secrets? | Use the [AI detection guide](AI-SECRET-DETECTION.md); rules are high confidence, not complete |
| Should the package automatically block users? | No: middleware is optional; verify it in staging before enabling anything outside tests |

A real `password`, API token or customer record must never be committed merely to demonstrate the scanner.

## Review checklist

- Explicitly scope allow paths; avoid blanket exclusions.
- Document why a legitimate `access_token` appears on a particular response.
- Treat traversal overflow/incomplete scanning as a failure, not a pass.
- Pair LeakProof with authentication/authorization tests; a response can be perfectly free of secrets and still reveal the wrong customer's data.
- Confirm the test DB, network services and queue backends are disposable.
- In CI, treat a finding as a contract regression and inspect **sanitized paths**, never raw payloads.

Start with [README](../README.md), [AI-secret coverage](AI-SECRET-DETECTION.md), and [security boundaries](SECURITY.md). Report vulnerabilities privately through [SECURITY.md](../SECURITY.md).
