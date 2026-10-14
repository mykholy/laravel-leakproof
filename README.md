# Laravel LeakProof

[![CI](https://github.com/mykholy/laravel-leakproof/actions/workflows/tests.yml/badge.svg)](https://github.com/mykholy/laravel-leakproof/actions/workflows/tests.yml)

**Detect sensitive fields in the JSON your Laravel API actually returns.**

A feature test can pass while the response unexpectedly includes a password hash, an access token, or a private credential. LeakProof analyzes serialized JSON and reports the path and matching rule **without printing the secret value**.

It is deliberately focused on accidental serialization leaks. It is not an authorization system, a static code scanner, or a substitute for Laravel API Resources and model `$hidden`.

## Requirements

PHP 8.2+, Laravel 12 / 13. Laravel 13 itself requires PHP 8.3+.

## Install

Once indexed by Packagist:

```bash
composer require --dev mykholy/laravel-leakproof
php artisan vendor:publish --tag=leakproof-config
```

No migrations, tables, scheduled jobs, or external services are required. Auto-discovery registers the provider.

## Feature tests

```php
use Mykholy\LeakProof\Testing\Concerns\AssertsNoSensitiveData;

class UserApiTest extends TestCase
{
    use AssertsNoSensitiveData;

    public function test_profile_does_not_leak_secrets(): void
    {
        $response = $this->getJson('/api/me');
        $response->assertOk();
        $this->assertNoSensitiveData($response);
    }
}
```

An accidental `password` response field generates a failure such as `$.data.user.password [field.sensitive_key]`. The field's **value is not included** in diagnostics.

### Narrow exceptions for intentional tokens

```php
$this->assertNoSensitiveData($response, ['data.access_token']);
$this->assertNoSensitiveData($response, ['data.sessions.*.access_token']);
```

The wildcard matches **one** segment. Paths are exact: an allow rule exempts only the selected subtree. Never use broad exceptions to silence security failures.

## Fixture scanning

```bash
php artisan leakproof:scan tests/Fixtures/user-response.json
php artisan leakproof:scan tests/Fixtures/login-response.json --allow=data.access_token
php artisan leakproof:scan tests/Fixtures/user-response.json --format=json
```

Exit codes: 0 clean; 1 finding or incomplete traversal; 2 invalid/unreadable input. The scanner reads local files only. JSON output contains sanitized paths and rules, never original values.

## Optional staging middleware

```php
Route::middleware('leakproof')->get('/profile', ProfileController::class)->name('profile');
```

The middleware is **off** unless explicitly attached **and** enabled:

- `LEAKPROOF_MODE=off` (default): no inspection.
- `LEAKPROOF_MODE=report`: record sanitized paths in application logs.
- `LEAKPROOF_MODE=block`: throw when a response leaks or cannot be fully inspected.

Do not use blocking mode in production without staging tests; legitimate token endpoints may otherwise return 500 errors.

For named routes, configure an exact exception in `config/leakproof.php`:

```php
'allowed_paths' => ['login' => ['data.access_token']],
```

Only JSON responses are inspected. Streams, HTML, and downloads are skipped.

## Programmatic API

```php
use Mykholy\LeakProof\LeakProof;

$report = app(LeakProof::class)->inspect(['user' => ['passwordHash' => 'sensitive']]);

if (! $report->passed()) {
    logger()->warning($report->summary());
}
```

## Safety limits

- Bounded traversal: default max depth 32, 50,000 nodes, and 100 findings.
- JSON input limit: default 2 MiB.
- Exceeding limits makes an inspection **inconclusive**, not successful.
- Non-identifier, very long, or credential-like object keys are redacted from diagnostic paths.
- High-confidence value patterns include private-key headers and selected live credential prefixes.
- This does **not** prove an API is private. Unknown secret formats, encoded values, and authorization mistakes may be missed.

See [Security considerations](docs/SECURITY.md).

## Development

```bash
composer install
composer test
composer analyse
composer format-check
composer smoke
```

CI checks supported PHP/Laravel combinations. See [Contributing](CONTRIBUTING.md).

## License

MIT. Copyright Ahmed Elkholy.
