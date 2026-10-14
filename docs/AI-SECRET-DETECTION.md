# AI API Key and Secret Detection

LeakProof detects **selected credential formats in JSON string values**, plus **sensitive JSON field names** even when the value format is unknown. Rules are conservative, offline, and never submit or validate a key against a provider. A match indicates *potential exposure*, not proof that a token is valid.

## Value-based rules

| Provider / category | Rule ID | Recognition |
| --- | --- | --- |
| OpenAI project | `ai.openai_project_key` | `sk-proj-` prefix |
| OpenAI service account | `ai.openai_service_key` | `sk-svcacct-` prefix |
| OpenAI admin | `ai.openai_admin_key` | `sk-admin-` prefix |
| Anthropic | `ai.anthropic_key` | `sk-ant-` prefix |
| Google AI Studio / Gemini (also other Google APIs) | `ai.google_api_key` | `AIza` and expected length |
| Hugging Face | `ai.huggingface_token` | `hf_` prefix |
| Groq | `ai.groq_key` | `gsk_` prefix |
| Replicate | `ai.replicate_token` | `r8_` prefix |
| Pinecone | `ai.pinecone_key` | `pcsk_` prefix |
| Perplexity | `ai.perplexity_key` | `pplx-` prefix |
| OpenAI legacy, DeepSeek, Mistral or other compatible keys | `ai.generic_sk_key` | Long generic `sk-` prefix; **not provider-attributed** |
| GitHub | `secret.github_token`, `secret.github_fine_grained_token` | `ghp_` family and `github_pat_` |
| Stripe | `secret.stripe_live_key` | Live secret or restricted prefixes |
| Slack | `secret.slack_token` | `xoxb-` family |
| Private keys | `secret.private_key_material` | RSA, EC, DSA, OpenSSH, PKCS#8, PGP headers |

Regexes deliberately require minimum lengths and boundaries; truncated keys, some rotated token formats, and new provider schemes will **not** always match. Recognition patterns are heuristics, not official validity guarantees.

## Field-name detection (important for provider formats without distinctive prefixes)

Response fields like `cohereApiKey`, `mistral_api_key`, `azureOpenaiApiKey`, `together_api_key`, `openrouterApiKey`, `bedrockSecretAccessKey`, `gemini_api_key`, `anthropicApiKey`, and `llmApiKey` are flagged by the configurable **sensitive_keys** list even when the token's format is unknown.

Field-name scanning applies to keys anywhere in the JSON tree. Use narrow, reviewed exceptions for intentionally returned login tokens. Do not add permissive wildcards globally.

## Customizing built-in rule selection

Publish config with:

```bash
php artisan vendor:publish --tag=leakproof-config
```

Then edit `config/leakproof.php`:

```php
// null = all built-in patterns, [] = no value patterns.
'value_rules' => [
    'ai.openai_project_key',
    'ai.anthropic_key',
    'ai.google_api_key',
    'ai.huggingface_token',
],
```

The `scan_secret_values` switch disables *value* pattern matching globally, but sensitive key-name detection remains active. Unknown rule IDs raise an exception, rather than silently disabling detection.

You can extend `sensitive_keys` for your own naming conventions, but custom arbitrary regular expressions are intentionally not accepted in config: untrusted regexes can introduce ReDoS or slow down every request.

## Example: API response leak

```php
use Mykholy\LeakProof\Testing\Concerns\AssertsNoSensitiveData;

final class ChatApiTest extends TestCase
{
    use AssertsNoSensitiveData;

    public function test_chat_response_contains_no_provider_credentials(): void
    {
        $response = $this->getJson('/api/chat/123');
        $response->assertOk();
        $this->assertNoSensitiveData($response);
    }
}
```

`data.provider.openaiApiKey` is caught by **field name**; a credential in `data.message` matching a supported prefix is caught by **value**.

LeakProof **does not automatically classify all personal information**, discover every provider's tokens, check whether credentials are valid, or audit authorization. Keep Laravel policies, response resources, and `$hidden` protections.

## Performance and security

- Value patterns use fixed, reviewed regexes with prefix prefilters.
- JSON inspection is bounded by depth, node count, findings, and input byte limits.
- Only synthetic data is used in the [benchmark](../tools/benchmark.php).
- `Report` objects intentionally exclude credential values.
- Do not store actual leaked tokens in logs or issue reports.
- Middleware remains opt-in and **off** by default.

Tokens and prefix formats change. Please report missing formats with **synthetic test vectors**, never live credentials.
