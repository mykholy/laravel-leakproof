<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Inspection;

use InvalidArgumentException;

/**
 * Recognizes high-confidence credential shapes within JSON string values.
 *
 * Rules never retain, return, hash, or log the matching credential. A prefix
 * match does not prove a key is live, and provider formats can change.
 */
final class ValueDetector
{
    /** @var array<string, string> */
    private const PRIVATE_KEY_HEADERS = [
        '-----BEGIN PRIVATE KEY-----' => 'secret.private_key_material',
        '-----BEGIN ENCRYPTED PRIVATE KEY-----' => 'secret.private_key_material',
        '-----BEGIN RSA PRIVATE KEY-----' => 'secret.private_key_material',
        '-----BEGIN EC PRIVATE KEY-----' => 'secret.private_key_material',
        '-----BEGIN DSA PRIVATE KEY-----' => 'secret.private_key_material',
        '-----BEGIN OPENSSH PRIVATE KEY-----' => 'secret.private_key_material',
        '-----BEGIN PGP PRIVATE KEY BLOCK-----' => 'secret.private_key_material',
    ];

    /**
     * Markers are cheap prefilters; regexes validate the token boundary and
     * minimum length. Rule ordering matters: provider-specific before generic.
     *
     * @var array<string, array{marker: string, regex: string}>
     */
    private const PATTERNS = [
        'ai.openai_project_key' => [
            'marker' => 'sk-proj-',
            'regex' => '~(?<![A-Za-z0-9_-])sk-proj-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])~',
        ],
        'ai.openai_service_key' => [
            'marker' => 'sk-svcacct-',
            'regex' => '~(?<![A-Za-z0-9_-])sk-svcacct-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])~',
        ],
        'ai.openai_admin_key' => [
            'marker' => 'sk-admin-',
            'regex' => '~(?<![A-Za-z0-9_-])sk-admin-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])~',
        ],
        'ai.anthropic_key' => [
            'marker' => 'sk-ant-',
            'regex' => '~(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])~',
        ],
        'ai.google_api_key' => [
            'marker' => 'AIza',
            'regex' => '~(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])~',
        ],
        'ai.huggingface_token' => [
            'marker' => 'hf_',
            'regex' => '~(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{30,}(?![A-Za-z0-9_])~',
        ],
        'ai.groq_key' => [
            'marker' => 'gsk_',
            'regex' => '~(?<![A-Za-z0-9_])gsk_[A-Za-z0-9]{32,}(?![A-Za-z0-9_])~',
        ],
        'ai.replicate_token' => [
            'marker' => 'r8_',
            'regex' => '~(?<![A-Za-z0-9_])r8_[A-Za-z0-9]{32,}(?![A-Za-z0-9_])~',
        ],
        'ai.pinecone_key' => [
            'marker' => 'pcsk_',
            'regex' => '~(?<![A-Za-z0-9_-])pcsk_[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])~',
        ],
        'ai.perplexity_key' => [
            'marker' => 'pplx-',
            'regex' => '~(?<![A-Za-z0-9_-])pplx-[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])~',
        ],
        'secret.github_fine_grained_token' => [
            'marker' => 'github_pat_',
            'regex' => '~(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{30,}(?![A-Za-z0-9_])~',
        ],
        'secret.github_token' => [
            'marker' => 'gh',
            'regex' => '~(?<![A-Za-z0-9_])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}(?![A-Za-z0-9_])~',
        ],
        'secret.stripe_live_key' => [
            'marker' => '_live_',
            'regex' => '~(?<![A-Za-z0-9_])(?:sk_live|rk_live)_[A-Za-z0-9]{16,}(?![A-Za-z0-9_])~',
        ],
        'secret.slack_token' => [
            'marker' => 'xox',
            'regex' => '~(?<![A-Za-z0-9_-])xox(?:b|p|a|s)-[A-Za-z0-9-]{24,}(?![A-Za-z0-9_-])~',
        ],
        // This prefix is shared by multiple AI providers. Never attribute it
        // to OpenAI/DeepSeek/Mistral without context.
        'ai.generic_sk_key' => [
            'marker' => 'sk-',
            'regex' => '~(?<![A-Za-z0-9_-])sk-[A-Za-z0-9]{32,}(?![A-Za-z0-9_-])~',
        ],
    ];

    /** @var array<string, true>|null */
    private ?array $enabledRules;

    /**
     * Null enables every built-in rule; [] disables all value rules.
     * Unknown rule identifiers fail explicitly to avoid silent misconfiguration.
     *
     * @param list<string>|null $enabledRules
     */
    public function __construct(?array $enabledRules = null)
    {
        $allowed = array_merge(array_values(self::PRIVATE_KEY_HEADERS), array_keys(self::PATTERNS));

        if ($enabledRules !== null) {
            foreach ($enabledRules as $rule) {
                if (! in_array($rule, $allowed, true)) {
                    throw new InvalidArgumentException('Unknown LeakProof value detection rule.');
                }
            }
        }

        $this->enabledRules = $enabledRules === null ? null : array_fill_keys($enabledRules, true);
    }

    /** @return list<string> */
    public static function supportedRules(): array
    {
        return array_values(array_unique(array_merge(array_values(self::PRIVATE_KEY_HEADERS), array_keys(self::PATTERNS))));
    }

    public function match(string $value): ?string
    {
        foreach (self::PRIVATE_KEY_HEADERS as $header => $rule) {
            if ($this->enabled($rule) && str_contains($value, $header)) {
                return $rule;
            }
        }

        foreach (self::PATTERNS as $rule => $pattern) {
            if (! $this->enabled($rule) || ! str_contains($value, $pattern['marker'])) {
                continue;
            }

            if (preg_match($pattern['regex'], $value) === 1) {
                return $rule;
            }
        }

        return null;
    }

    private function enabled(string $rule): bool
    {
        return $this->enabledRules === null || isset($this->enabledRules[$rule]);
    }
}
