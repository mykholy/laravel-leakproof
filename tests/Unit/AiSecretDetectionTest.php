<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Tests\Unit;

use InvalidArgumentException;
use Mykholy\LeakProof\Inspection\Inspector;
use Mykholy\LeakProof\Inspection\KeyDetector;
use Mykholy\LeakProof\Inspection\ValueDetector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AiSecretDetectionTest extends TestCase
{
    /** @return iterable<string, array{string, string}> */
    public static function credentialExamples(): iterable
    {
        // Every value is synthetic: no real credentials are stored in tests.
        yield 'OpenAI project' => ['sk-proj-'.str_repeat('A', 48), 'ai.openai_project_key'];
        yield 'OpenAI project with separators' => ['sk-proj-'.str_repeat('A', 24).'-'.str_repeat('B', 24), 'ai.openai_project_key'];
        yield 'OpenAI service' => ['sk-svcacct-'.str_repeat('C', 48), 'ai.openai_service_key'];
        yield 'OpenAI admin' => ['sk-admin-'.str_repeat('D', 48), 'ai.openai_admin_key'];
        yield 'Anthropic API' => ['sk-ant-api03-'.str_repeat('E', 48), 'ai.anthropic_key'];
        yield 'Anthropic admin' => ['sk-ant-admin01-'.str_repeat('F', 48), 'ai.anthropic_key'];
        yield 'Gemini / Google API' => ['AIza'.str_repeat('G', 35), 'ai.google_api_key'];
        yield 'Hugging Face' => ['hf_'.str_repeat('H', 34), 'ai.huggingface_token'];
        yield 'Groq' => ['gsk_'.str_repeat('I', 48), 'ai.groq_key'];
        yield 'Replicate' => ['r8_'.str_repeat('J', 38), 'ai.replicate_token'];
        yield 'Pinecone' => ['pcsk_'.str_repeat('K', 35), 'ai.pinecone_key'];
        yield 'Perplexity' => ['pplx-'.str_repeat('L', 40), 'ai.perplexity_key'];
        yield 'Shared sk prefix' => ['sk-'.str_repeat('M', 48), 'ai.generic_sk_key'];
        yield 'GitHub fine-grained' => ['github_pat_'.str_repeat('N', 52), 'secret.github_fine_grained_token'];
        yield 'GitHub classic' => ['ghp_'.str_repeat('O', 40), 'secret.github_token'];
        yield 'Stripe live' => ['sk_live_'.str_repeat('P', 24), 'secret.stripe_live_key'];
        yield 'Slack' => ['xoxb-'.str_repeat('1234567890', 3), 'secret.slack_token'];
        yield 'OpenSSH private key' => ['-----BEGIN OPENSSH PRIVATE KEY-----', 'secret.private_key_material'];
        yield 'Encrypted private key' => ['-----BEGIN ENCRYPTED PRIVATE KEY-----', 'secret.private_key_material'];
        yield 'PGP private key' => ['-----BEGIN PGP PRIVATE KEY BLOCK-----', 'secret.private_key_material'];
    }

    #[DataProvider('credentialExamples')]
    public function test_detects_synthetic_credential_without_leaking_value(string $secret, string $rule): void
    {
        $report = (new Inspector(new KeyDetector([]), new ValueDetector))->inspect(['data' => ['note' => 'Bearer '.$secret]]);
        self::assertFalse($report->passed());
        self::assertCount(1, $report->findings);
        self::assertSame($rule, $report->findings[0]->rule);
        self::assertStringNotContainsString($secret, $report->summary());
        self::assertStringNotContainsString($secret, json_encode($report, JSON_THROW_ON_ERROR));
    }

    /** @return iterable<string, array{string}> */
    public static function harmlessExamples(): iterable
    {
        yield 'Short OpenAI-like string' => ['sk-proj-not-a-token'];
        yield 'Short Anthropic-like string' => ['sk-ant-api03-example'];
        yield 'Google-like string too short' => ['AIza'.str_repeat('A', 34)];
        yield 'Google-like string too long' => ['AIza'.str_repeat('A', 36)];
        yield 'Short Hugging Face' => ['hf_example'];
        yield 'Short Groq' => ['gsk_short'];
        yield 'Short Replicate' => ['r8_short'];
        yield 'Short GitHub' => ['github_pat_example'];
        yield 'Incomplete PEM' => ['-----BEGIN CERTIFICATE-----'];
        yield 'Provider documentation' => ['Use OPENAI_API_KEY, ANTHROPIC_API_KEY or GEMINI_API_KEY'];
        yield 'Common AI model ID' => ['gpt-4o-mini'];
        yield 'Mixed text' => ['The sk-proj- prefix can appear in documentation.'];
    }

    #[DataProvider('harmlessExamples')]
    public function test_does_not_flag_harmless_strings(string $value): void
    {
        self::assertNull((new ValueDetector)->match($value));
    }

    public function test_rejects_unknown_rule_identifiers(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new ValueDetector(['ai.nonexistent_rule']);
    }

    public function test_rule_selection_and_legacy_api_compatibility(): void
    {
        $example = 'sk-proj-'.str_repeat('A', 48);
        self::assertNull((new ValueDetector([]))->match($example));
        self::assertNull((new ValueDetector(['ai.groq_key']))->match($example));
        self::assertSame('ai.openai_project_key', (new ValueDetector(['ai.openai_project_key']))->match($example));
        self::assertContains('ai.openai_project_key', ValueDetector::supportedRules());
    }

    public function test_value_scanning_can_be_disabled_without_suppressing_key_scanning(): void
    {
        $inspector = new Inspector(new KeyDetector(['api_key']), new ValueDetector, false);
        $payload = ['public_note' => 'sk-proj-'.str_repeat('A', 48), 'api_key' => 'unused'];
        $report = $inspector->inspect($payload);

        self::assertCount(1, $report->findings);
        self::assertSame('field.sensitive_key', $report->findings[0]->rule);
    }

    public function test_scans_token_inside_nested_response_with_sanitized_path(): void
    {
        $token = 'hf_'.str_repeat('H', 34);
        $inspector = new Inspector(new KeyDetector([]), new ValueDetector);
        $report = $inspector->inspect(['data' => [['message' => 'Found token: '.$token]]]);

        self::assertCount(1, $report->findings);
        self::assertSame('$.data[0].message', $report->findings[0]->path);
        self::assertSame('ai.huggingface_token', $report->findings[0]->rule);
        self::assertStringNotContainsString($token, $report->summary());
    }
}
