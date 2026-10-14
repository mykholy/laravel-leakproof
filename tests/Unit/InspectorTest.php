<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Tests\Unit;

use Mykholy\LeakProof\Inspection\Inspector;
use Mykholy\LeakProof\Inspection\KeyDetector;
use Mykholy\LeakProof\Inspection\ValueDetector;
use PHPUnit\Framework\TestCase;

final class InspectorTest extends TestCase
{
    private function inspector(int $maxDepth = 32, int $maxNodes = 1000, int $maxFindings = 100): Inspector
    {
        return new Inspector(new KeyDetector(['password', 'access_token', 'api_key']), new ValueDetector, true, $maxDepth, $maxNodes, $maxFindings);
    }

    public function test_safe_response_passes(): void
    {
        self::assertTrue($this->inspector()->inspect(['data' => [['name' => 'Alice']]])->passed());
    }

    public function test_nested_fields_and_camel_case_are_found(): void
    {
        $report = $this->inspector()->inspect(['data' => [['password' => 'hidden'], ['accessToken' => 'hidden']]]);
        self::assertFalse($report->passed());
        self::assertSame('$.data[0].password', $report->findings[0]->path);
        self::assertSame('$.data[1].accessToken', $report->findings[1]->path);
        self::assertStringNotContainsString('hidden', json_encode($report, JSON_THROW_ON_ERROR));
    }

    public function test_exact_wildcard_allowlist_does_not_hide_other_fields(): void
    {
        $report = $this->inspector()->inspect(['data' => [['access_token' => 'ok', 'password' => 'hidden']]], ['data.*.access_token']);
        self::assertCount(1, $report->findings);
        self::assertSame('$.data[0].password', $report->findings[0]->path);
    }

    public function test_traversal_limits_are_inconclusive(): void
    {
        self::assertTrue($this->inspector(maxNodes: 1)->inspect(['a' => 1, 'password' => 'hidden'])->truncated);
        self::assertTrue($this->inspector(maxDepth: 1)->inspect(['a' => ['b' => ['password' => 'hidden']]])->truncated);
        self::assertTrue($this->inspector(maxFindings: 1)->inspect(['password' => 'hidden', 'access_token' => 'hidden'])->truncated);
    }

    public function test_secret_formats_are_detected_without_exposing_values(): void
    {
        $secret = 'sk_live_'.str_repeat('Z', 24);
        $report = $this->inspector()->inspect(['note' => $secret]);
        self::assertSame('secret.stripe_live_key', $report->findings[0]->rule);
        self::assertStringNotContainsString($secret, $report->summary());
    }

    public function test_dynamic_keys_are_redacted(): void
    {
        $email = 'person@example.com';
        $report = $this->inspector()->inspect(['people' => [$email => ['password' => 'hidden']]]);
        self::assertSame('$["<dynamic-key>"]["<dynamic-key>"].password', $report->findings[0]->path);
        self::assertStringNotContainsString($email, $report->summary());
    }

    public function test_identifier_shaped_dynamic_keys_are_redacted(): void
    {
        $identifier = 'AhmedNationalId123456789';
        $report = $this->inspector()->inspect(['data' => [$identifier => ['password' => 'hidden']]]);

        self::assertSame('$.data["<dynamic-key>"].password', $report->findings[0]->path);
        self::assertStringNotContainsString($identifier, $report->summary());
        self::assertStringNotContainsString('hidden', json_encode($report, JSON_THROW_ON_ERROR));
    }

    public function test_unknown_plain_word_object_keys_are_redacted(): void
    {
        $report = $this->inspector()->inspect(['people' => ['johnsmith' => ['api_key' => 'hidden']]]);

        self::assertSame('$["<dynamic-key>"]["<dynamic-key>"].api_key', $report->findings[0]->path);
    }

    public function test_normalized_key_names_and_no_fuzzy_matches(): void
    {
        self::assertSame('$.APIKey', $this->inspector()->inspect(['APIKey' => 'hidden'])->findings[0]->path);
        self::assertTrue($this->inspector()->inspect(['password_hint' => 'public'])->passed());
    }
}
