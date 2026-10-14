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

    public function testSafeResponsePasses(): void
    {
        self::assertTrue($this->inspector()->inspect(['data' => [['name' => 'Alice']]])->passed());
    }

    public function testNestedFieldsAndCamelCaseAreFound(): void
    {
        $report = $this->inspector()->inspect(['data' => [['password' => 'hidden'], ['accessToken' => 'hidden']]]);
        self::assertFalse($report->passed());
        self::assertSame('$.data[0].password', $report->findings[0]->path);
        self::assertSame('$.data[1].accessToken', $report->findings[1]->path);
        self::assertStringNotContainsString('hidden', json_encode($report, JSON_THROW_ON_ERROR));
    }

    public function testExactWildcardAllowlistDoesNotHideOtherFields(): void
    {
        $report = $this->inspector()->inspect(['data' => [['access_token' => 'ok', 'password' => 'hidden']]], ['data.*.access_token']);
        self::assertCount(1, $report->findings);
        self::assertSame('$.data[0].password', $report->findings[0]->path);
    }

    public function testTraversalLimitsAreInconclusive(): void
    {
        self::assertTrue($this->inspector(maxNodes: 1)->inspect(['a' => 1, 'password' => 'hidden'])->truncated);
        self::assertTrue($this->inspector(maxDepth: 1)->inspect(['a' => ['b' => ['password' => 'hidden']]])->truncated);
        self::assertTrue($this->inspector(maxFindings: 1)->inspect(['password' => 'hidden', 'access_token' => 'hidden'])->truncated);
    }

    public function testSecretFormatsAreDetectedWithoutExposingValues(): void
    {
        $secret = 'sk_live_'.str_repeat('Z', 24);
        $report = $this->inspector()->inspect(['note' => $secret]);
        self::assertSame('secret.stripe_live_key', $report->findings[0]->rule);
        self::assertStringNotContainsString($secret, $report->summary());
    }

    public function testDynamicKeysAreRedacted(): void
    {
        $email = 'person@example.com';
        $report = $this->inspector()->inspect(['people' => [$email => ['password' => 'hidden']]]);
        self::assertSame('$.people["<dynamic-key>"].password', $report->findings[0]->path);
        self::assertStringNotContainsString($email, $report->summary());
    }

    public function testNormalizedKeyNamesAndNoFuzzyMatches(): void
    {
        self::assertSame('$.APIKey', $this->inspector()->inspect(['APIKey' => 'hidden'])->findings[0]->path);
        self::assertTrue($this->inspector()->inspect(['password_hint' => 'public'])->passed());
    }
}
