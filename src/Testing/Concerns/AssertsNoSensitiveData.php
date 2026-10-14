<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Testing\Concerns;

use Illuminate\Testing\TestResponse;
use Mykholy\LeakProof\Http\JsonPayload;
use Mykholy\LeakProof\LeakProof;
use PHPUnit\Framework\Assert;

trait AssertsNoSensitiveData
{
    /**
     * Fail this feature test when the response contains sensitive fields.
     * @param list<string> $allowedPaths
     */
    public function assertNoSensitiveData(TestResponse $response, array $allowedPaths = []): void
    {
        $max = (int) config('leakproof.max_response_bytes', 2097152);
        $payload = JsonPayload::decode((string) $response->getContent(), $max);
        $report = app(LeakProof::class)->inspect($payload, $allowedPaths);

        Assert::assertTrue($report->passed(), "Sensitive JSON response detected:\n".$report->summary());
    }
}
