<?php

declare(strict_types=1);

namespace Mykholy\LeakProof;

use Mykholy\LeakProof\Exceptions\SensitiveDataDetected;
use Mykholy\LeakProof\Inspection\Inspector;
use Mykholy\LeakProof\Inspection\Report;

final readonly class LeakProof
{
    public function __construct(private Inspector $inspector) {}

    /**
     * @param  array<array-key, mixed>  $payload
     * @param  list<string>  $allowedPaths
     */
    public function inspect(array $payload, array $allowedPaths = []): Report
    {
        return $this->inspector->inspect($payload, $allowedPaths);
    }

    /**
     * @param  array<array-key, mixed>  $payload
     * @param  list<string>  $allowedPaths
     */
    public function assertSafe(array $payload, array $allowedPaths = []): void
    {
        $report = $this->inspect($payload, $allowedPaths);

        if (! $report->passed()) {
            throw new SensitiveDataDetected($report);
        }
    }
}
