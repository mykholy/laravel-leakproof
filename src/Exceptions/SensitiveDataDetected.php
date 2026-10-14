<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Exceptions;

use Mykholy\LeakProof\Inspection\Report;
use RuntimeException;

final class SensitiveDataDetected extends RuntimeException
{
    public function __construct(public readonly Report $report)
    {
        parent::__construct('LeakProof detected sensitive response fields: '.$report->summary());
    }
}
