<?php

declare(strict_types=1);

/**
 * Reproducible micro-benchmark for the detection core (not an application SLA).
 * Usage: php tools/benchmark.php [iterations], e.g. php tools/benchmark.php 200
 * Never use real API credentials or production response dumps as fixtures.
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'Mykholy\\LeakProof\\';
    if (str_starts_with($class, $prefix)) {
        require dirname(__DIR__).'/src/'.str_replace('\\', '/', substr($class, strlen($prefix))).'.php';
    }
});

use Mykholy\LeakProof\Inspection\Inspector;
use Mykholy\LeakProof\Inspection\KeyDetector;
use Mykholy\LeakProof\Inspection\ValueDetector;

$iterations = filter_var($argv[1] ?? '100', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 10000]]);

if ($iterations === false) {
    fwrite(STDERR, "Usage: php tools/benchmark.php [iterations 1..10000]\n");
    exit(2);
}

$inspector = new Inspector(new KeyDetector(['password', 'api_key']), new ValueDetector);
$cases = [
    '1kb-safe' => ['data' => [['message' => str_repeat('a', 1024)]]],
    '100kb-safe' => ['data' => array_fill(0, 100, ['message' => str_repeat('b', 1024)])],
    '100kb-mixed' => ['data' => array_fill(0, 100, ['message' => str_repeat('c', 1024)])],
];
$cases['100kb-mixed']['data'][42]['message'] = 'sk-proj-'.str_repeat('D', 48);

foreach ($cases as $label => $payload) {
    $start = hrtime(true);
    $findings = 0;
    for ($i = 0; $i < $iterations; $i++) {
        $report = $inspector->inspect($payload);
        if ($report->truncated) {
            fwrite(STDERR, "Benchmark truncated unexpectedly.\n");
            exit(1);
        }
        $findings += count($report->findings);
    }

    $milliseconds = (hrtime(true) - $start) / 1000000 / $iterations;

    echo sprintf("%-13s %7.3f ms/scan %5d findings total, peak memory %.1f MiB\n",
        $label,
        $milliseconds,
        $findings,
        memory_get_peak_usage(true) / 1048576,
    );
}
