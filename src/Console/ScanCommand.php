<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Console;

use Illuminate\Console\Command;
use Mykholy\LeakProof\Http\JsonPayload;
use Mykholy\LeakProof\LeakProof;
use Throwable;

final class ScanCommand extends Command
{
    protected $signature = 'leakproof:scan
        {file : Path to a local JSON fixture (never a URL)}
        {--allow=* : Explicitly allowed dotted JSON paths}
        {--format=text : Output format: text or json}';

    protected $description = 'Inspect a JSON fixture for sensitive fields without exposing their values.';

    public function handle(LeakProof $leakProof): int
    {
        $format = $this->option('format');

        if (! in_array($format, ['text', 'json'], true)) {
            $this->error('Invalid --format. Use text or json.');

            return self::FAILURE;
        }

        $file = $this->argument('file');
        $maxBytes = (int) config('leakproof.max_response_bytes', 2097152);

        try {
            if (! is_string($file) || ! is_file($file) || ! is_readable($file)) {
                throw new \InvalidArgumentException('The JSON file must exist and be readable.');
            }

            if (filesize($file) === false || filesize($file) > $maxBytes) {
                throw new \InvalidArgumentException('File exceeds the configured inspection limit.');
            }

            $raw = file_get_contents($file);
            if ($raw === false) {
                throw new \InvalidArgumentException('Unable to read the JSON file.');
            }

            $payload = JsonPayload::decode($raw, $maxBytes);
            $report = $leakProof->inspect($payload, (array) $this->option('allow'));
        } catch (Throwable $exception) {
            if ($format === 'json') {
                $this->line(json_encode(['error' => $exception->getMessage()], JSON_THROW_ON_ERROR));
            } else {
                $this->error($exception->getMessage());
            }

            return 2;
        }

        if ($format === 'json') {
            $this->line(json_encode($report, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT));
        } else {
            $this->line($report->summary());
        }

        return $report->passed() ? self::SUCCESS : self::FAILURE;
    }
}
