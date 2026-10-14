<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Inspection;

use InvalidArgumentException;

final readonly class Inspector
{
    public function __construct(
        private KeyDetector $keyDetector,
        private ValueDetector $valueDetector,
        private bool $scanValues = true,
        private int $maxDepth = 32,
        private int $maxNodes = 50000,
        private int $maxFindings = 100,
    ) {
        if ($maxDepth < 1 || $maxNodes < 1 || $maxFindings < 1) {
            throw new InvalidArgumentException('Inspection limits must be greater than zero.');
        }
    }

    /**
     * Inspect a decoded JSON payload, without retaining the original values.
     * @param array<array-key, mixed> $payload
     * @param list<string> $allowedPaths
     */
    public function inspect(array $payload, array $allowedPaths = []): Report
    {
        $findings = [];
        $visited = 0;
        $truncated = false;

        /** @var list<array{value: array<array-key, mixed>, path: list<string>, depth: int}> $stack */
        $stack = [['value' => $payload, 'path' => [], 'depth' => 0]];

        while ($stack !== []) {
            $item = array_pop($stack);

            foreach (array_reverse($item['value'], true) as $key => $value) {
                if ($visited >= $this->maxNodes || count($findings) >= $this->maxFindings) {
                    $truncated = true;
                    break 2;
                }

                ++$visited;
                $path = [...$item['path'], (string) $key];

                if (Path::allowed($path, $allowedPaths)) {
                    continue;
                }

                if (is_string($key) && $this->keyDetector->matches($key)) {
                    $findings[] = new Finding(Path::render($path), 'field.sensitive_key', 'Sensitive field present in JSON response.');

                    continue;
                }

                if (is_string($value) && $this->scanValues) {
                    $rule = $this->valueDetector->match($value);

                    if ($rule !== null) {
                        $findings[] = new Finding(Path::render($path), $rule, 'Credential-like value present in JSON response.');
                    }
                }

                if (is_array($value) && $value !== []) {
                    if ($item['depth'] >= $this->maxDepth) {
                        $truncated = true;
                    } else {
                        $stack[] = ['value' => $value, 'path' => $path, 'depth' => $item['depth'] + 1];
                    }
                }
            }
        }

        return new Report(array_slice($findings, 0, $this->maxFindings), $visited, $truncated);
    }
}
