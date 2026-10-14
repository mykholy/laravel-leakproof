<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Inspection;

final class KeyDetector
{
    /** @var array<string, true> */
    private array $keys = [];

    /** @param list<string> $sensitiveKeys */
    public function __construct(array $sensitiveKeys)
    {
        foreach ($sensitiveKeys as $key) {
            if ($key !== '') {
                $this->keys[self::normalize($key)] = true;
            }
        }
    }

    public function matches(string $key): bool
    {
        return isset($this->keys[self::normalize($key)]);
    }

    private static function normalize(string $key): string
    {
        $key = preg_replace('/([A-Z]+)([A-Z][a-z])/', '$1_$2', $key) ?? $key;
        $key = preg_replace('/([a-z0-9])([A-Z])/', '$1_$2', $key) ?? $key;
        $key = preg_replace('/[^A-Za-z0-9]+/', '_', $key) ?? $key;

        return strtolower(trim($key, '_'));
    }
}
