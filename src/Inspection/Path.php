<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Inspection;

final class Path
{
    /** @param list<string> $segments */
    public static function render(array $segments): string
    {
        $path = '$';

        foreach ($segments as $segment) {
            if (strlen($segment) <= 8 && ctype_digit($segment)) {
                $path .= '['.$segment.']';
            } elseif (strlen($segment) <= 64
                && preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D', $segment) === 1
                && (new ValueDetector)->match($segment) === null) {
                $path .= '.'.$segment;
            } else {
                // Never print dynamic keys that might contain personal data.
                $path .= '["<dynamic-key>"]';
            }
        }

        return $path;
    }

    /**
     * A dotted allow rule may use * to match exactly one path segment.
     * @param list<string> $segments
     * @param list<string> $rules
     */
    public static function allowed(array $segments, array $rules): bool
    {
        foreach ($rules as $rule) {
            if ($rule === '') {
                continue;
            }

            $parts = explode('.', preg_replace('/^\$\./', '', $rule) ?? $rule);

            if (count($parts) !== count($segments)) {
                continue;
            }

            $matches = true;

            foreach ($parts as $index => $part) {
                if ($part !== '*' && $part !== $segments[$index]) {
                    $matches = false;
                    break;
                }
            }

            if ($matches) {
                return true;
            }
        }

        return false;
    }
}
