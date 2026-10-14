<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Http;

use InvalidArgumentException;
use JsonException;

final class JsonPayload
{
    /** @return array<array-key, mixed> */
    public static function decode(string $json, int $maxBytes = 2097152): array
    {
        if ($maxBytes < 1) {
            throw new InvalidArgumentException('The maximum response size must be positive.');
        }

        if (strlen($json) > $maxBytes) {
            throw new InvalidArgumentException('JSON exceeds configured inspection limit.');
        }

        try {
            $payload = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Invalid JSON response: '.$exception->getMessage(), previous: $exception);
        }

        if (! is_array($payload)) {
            throw new InvalidArgumentException('Expected a JSON object or array as response root.');
        }

        return $payload;
    }
}
