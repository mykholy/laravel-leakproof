<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Inspection;

final class ValueDetector
{
    public function match(string $value): ?string
    {
        if (str_contains($value, '-----BEGIN PRIVATE KEY-----')
            || str_contains($value, '-----BEGIN RSA PRIVATE KEY-----')
            || str_contains($value, '-----BEGIN EC PRIVATE KEY-----')) {
            return 'secret.private_key_material';
        }

        if (preg_match('/\b(?:sk_live|rk_live)_[A-Za-z0-9]{16,}\b/D', $value) === 1) {
            return 'secret.stripe_live_key';
        }

        if (preg_match('/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b/D', $value) === 1) {
            return 'secret.github_token';
        }

        return null;
    }
}
