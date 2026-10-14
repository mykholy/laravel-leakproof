<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Inspection;

final class Path
{
    /**
     * Only display known structural and credential field names. An arbitrary
     * identifier-shaped JSON object key may itself contain personal data.
     * Unknown keys are replaced with a non-sensitive placeholder.
     *
     * @var array<string, true>
     */
    private const SAFE_SEGMENTS = [
        'data' => true,
        'meta' => true,
        'links' => true,
        'included' => true,
        'errors' => true,
        'error' => true,
        'message' => true,
        'results' => true,
        'items' => true,
        'records' => true,
        'record' => true,
        'users' => true,
        'user' => true,
        'profile' => true,
        'attributes' => true,
        'settings' => true,
        'sessions' => true,
        'session' => true,
        'auth' => true,
        'credentials' => true,
        'payload' => true,
        'response' => true,
        'details' => true,
        'tokens' => true,
        'token' => true,
        'account' => true,
        'accounts' => true,
        'customer' => true,
        'customers' => true,
        'orders' => true,
        'order' => true,
        'products' => true,
        'product' => true,
        'password' => true,
        'password_hash' => true,
        'password_confirmation' => true,
        'remember_token' => true,
        'access_token' => true,
        'refresh_token' => true,
        'api_key' => true,
        'api_token' => true,
        'secret_key' => true,
        'client_secret' => true,
        'private_key' => true,
        'session_token' => true,
        'session_id' => true,
        'authorization' => true,
        'cookie' => true,
        'cvv' => true,
        'cvc' => true,
        'card_cvv' => true,
        'credit_card_number' => true,
        'otp_secret' => true,
        'totp_secret' => true,
        'two_factor_secret' => true,
        'two_factor_recovery_codes' => true,
        'recovery_codes' => true,
    ];

    /** @param  list<string>  $segments */
    public static function render(array $segments): string
    {
        $path = '$';

        foreach ($segments as $segment) {
            if (strlen($segment) <= 8 && ctype_digit($segment)) {
                $path .= '['.$segment.']';
            } elseif (self::safeIdentifier($segment)) {
                $path .= '.'.$segment;
            } else {
                $path .= '["<dynamic-key>"]';
            }
        }

        return $path;
    }

    private static function safeIdentifier(string $segment): bool
    {
        if (strlen($segment) > 64 || preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D', $segment) !== 1) {
            return false;
        }

        $normalized = preg_replace('/([A-Z]+)([A-Z][a-z])/', '$1_$2', $segment) ?? $segment;
        $normalized = preg_replace('/([a-z0-9])([A-Z])/', '$1_$2', $normalized) ?? $normalized;
        $normalized = preg_replace('/[^A-Za-z0-9]+/', '_', $normalized) ?? $normalized;

        return isset(self::SAFE_SEGMENTS[strtolower(trim($normalized, '_'))]);
    }

    /**
     * A dotted allow rule may use * to match exactly one path segment.
     *
     * @param  list<string>  $segments
     * @param  list<string>  $rules
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
