<?php

declare(strict_types=1);

return [
    // Middleware must be explicitly attached to a route. It is off by default.
    'mode' => env('LEAKPROOF_MODE', 'off'),
    // Exact normalized identifiers (camelCase/kebab-case converted to snake_case).
    'sensitive_keys' => [
        'password', 'password_confirmation', 'password_hash', 'remember_token',
        'access_token', 'refresh_token', 'api_token', 'api_key', 'secret_key',
        'client_secret', 'private_key', 'session_token', 'session_id',
        'authorization', 'cookie', 'cvv', 'cvc', 'card_cvv',
        'credit_card_number', 'otp_secret', 'totp_secret', 'two_factor_secret',
        'two_factor_recovery_codes', 'recovery_codes',
    ],
    'scan_secret_values' => true,
    // Named route => exact JSON paths. Wildcard matches one segment.
    'allowed_paths' => [],
    'max_depth' => 32,
    'max_nodes' => 50000,
    'max_findings' => 100,
    'max_response_bytes' => 2097152,
];
