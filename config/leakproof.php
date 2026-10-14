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
        // AI APIs and inference providers (field-name detection, regardless of token format).
        'openai_api_key', 'anthropic_api_key', 'gemini_api_key',
        'google_ai_api_key', 'google_api_key', 'vertex_ai_api_key',
        'azure_openai_api_key', 'azure_ai_api_key',
        'huggingface_token', 'hugging_face_token', 'huggingface_api_key',
        'groq_api_key', 'replicate_api_token', 'replicate_api_key',
        'cohere_api_key', 'mistral_api_key', 'deepseek_api_key',
        'perplexity_api_key', 'pinecone_api_key', 'together_api_key',
        'fireworks_api_key', 'openrouter_api_key', 'elevenlabs_api_key',
        'bedrock_secret_access_key', 'aws_secret_access_key',
        'ai_api_key', 'llm_api_key', 'inference_api_key',
        'xai_api_key', 'grok_api_key', 'nvidia_api_key', 'nvidia_ngc_api_key',
        'tavily_api_key', 'fal_api_key', 'voyage_api_key', 'ai21_api_key',
        'cerebras_api_key', 'langsmith_api_key', 'langchain_api_key',
        'weaviate_api_key', 'qdrant_api_key', 'modal_token_secret',
    ],
    'scan_secret_values' => true,
    // Null enables all built-in value rules. Use an explicit list of rule IDs
    // to enable a subset; [] disables all value rules (not sensitive key detection).
    'value_rules' => null,
    // Named route => exact JSON paths. Wildcard matches one segment.
    'allowed_paths' => [],
    'max_depth' => 32,
    'max_nodes' => 50000,
    'max_findings' => 100,
    'max_response_bytes' => 2097152,
];
