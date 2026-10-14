<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Tests\Feature;

use Illuminate\Support\Facades\Route;
use Mykholy\LeakProof\LeakProofServiceProvider;
use Mykholy\LeakProof\Testing\Concerns\AssertsNoSensitiveData;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\AssertionFailedError;

final class AiSecretIntegrationTest extends TestCase
{
    use AssertsNoSensitiveData;

    protected function getPackageProviders($app): array
    {
        return [LeakProofServiceProvider::class];
    }

    protected function setUp(): void
    {
        parent::setUp();

        Route::get('/ai-config', static fn () => response()->json([
            'data' => ['config' => ['openaiApiKey' => 'synthetic-placeholder']],
        ]));
        Route::get('/ai-text', static fn () => response()->json([
            'data' => ['message' => 'sk-proj-'.str_repeat('Q', 48)],
        ]));
    }

    public function test_ai_provider_field_name_is_detected(): void
    {
        $this->expectException(AssertionFailedError::class);

        $this->assertNoSensitiveData($this->getJson('/ai-config'));
    }

    public function test_ai_secret_value_is_detected(): void
    {
        $this->expectException(AssertionFailedError::class);

        $this->assertNoSensitiveData($this->getJson('/ai-text'));
    }

    public function test_value_rules_can_be_disabled_without_disabling_key_rules(): void
    {
        config()->set('leakproof.value_rules', []);

        $this->assertNoSensitiveData($this->getJson('/ai-text'));

        $this->expectException(AssertionFailedError::class);

        $this->assertNoSensitiveData($this->getJson('/ai-config'));
    }
}
