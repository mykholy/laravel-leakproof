<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Tests\Feature;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Mykholy\LeakProof\Exceptions\SensitiveDataDetected;
use Mykholy\LeakProof\LeakProofServiceProvider;
use Mykholy\LeakProof\Testing\Concerns\AssertsNoSensitiveData;
use Orchestra\Testbench\TestCase;

final class IntegrationTest extends TestCase
{
    use AssertsNoSensitiveData;

    protected function getPackageProviders($app): array
    {
        return [LeakProofServiceProvider::class];
    }

    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware('leakproof')->get('/leaky', static fn () => response()->json(['data' => ['password' => 'hidden']]))->name('leaky');
        Route::middleware('leakproof')->get('/safe', static fn () => response()->json(['data' => ['name' => 'Alice']]))->name('safe');
        Route::middleware('leakproof')->get('/login', static fn () => response()->json(['data' => ['access_token' => 'token']]))->name('login');
    }

    public function testMiddlewareDisabledByDefault(): void
    {
        $this->getJson('/leaky')->assertOk();
    }

    public function testFeatureAssertionsDetectLeaks(): void
    {
        $this->assertNoSensitiveData($this->getJson('/safe'));
        $this->expectException(\PHPUnit\Framework\AssertionFailedError::class);
        $this->assertNoSensitiveData($this->getJson('/leaky'));
    }

    public function testExactAllowlistWorks(): void
    {
        $this->assertNoSensitiveData($this->getJson('/login'), ['data.access_token']);
    }

    public function testReportModeDoesNotChangeResponses(): void
    {
        config()->set('leakproof.mode', 'report');
        Log::spy();
        $this->getJson('/leaky')->assertOk()->assertJsonPath('data.password', 'hidden');
        Log::shouldHaveReceived('warning')->once();
    }

    public function testBlockModeThrows(): void
    {
        config()->set('leakproof.mode', 'block');
        $this->expectException(SensitiveDataDetected::class);
        $this->withoutExceptionHandling()->getJson('/leaky');
    }

    public function testNamedRouteAllowlistWorks(): void
    {
        config()->set('leakproof.mode', 'block');
        config()->set('leakproof.allowed_paths', ['login' => ['data.access_token']]);
        $this->getJson('/login')->assertOk();
    }
}
