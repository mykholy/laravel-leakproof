<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Tests\Feature;

use Mykholy\LeakProof\LeakProofServiceProvider;
use Orchestra\Testbench\TestCase;

final class ScanCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [LeakProofServiceProvider::class];
    }

    public function test_safe_fixture_passes(): void
    {
        $file = $this->fixture('{"data":{"name":"Alice"}}');
        try {
            $this->artisan('leakproof:scan', ['file' => $file])->assertExitCode(0);
        } finally {
            unlink($file);
        }
    }

    public function test_secret_fixture_fails(): void
    {
        $file = $this->fixture('{"data":{"password":"never-print"}}');
        try {
            $this->artisan('leakproof:scan', ['file' => $file, '--format' => 'json'])->assertExitCode(1);
        } finally {
            unlink($file);
        }
    }

    public function test_specific_allow_rules_pass(): void
    {
        $file = $this->fixture('{"data":{"access_token":"token"}}');
        try {
            $this->artisan('leakproof:scan', ['file' => $file, '--allow' => ['data.access_token']])->assertExitCode(0);
        } finally {
            unlink($file);
        }
    }

    public function test_invalid_fixture_returns_input_error(): void
    {
        $file = $this->fixture('{broken');
        try {
            $this->artisan('leakproof:scan', ['file' => $file])->assertExitCode(2);
        } finally {
            unlink($file);
        }
    }

    private function fixture(string $json): string
    {
        $file = tempnam(sys_get_temp_dir(), 'leakproof-');
        if ($file === false || file_put_contents($file, $json) === false) {
            throw new \RuntimeException('Unable to create a temporary fixture.');
        }

        return $file;
    }
}
