<?php

declare(strict_types=1);

namespace Mykholy\LeakProof;

use Illuminate\Support\ServiceProvider;
use Mykholy\LeakProof\Console\ScanCommand;
use Mykholy\LeakProof\Http\Middleware\AuditJsonResponses;
use Mykholy\LeakProof\Inspection\Inspector;
use Mykholy\LeakProof\Inspection\KeyDetector;
use Mykholy\LeakProof\Inspection\ValueDetector;

final class LeakProofServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/leakproof.php', 'leakproof');

        $this->app->singleton(LeakProof::class, function ($app): LeakProof {
            $config = $app['config'];

            return new LeakProof(new Inspector(
                new KeyDetector((array) $config->get('leakproof.sensitive_keys', [])),
                new ValueDetector,
                (bool) $config->get('leakproof.scan_secret_values', true),
                (int) $config->get('leakproof.max_depth', 32),
                (int) $config->get('leakproof.max_nodes', 50000),
                (int) $config->get('leakproof.max_findings', 100),
            ));
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/leakproof.php' => config_path('leakproof.php'),
        ], 'leakproof-config');

        $this->app['router']->aliasMiddleware('leakproof', AuditJsonResponses::class);

        if ($this->app->runningInConsole()) {
            $this->commands([ScanCommand::class]);
        }
    }
}
