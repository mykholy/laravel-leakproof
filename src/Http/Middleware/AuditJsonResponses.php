<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Http\Middleware;

use Closure;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use Mykholy\LeakProof\Exceptions\SensitiveDataDetected;
use Mykholy\LeakProof\Http\JsonPayload;
use Mykholy\LeakProof\LeakProof;
use Symfony\Component\HttpFoundation\Response;

final readonly class AuditJsonResponses
{
    public function __construct(private LeakProof $leakProof, private Config $config) {}

    public function handle(Request $request, Closure $next): Response
    {
        /** @var Response $response */
        $response = $next($request);
        $mode = $this->config->get('leakproof.mode', 'off');

        if ($mode === 'off') {
            return $response;
        }

        if (! in_array($mode, ['report', 'block'], true)) {
            throw new InvalidArgumentException('LEAKPROOF_MODE must be off, report or block.');
        }

        $type = strtolower((string) $response->headers->get('Content-Type', ''));
        if (! str_contains($type, '/json') && ! str_contains($type, '+json')) {
            return $response;
        }

        $content = $response->getContent();
        if (! is_string($content) || $content === '') {
            return $response;
        }

        $route = $request->route()?->getName();
        $configuredPaths = $this->config->get('leakproof.allowed_paths', []);
        $allowed = is_string($route) && is_array($configuredPaths)
            ? ($configuredPaths[$route] ?? []) : [];
        $allowed = is_array($allowed) ? array_values($allowed) : [];

        try {
            $data = JsonPayload::decode($content, (int) $this->config->get('leakproof.max_response_bytes', 2097152));
            $report = $this->leakProof->inspect($data, $allowed);
        } catch (InvalidArgumentException $exception) {
            if ($mode === 'block') {
                throw $exception;
            }

            Log::warning('LeakProof skipped an uninspectable JSON response.', [
                'route' => $route,
                'reason' => $exception->getMessage(),
            ]);

            return $response;
        }

        if ($report->passed()) {
            return $response;
        }

        if ($mode === 'block') {
            throw new SensitiveDataDetected($report);
        }

        Log::warning('LeakProof found a sensitive or incomplete JSON response.', [
            'route' => $route,
            'paths' => array_map(static fn ($finding): string => $finding->path, $report->findings),
            'truncated' => $report->truncated,
        ]);

        return $response;
    }
}
