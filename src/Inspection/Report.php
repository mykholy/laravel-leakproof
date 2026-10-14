<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Inspection;

final readonly class Report implements \JsonSerializable
{
    /** @param list<Finding> $findings */
    public function __construct(public array $findings, public int $visitedNodes, public bool $truncated) {}

    public function passed(): bool
    {
        return $this->findings === [] && ! $this->truncated;
    }

    public function summary(): string
    {
        $lines = array_map(static fn (Finding $finding): string => sprintf('%s [%s]', $finding->path, $finding->rule), $this->findings);

        if ($this->truncated) {
            $lines[] = 'Inspection limit reached; result is incomplete.';
        }

        return $lines === [] ? 'No sensitive fields detected.' : implode("\n", $lines);
    }

    /** @return array{passed: bool, truncated: bool, visited_nodes: int, findings: list<Finding>} */
    public function jsonSerialize(): array
    {
        return [
            'passed' => $this->passed(),
            'truncated' => $this->truncated,
            'visited_nodes' => $this->visitedNodes,
            'findings' => $this->findings,
        ];
    }
}
