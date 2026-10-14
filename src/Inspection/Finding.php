<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Inspection;

final readonly class Finding implements \JsonSerializable
{
    public function __construct(public string $path, public string $rule, public string $message) {}

    public function jsonSerialize(): array
    {
        return ['path' => $this->path, 'rule' => $this->rule, 'message' => $this->message];
    }
}
