<?php

declare(strict_types=1);

namespace Mykholy\LeakProof\Tests\Unit;

use InvalidArgumentException;
use Mykholy\LeakProof\Http\JsonPayload;
use PHPUnit\Framework\TestCase;

final class JsonPayloadTest extends TestCase
{
    public function testDecodesArraysAndObjects(): void
    {
        self::assertSame(['ok' => true], JsonPayload::decode('{"ok":true}'));
        self::assertSame([1, 2], JsonPayload::decode('[1,2]'));
    }

    public function testInvalidJsonIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        JsonPayload::decode('{broken');
    }

    public function testOversizedJsonIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        JsonPayload::decode('{"data":"too big"}', 5);
    }

    public function testPrimitiveRootIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        JsonPayload::decode('null');
    }
}
