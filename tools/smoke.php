<?php

declare(strict_types=1);

// These core checks run without Composer or Laravel dependencies.
spl_autoload_register(static function (string $class): void {
    $prefix = 'Mykholy\\LeakProof\\';
    if (str_starts_with($class, $prefix)) {
        require dirname(__DIR__).'/src/'.str_replace('\\', '/', substr($class, strlen($prefix))).'.php';
    }
});

use Mykholy\LeakProof\Http\JsonPayload;
use Mykholy\LeakProof\Inspection\Inspector;
use Mykholy\LeakProof\Inspection\KeyDetector;
use Mykholy\LeakProof\Inspection\ValueDetector;

$inspector = new Inspector(new KeyDetector(['password', 'access_token']), new ValueDetector);
$checks = 0;
$check = static function (bool $result) use (&$checks): void {
    $checks++;
    if (! $result) {
        fwrite(STDERR, "FAILED core check {$checks}\n");
        exit(1);
    }
};

$check($inspector->inspect(['name' => 'Alice'])->passed());
$check($inspector->inspect(['password' => 'hidden'])->findings[0]->path === '$.password');
$check($inspector->inspect(['data' => [['accessToken' => 'hidden']]])->findings[0]->path === '$.data[0].accessToken');
$check($inspector->inspect(['data' => [['password' => 'hidden']]], ['data.*.password'])->passed());
$check(! $inspector->inspect(['data' => [['password' => 'hidden']]], ['*.password'])->passed());
$check(! str_contains($inspector->inspect(['people' => ['email@example.com' => ['password' => 'hidden']]])->summary(), 'email@example.com'));
$check(! str_contains(json_encode($inspector->inspect(['password' => 'hidden']), JSON_THROW_ON_ERROR), 'hidden'));
$check((new Inspector(new KeyDetector([]), new ValueDetector, true, 32, 1))->inspect(['a' => 1, 'b' => 2])->truncated);
$check(JsonPayload::decode('{"ok":true}') === ['ok' => true]);

echo "PASS: {$checks} core checks\n";
