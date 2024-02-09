<?php

declare(strict_types=1);

namespace Equit\Totp\Tests\Types;

use Cassandra\Time;
use Equit\Totp\Tests\Framework\TestCase;
use Equit\Totp\Types\TimeStep;

class TimeStepTest extends TestCase
{
    private TimeStep $timeStep;

    public function setUp(): void
    {
        $this->timeStep = new TimeStep(TimeStep::DefaultTimeStep);
    }

    public function tearDown(): void
    {
        unset($this->timeStep);
    }

    public static function dataForTestConstructor1(): iterable
    {
        for ($seconds = 1; $seconds < 600; ++$seconds) {
            yield "{$seconds} seconds" => [$seconds];
        }
    }

    /**
     * Ensure we can construct TimeSteps with valid time steps in seconds.
     * @dataProvider dataForTestConstructor1
     */
    public function testConstructor1(int $seconds): void
    {
        $timeStep = new TimeStep($seconds);
        self::assertSame($seconds, $timeStep->seconds());
    }
}
