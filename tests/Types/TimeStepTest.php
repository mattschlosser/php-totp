<?php

declare(strict_types=1);

namespace Equit\TotpTests\Types;

use DateInterval;
use Equit\Totp\Exceptions\InvalidTimeStepException;
use Equit\TotpTests\Framework\TestCase;
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

    public static function dataForTestConstructor2(): iterable
    {
        for ($seconds = 0; $seconds >= -100; --$seconds) {
            yield "{$seconds} seconds" => [$seconds];
        }

        yield "php-int-min" => [PHP_INT_MIN];
    }

    /**
     * Ensure the constructor throws with invalid time steps.
     * @dataProvider dataForTestConstructor2
     */
    public function testConstructor2(int $seconds): void
    {
        self::expectException(InvalidTimeStepException::class);
        self::expectExceptionMessage("Expected valid TOTP time step, found {$seconds}");
        new TimeStep($seconds);
    }

    public function testSeconds1(): void
    {
        self::assertSame(TimeStep::DefaultTimeStep, $this->timeStep->seconds());
    }

    /** @dataProvider dataForTestConstructor1 */
    public function testFromSeconds1(int $seconds): void
    {
        $timeStep = TimeStep::fromSeconds($seconds);
        self::assertSame($seconds, $timeStep->seconds());
    }

    /** @dataProvider dataForTestConstructor2 */
    public function testFromSeconds2(int $seconds): void
    {
        self::expectException(InvalidTimeStepException::class);
        self::expectExceptionMessage("Expected valid TOTP time step, found {$seconds}");
        TimeStep::fromSeconds($seconds);
    }

    public static function dataForTestFromMinutes1(): iterable
    {
        for ($minutes = 1; $minutes <= 60; ++$minutes) {
            yield "{$minutes} minutes" => [$minutes, 60 * $minutes,];
        }
    }

    /** @dataProvider dataForTestFromMinutes1 */
    public function testFromMinutes1(int $minutes, int $expectedSeconds): void
    {
        $timeStep = TimeStep::fromMinutes($minutes);
        self::assertSame($expectedSeconds, $timeStep->seconds());
    }

    public static function dataForTestFromMinutes2(): iterable
    {
        for ($minutes = 0; $minutes >= -60; --$minutes) {
            yield "{$minutes} minutes" => [$minutes, 60 * $minutes];
        }
    }

    /** @dataProvider dataForTestFromMinutes2 */
    public function testFromMinutes2(int $minutes, $invalidSeconds): void
    {
        self::expectException(InvalidTimeStepException::class);
        self::expectExceptionMessage("Expected valid TOTP time step, found {$invalidSeconds}");
        TimeStep::fromMinutes($minutes);
    }

    /** Ensure time steps convert to string as expected. */
    public function testToString1(): void
    {
        self::assertSame("30", $this->timeStep->__toString());
    }

    public static function dataForTestFromDateInterval1(): iterable
    {
        yield "one-second" => [new DateInterval("PT1S"), 1,];
        yield "ten-seconds" => [new DateInterval("PT10S"), 10,];
        yield "sixty-seconds" => [new DateInterval("PT60S"), 60,];
        yield "two-minutes-thirty-seconds" => [new DateInterval("PT2M30S"), 150,];
        yield "one-hour" => [new DateInterval("PT1H"), 3600,];
        yield "two-hours-eleven-minutes-three-seconds" => [new DateInterval("PT2H11M3S"), 7863,];
        yield "one-day" => [new DateInterval("P1D"), 86400,];
    }

    /**
     * Ensure we can successfully create a TimeStep from a DateInterval.
     * @dataProvider dataForTestFromDateInterval1
     */
    public function testFromDateInterval1(DateInterval $interval, int $expectedSeconds): void
    {
        $timeStep = TimeStep::fromDateInterval($interval);
        self::assertSame($expectedSeconds, $timeStep->seconds());
    }

    public static function dataForTestFromDateInterval2(): iterable
    {
        yield "has-month" => [new DateInterval("P1MT1S"), 1,];
        yield "has-year" => [new DateInterval("P1YT1S"), 10,];
    }

    /**
     * Ensure we can successfully create a TimeStep from a DateInterval.
     * @dataProvider dataForTestFromDateInterval2
     */
    public function testFromDateInterval2(DateInterval $interval): void
    {
        self::expectException(InvalidTimeStepException::class);
        self::expectExceptionMessage("Expected DateInterval without years or months, found {$interval->y} year(s), {$interval->m} month(s)");
        TimeStep::fromDateInterval($interval);
    }
}
