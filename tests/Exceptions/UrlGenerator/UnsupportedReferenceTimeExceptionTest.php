<?php
/*
 * Copyright 2022 Darren Edale
 *
 * This file is part of the php-totp package.
 *
 * php-totp is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License v2.0.
 *
 * php-totp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Apache License for more details.
 *
 * You should have received a copy of the Apache License v2.0
 * along with php-totp. If not, see <http://www.apache.org/licenses/>.
 */

declare(strict_types=1);

namespace Equit\Totp\Tests\Exceptions\UrlGenerator;

use Equit\Totp\Exceptions\UrlGenerator\UnsupportedReferenceTimeException;
use Equit\Totp\Tests\Framework\TestCase;
use DateTime;
use DateTimeZone;
use Exception;
use Generator;
use InvalidArgumentException;
use TypeError;

/**
 * Unit test for the UnsupportedReferenceTimeException class.
 */
class UnsupportedReferenceTimeExceptionTest extends TestCase
{
    /**
     * When generating random timestamps, the earliest will be 80 years before the Unix epoch.
     */
    private const MinTimestamp = -80 * 365 * 24 * 60 * 60;

    /**
     * When generating random timestamps, the latest will be 80 years after the Unix epoch.
     */
    private const MaxTimestamp = 80 * 365 * 24 * 60 * 60;

    /**
     * Test data for UnsupportedReferenceTimeException constructor.
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor should not throw with timestamp argument.
     */
    public function dataForTestConstructor(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with timestamp argument. */
        return [
            "typicalTimestamp60" => [60,],
            "typicalTimestamp120" => [120,],
            "typicalTimestampNow" => [time(),],
            "typicalDateTime60" => [new DateTime("@60", new DateTimeZone("UTC")),],
            "typicalDateTime120" => [new DateTime("@120", new DateTimeZone("UTC")),],
            "typicalDateTimeNow" => [new DateTime("@" . time(), new DateTimeZone("UTC")),],
            "typicalTimestampAndMessage" => [60, "60 is not a valid reference time.",],
            "typicalTimestampMessageAndCode" => [60, "60 is not a valid reference time.", 12,],
            "typicalTimestampMessageCodeAndPrevious" => [60, "60 is not a valid reference time.", 12, new Exception("foo"),],
            "typicalDateTimeAndMessage" => [new DateTime("@60", new DateTimeZone("UTC")), "60 is not a valid reference time.",],
            "typicalDateTimeMessageAndCode" => [new DateTime("@60", new DateTimeZone("UTC")), "60 is not a valid reference time.", 12,],
            "typicalDateTimeMessageCodeAndPrevious" => [new DateTime("@60", new DateTimeZone("UTC")), "60 is not a valid reference time.", 12, new Exception("foo"),],
            "extremeVeryEarly" => [self::MinTimestamp,],
            "extremeVeryLate" => [self::MaxTimestamp,],
            "invalidNullTime" => [null, "null is not a valid reference time.", 12, new Exception("foo"), TypeError::class],
            "invalidStringTime" => ["1970-01-01 00:01:00", "'1970-01-01 00:01:00' is not a valid reference time.", 12, new Exception("foo"), TypeError::class],
            "invalidStringableTimestamp" => [self::createStringable("0"), "'0' is not a valid reference time.", 12, new Exception("foo"), TypeError::class],
            "invalidStringableDateTime" => [self::createStringable("1970-01-01 00:01:00"), "'1970-01-01 00:01:00' is not a valid reference time.", 12, new Exception("foo"), TypeError::class],
            "invalidFloatTime" => [0.15, "0.15 is not a valid reference time.", 12, new Exception("foo"), TypeError::class],
            "invalidTrueTime" => [true, "true is not a valid reference time.", 12, new Exception("foo"), TypeError::class],
            "invalidFalseTime" => [false, "false is not a valid reference time.", 12, new Exception("foo"), TypeError::class],
            "invalidObjectTimeastamp" => [(object)["time" => 60,], "object is not a valid reference time.", 12, new Exception("foo"), TypeError::class],
            "invalidObjectDateTime" => [(object)["time" => "1970-01-01 00:01:00",], "object is not a valid reference time.", 12, new Exception("foo"), TypeError::class],
            "invalidArrayTimestamp" => [[60,], "[60] is not a valid reference time.", 12, new Exception("foo"), TypeError::class],
            "invalidArrayTime" => [["1970-01-01 00:01:00",], "'1970-01-01 00:01:00' is not a valid reference time.", 12, new Exception("foo"), TypeError::class],
        ];
    }

    /**
     * Test for the UnsupportedReferenceTimeException constructor.
     *
     * @dataProvider dataForTestConstructor
     *
     * @param mixed $time The invalid time for the test exception.
     * @param mixed $message The message for the test exception. Defaults to an empty string.
     * @param mixed $code The error code for the test exception. Defaults to 0.
     * @param mixed|null $previous The previous throwable for the test exception. Defaults to null.
     * @param string|null $exceptionClass The class name of the exception that is expected during the test, if any.
     *
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor should not throw with timestamp argument.
     */
    public function testConstructor(mixed $time, mixed $message = "", mixed $code = 0, mixed $previous = null, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $exception = new UnsupportedReferenceTimeException($time, $message, $code, $previous);

        if ($time instanceof DateTime) {
            $timestamp = $time->getTimestamp();
        } else {
            if (is_int($time)) {
                $timestamp = $time;
                /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with a timestamp argument. */
                $time = new DateTime("@{$time}", new DateTimeZone("UTC"));
            } else {
                if (!isset($exceptionClass)) {
                    throw new InvalidArgumentException("\$time is not a timestamp nor a DateTime - we should be expecting an exception but we're not.");
                }
            }
        }

        $this->assertEquals($time, $exception->getTime(), "Unsupported DateTime retrieved from exception was not as expected.");
        /** @noinspection PhpUndefinedVariableInspection We know $timestamp is defined because the only branch that doesn't define it throws */
        $this->assertEquals($timestamp, $exception->getTimestamp(), "Timestamp retrieved from exception was not as expected.");
        $this->assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        $this->assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        $this->assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /**
     * Test data for UnsupportedReferenceTimeException::getTimestamp().
     *
     * @return \Generator
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor should not throw with a timestamp argument.
     */
    public function dataForTestGetTimestamp(): Generator
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with a timestamp argument. */
        yield from [
            "typicalTimestamp60" => [60, 60,],
            "extremeVeryEarly" => [self::MinTimestamp, self::MinTimestamp,],
            "extremeVeryLate" => [self::MaxTimestamp, self::MaxTimestamp,],
            "typicalDateTime60" => [new DateTime("@60", new DateTimeZone("UTC")), 60,],
            "extremeDateTimeVeryEarly" => [new DateTime("@" . self::MinTimestamp, new DateTimeZone("UTC")), self::MinTimestamp,],
            "extremeDateTimeVeryLate" => [new DateTime("@" . self::MaxTimestamp, new DateTimeZone("UTC")), self::MaxTimestamp,],
        ];

        $nowTimestamp = time();
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with a timestamp argument. */
        $nowTime = new DateTime("@{$nowTimestamp}", new DateTimeZone("UTC"));
        yield "typicalNow" => [$nowTimestamp, $nowTimestamp,];
        yield "typicalDateTimeNow" => [$nowTime, $nowTimestamp,];

        for ($idx = 0; $idx < 100; ++$idx) {
            do {
                $timestamp = mt_rand(-60 * 365 * 24 * 60 * 60, 60 * 365 * 24 * 60 * 60);
            } while (0 === $timestamp);

            /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with a timestamp argument. */
            $time = new DateTime("@{$timestamp}", new DateTimeZone("UTC"));

            yield "randomTimestamp" . sprintf("%02d", $idx) => [$timestamp, $timestamp,];
            yield "randomDateTime" . sprintf("%02d", $idx) => [$time, $timestamp,];
        }
    }

    /**
     * Test the UnsupportedReferenceTimeException::getTimestamp() method.
     *
     * @dataProvider dataForTestGetTimestamp
     *
     * @param int|\DateTime $time The time to use to initialise the test exception.
     * @param int $expectedTimestamp The expected value returned from getTimestamp().
     */
    public function testGetTimestamp(int|DateTime $time, int $expectedTimestamp): void
    {
        $exception = new UnsupportedReferenceTimeException($time);
        $this->assertEquals($expectedTimestamp, $exception->getTimestamp(), "Unsupported reference timestamp retrieved from exception was not as expected.");
    }

    /**
     * Test data for UnsupportedReferenceTimeException::getTimestamp().
     *
     * @return \Generator
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor should not throw with a timestamp argument.
     */
    public function dataForTestGetTime(): Generator
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with a timestamp argument. */
        yield from [
            "typicalTimestamp60" => [60, new DateTime("@60", new DateTimeZone("UTC")),],
            "extremeVeryEarly" => [self::MinTimestamp, new DateTime("@" . self::MinTimestamp, new DateTimeZone("UTC")),],
            "extremeVeryLate" => [self::MaxTimestamp, new DateTime("@" . self::MaxTimestamp, new DateTimeZone("UTC")),],
            "typicalDateTime60" => [new DateTime("@60", new DateTimeZone("UTC")), new DateTime("@60", new DateTimeZone("UTC")),],
            "extremeDateTimeVeryEarly" => [new DateTime("@" . self::MinTimestamp, new DateTimeZone("UTC")), new DateTime("@" . self::MinTimestamp, new DateTimeZone("UTC")),],
            "extremeDateTimeVeryLate" => [new DateTime("@" . self::MaxTimestamp, new DateTimeZone("UTC")), new DateTime("@" . self::MaxTimestamp, new DateTimeZone("UTC")),],
        ];

        $nowTimestamp = time();
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with a timestamp argument. */
        $nowTime = new DateTime("@{$nowTimestamp}", new DateTimeZone("UTC"));
        yield "typicalNow" => [$nowTimestamp, $nowTime,];
        yield "typicalDateTimeNow" => [$nowTime, $nowTime,];

        for ($idx = 0; $idx < 100; ++$idx) {
            do {
                $timestamp = mt_rand(self::MinTimestamp, self::MaxTimestamp);
            } while (0 === $timestamp);

            /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with a timestamp argument. */
            $time = new DateTime("@{$timestamp}", new DateTimeZone("UTC"));

            yield "randomTimestamp" . sprintf("%02d", $idx) => [$timestamp, $time,];
            yield "randomDateTime" . sprintf("%02d", $idx) => [$time, $time,];
        }
    }

    /**
     * Test the UnsupportedReferenceTimeException::getTime() method.
     *
     * @dataProvider dataForTestGetTime
     *
     * @param int|\DateTime $time The time to use to initialise the test exception.
     * @param \DateTime $expectedTime The expected value returned from getDateTime().
     */
    public function testGetTime(int|DateTime $time, DateTime $expectedTime): void
    {
        $exception = new UnsupportedReferenceTimeException($time);
        $this->assertEquals($expectedTime, $exception->getTime(), "Unsupported DateTime retrieved from exception was not as expected.");
    }
}
