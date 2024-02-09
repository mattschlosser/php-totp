<?php
/*
 * Copyright 2024 Darren Edale
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

namespace Equit\Totp\Tests\Exceptions;

use Equit\Totp\Exceptions\InvalidTimeException;
use Equit\Totp\Tests\Framework\TestCase;
use DateTime;
use DateTimeZone;
use Exception;
use Generator;
use TypeError;

/**
 * Unit test for the InvalidTimeException class.
 */
class InvalidTimeExceptionTest extends TestCase
{
    /**
     * Test data for InvalidTimeException constructor.
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor shouldn't throw with test data.
     */
    public function dataForTestConstructor(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor shouldn't throw with test data. */
        return [
            "typicalTimestamp0" => [0,],
            "typicalTimestamp60" => [60,],
            "typicalTimestampNow" => [time(),],
            "typicalDateTime0" => [new DateTime("@0", new DateTimeZone("UTC")),],
            "typicalDateTime60" => [new DateTime("@60", new DateTimeZone("UTC")),],
            "typicalDateTimeNow" => [new DateTime("@" . time(), new DateTimeZone("UTC")),],
            "typicalTimestampAndMessage" => [0, "0 is not a valid time.",],
            "typicalTimestampMessageAndCode" => [0, "0 is not a valid time.", 12,],
            "typicalTimestampMessageCodeAndPrevious" => [0, "0 is not a valid time.", 12, new Exception("foo"),],
            "typicalTimeAndMessage" => [new DateTime("@0", new DateTimeZone("UTC")), "Unix epoch is not a valid time.",],
            "typicalTimeMessageAndCode" => [new DateTime("@0", new DateTimeZone("UTC")), "Unix epoch is not a valid time.", 12,],
            "typicalTimeMessageCodeAndPrevious" => [new DateTime("@0", new DateTimeZone("UTC")), "Unix epoch is not a valid time.", 12, new Exception("foo"),],
            "extremeIntMin" => [PHP_INT_MIN,],
            "extremeMaxDateTime" => [new DateTime("9999-12-31 23:59:59", new DateTimeZone("UTC")),],
            "invalidNullTime" => [null, "null is not a valid time.", 12, new Exception("foo"), TypeError::class],
            "invalidStringTime" => ["1970-01-01 00:00:00", "'1970-01-01 00:00:00' is not a valid time.", 12, new Exception("foo"), TypeError::class],
            "invalidStringableTime" => [self::createStringable("1970-01-01 00:00:00"), "'1970-01-01 00:00:00' is not a valid time.", 12, new Exception("foo"), TypeError::class],
            "invalidFloatTime" => [0.15, "0.15 is not a valid time.", 12, new Exception("foo"), TypeError::class],
            "invalidTrueTime" => [true, "true is not a valid time.", 12, new Exception("foo"), TypeError::class],
            "invalidFalseTime" => [false, "false is not a valid time.", 12, new Exception("foo"), TypeError::class],
            "invalidObjectTime" => [(object)["time" => "1970-01-01 00:00:00",], "object is not a valid time.", 12, new Exception("foo"), TypeError::class],
            "invalidArrayTime" => [["1970-01-01 00:00:00",], "['1970-01-01 00:00:00'] is not a valid time.", 12, new Exception("foo"), TypeError::class],
        ];
    }

    /**
     * Test for the InvalidTimeException constructor.
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

        $exception = new InvalidTimeException($time, $message, $code, $previous);

        if ($time instanceof DateTime) {
            $timestamp = $time->getTimestamp();
        } else {
            $timestamp = $time;
            /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with timestamp argument. */
            $time = new DateTime("@{$time}", new DateTimeZone("UTC"));
        }

        $this->assertEquals($time, $exception->getTime(), "DateTime retrieved from exception was not as expected.");
        $this->assertEquals($timestamp, $exception->getTimestamp(), "Timestamp retrieved from exception was not as expected.");
        $this->assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        $this->assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        $this->assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /**
     * Test data for InvalidTimeException::getTimestamp().
     *
     * @return \Generator
     */
    public function dataForTestGetTimestamp(): Generator
    {
        yield from [
            "typical0" => [0,],
            "extremeIntMin" => [PHP_INT_MIN,],
        ];

        yield "typicalNow" => [time(),];

        for ($idx = 0; $idx < 100; ++$idx) {
            yield "random" . sprintf("%02d", $idx) => [mt_rand(PHP_INT_MIN, PHP_INT_MAX),];
        }
    }

    /**
     * Test the InvalidTimeException::getTimestamp() method.
     *
     * @dataProvider dataForTestGetTimestamp
     *
     * @param int $timestamp The timestamp to test with.
     */
    public function testGetTimestamp(int $timestamp): void
    {
        $exception = new InvalidTimeException($timestamp);
        $this->assertEquals($timestamp, $exception->getTimestamp(), "Invalid timestamp retrieved from exception was not as expected.");
    }

    /**
     * Test data for InvalidTimeException::getDateTime().
     *
     * @return \Generator
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor should not throw with timestamp argument.
     */
    public function dataForTestGetDateTime(): Generator
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with timestamp argument. */
        yield from [
            "typical0" => [0, new DateTime("@0", new DateTimeZone("UTC")),],
            "extremeIntMin" => [PHP_INT_MIN, new DateTime("@" . PHP_INT_MIN, new DateTimeZone("UTC")),],
        ];

        $now = time();
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with timestamp argument. */
        yield "now" => [$now, new DateTime("@{$now}", new DateTimeZone("UTC")),];

        for ($idx = 0; $idx < 100; ++$idx) {
            $time = mt_rand(PHP_INT_MIN, PHP_INT_MAX);
            yield "random" . sprintf("%02d", $idx) => [$time, new DateTime("@{$time}", new DateTimeZone("UTC")),];
        }
    }

    /**
     * Test the InvalidTimeException::getDateTime() method.
     *
     * @dataProvider dataForTestGetDateTime
     *
     * @param int $timestamp The timestamp to use to initialise the test exception.
     * @param \DateTime $expectedTime The expected value returned from getDateTime().
     */
    public function testGetDateTime(int $timestamp, DateTime $expectedTime): void
    {
        $exception = new InvalidTimeException($timestamp);
        $this->assertEquals($expectedTime, $exception->getTime(), "Invalid DateTime retrieved from exception was not as expected.");
    }
}
