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

namespace Equit\Totp\Tests\Exceptions;

use Equit\Totp\Exceptions\InvalidBase64DataException;
use Equit\Totp\Tests\Framework\TestCase;
use Exception;
use Generator;
use TypeError;

/**
 * Unit test for the InvalidBase64DataException class.
 */
class InvalidBase64DataExceptionTest extends TestCase
{
    /**
     * Generate a random string that is guaranteed not to be a valid Base64 string.
     *
     * @return string The generated string.
     */
    private static function randomInvalidBase64String(): string
    {
        static $alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";

        $str = "_";

        for ($length = mt_rand(4, 24); 0 !== $length; --$length) {
            $str .= $alphabet[mt_rand(0, strlen($alphabet) - 1)];
        }

        return $str;
    }

    /**
     * Test data for InvalidBase64DataException constructor.
     *
     * @return array The test data.
     */
    public function dataForTestConstructor(): array
    {
        return [
            "typicalDataOnly" => ["blah_:",],
            "typicalDataAndMessage" => ["blah_:", "'blah_:' is not valid base64 content.",],
            "typicalDataMessageAndCode" => ["blah_:", "'blah_:' is not valid base64 content.", 12,],
            "typicalDataMessageCodeAndPrevious" => ["blah_:", "'blah_:' is not valid base64 content.", 12, new Exception("foo"),],
            "invalidNullData" => [null, "null is not valid base64 content.", 12, new Exception("foo"), TypeError::class],
            "invalidStringableData" => [self::createStringable("blah_:"), "'blah_:' is not valid base64 content.", 12, new Exception("foo"), TypeError::class],
            "invalidIntData" => [1, "1 is not valid base64 content.", 12, new Exception("foo"), TypeError::class],
            "invalidFloatData" => [1.115, "1.115 is not valid base64 content.", 12, new Exception("foo"), TypeError::class],
            "invalidTrueData" => [true, "true is not valid base64 content.", 12, new Exception("foo"), TypeError::class],
            "invalidFalseData" => [false, "false is not valid base64 content.", 12, new Exception("foo"), TypeError::class],
            "invalidArrayData" => [["blah_:",], "['blah_:'] is not valid base64 content.", 12, new Exception("foo"), TypeError::class],
        ];
    }

    /**
     * Test for the InvalidBase64DataException constructor.
     *
     * @dataProvider dataForTestConstructor
     *
     * @param mixed $data The invalid base64 data for the test exception.
     * @param mixed $message The message for the test exception. Defaults to an empty string.
     * @param mixed $code The error code for the test exception. Defaults to 0.
     * @param mixed|null $previous The previous throwable for the test exception. Defaults to null.
     * @param string|null $exceptionClass The class name of the exception that is expected during the test, if any.
     */
    public function testConstructor(mixed $data, mixed $message = "", mixed $code = 0, mixed $previous = null, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $exception = new InvalidBase64DataException($data, $message, $code, $previous);
        $this->assertEquals($data, $exception->getData(), "Invalid Base64 data retrieved from exception was not as expected.");
        $this->assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        $this->assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        $this->assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /**
     * Test data for InvalidBase64DataException::getData().
     *
     * @return Generator
     */
    public function dataForTestGetData(): Generator
    {
        yield from [
            "typical" => ["fizzbuzz",],
            "extremeEmpty" => ["",],
        ];

        for ($idx = 0; $idx < 100; ++$idx) {
            yield "typicalRandom" . sprintf("%02d", $idx) => [self::randomInvalidBase64String(),];
        }
    }

    /**
     * Test the InvalidBase64DataException::getData() method.
     *
     * @dataProvider dataForTestGetData
     *
     * @param string $data The data to test with.
     */
    public function testGetData(string $data): void
    {
        $exception = new InvalidBase64DataException($data);
        $this->assertEquals($data, $exception->getData(), "Invalid Base64 data retrieved from exception was not as expected.");
    }
}
