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

use Equit\Totp\Exceptions\InvalidDigitsException;
use Equit\Totp\Tests\Framework\TestCase;
use Exception;
use Generator;
use TypeError;

/**
 * Unit test for the InvalidDigitsException class.
 */
class InvalidDigitsExceptionTest extends TestCase
{

    /**
     * Test data for InvalidDigitsException constructor.
     *
     * @return Generator The test data.
     */
    public function dataForTestConstructor(): Generator
    {
        for ($digits = 1; $digits < 6; ++$digits) {
            yield "typical{$digits}" => [$digits];
        }

        yield from [
            "typicalDigitsAndMessage" => [1, "1 is not a valid number of digits.",],
            "typicalDigitsMessageAndCode" => [1, "1 is not a valid number of digits.", 12,],
            "typicalDigitsMessageCodeAndPrevious" => [1, "1 is not a valid number of digits.", 12, new Exception("foo"),],
            "invalidNullDigits" => [null, "Null is not a valid number of digits.", 12, new Exception("foo"), TypeError::class],
            "invalidStringDigits" => ["1", "'1' is not a valid number of digits.", 12, new Exception("foo"), TypeError::class],
            "invalidFloatDigits" => [1.115, "1.115 is not a valid number of digits.", 12, new Exception("foo"), TypeError::class],
            "invalidTrueDigits" => [true, "True is not a valid number of digits.", 12, new Exception("foo"), TypeError::class],
            "invalidFalseDigits" => [false, "False is not a valid number of digits.", 12, new Exception("foo"), TypeError::class],
            "invalidObjectDigits" => [(object)["digits" => 1,], "This is not a valid number of digits.", 12, new Exception("foo"), TypeError::class],
            "invalidStringableDigits" => [self::createStringable("1"), "'1' is not a valid number of digits.", 12, new Exception("foo"), TypeError::class],
            "invalidArrayDigits" => [[1,], "[1] is not a valid number of digits.", 12, new Exception("foo"), TypeError::class],
        ];
    }

    /**
     * Test for the InvalidDigitsException constructor.
     *
     * @dataProvider dataForTestConstructor
     *
     * @param mixed $digits The invalid number of digits for the test exception.
     * @param mixed $message The message for the test exception. Defaults to an empty string.
     * @param mixed $code The error code for the test exception. Defaults to 0.
     * @param mixed|null $previous The previous throwable for the test exception. Defaults to null.
     * @param string|null $exceptionClass The class name of the exception that is expected during the test, if any.
     */
    public function testConstructor(mixed $digits, mixed $message = "", mixed $code = 0, mixed $previous = null, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $exception = new InvalidDigitsException($digits, $message, $code, $previous);
        $this->assertEquals($digits, $exception->getDigits(), "Invalid number of digits retrieved from exception was not as expected.");
        $this->assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        $this->assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        $this->assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /**
     * Test data for InvalidDigitsException::getDigits().
     *
     * @return \Generator
     */
    public function dataForTestGetDigits(): Generator
    {
        yield from [
            "typical" => [5,],
            "extremeZero" => [0,],
            "extremeMinus7" => [-7,],
        ];

        for ($idx = 0; $idx < 100; ++$idx) {
            yield "random" . sprintf("%02d", $idx) => [mt_rand(PHP_INT_MIN, 5),];
        }
    }

    /**
     * Test the InvalidDigitsException::getDigits() method.
     *
     * @dataProvider dataForTestGetDigits
     *
     * @param int $digits The number of digits to test with.
     */
    public function testGetDigits(int $digits): void
    {
        $exception = new InvalidDigitsException($digits);
        $this->assertEquals($digits, $exception->getDigits(), "Invalid number of digits retrieved from exception was not as expected.");
    }
}
