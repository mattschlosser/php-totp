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

use Equit\Totp\Exceptions\InvalidVerificationWindowException;
use Equit\Totp\Tests\Framework\TestCase;
use Exception;
use Generator;
use TypeError;

/**
 * Unit test for the InvalidVerificationWindowException class.
 */
class InvalidVerificationWindowExceptionTest extends TestCase
{
    /**
     * Test data for InvalidVerificationWindowException constructor.
     *
     * @return array The test data.
     */
    public function dataForTestConstructor(): array
    {
        return [
            "typicalMinus1" => [-1],
            "typicalWindowMessageAndCode" => [-1, "-1 is not a valid verification window.", 12,],
            "typicalWindowMessageCodeAndPrevious" => [-1, "-1 is not a valid verification window.", 12, new Exception("foo"),],
            "extremeIntMin" => [PHP_INT_MIN,],
            "invalidNullWindow" => [null, "null is not a valid verification window.", 12, new Exception("foo"), TypeError::class],
            "invalidStringWindow" => ["-1", "'-1' is not a valid verification window.", 12, new Exception("foo"), TypeError::class],
            "invalidFloatWindow" => [0.15, "0.15 is not a valid verification window.", 12, new Exception("foo"), TypeError::class],
            "invalidTrueWindow" => [true, "true is not a valid verification window.", 12, new Exception("foo"), TypeError::class],
            "invalidFalseWindow" => [false, "false is not a valid verification window.", 12, new Exception("foo"), TypeError::class],
            "invalidObjectWindow" => [(object)["window" => -1,], "object is not a valid verification window.", 12, new Exception("foo"), TypeError::class],
            "invalidArrayWindow" => [[-1,], "[-1] is not a valid verification window.", 12, new Exception("foo"), TypeError::class],
        ];
    }

    /**
     * Test for InvalidVerificationWindowException constructor.
     *
     * @dataProvider dataForTestConstructor
     *
     * @param mixed $window The invalid window for the test exception.
     * @param mixed $message The message for the test exception. Defaults to an empty string.
     * @param mixed $code The error code for the test exception. Defaults to 0.
     * @param mixed|null $previous The previous throwable for the test exception. Defaults to null.
     * @param string|null $exceptionClass The class name of the exception that is expected during the test, if any.
     */
    public function testConstructor(mixed $window, mixed $message = "", mixed $code = 0, mixed $previous = null, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $exception = new InvalidVerificationWindowException($window, $message, $code, $previous);
        $this->assertEquals($window, $exception->getWindow(), "Invalid window retrieved from exception was not as expected.");
        $this->assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        $this->assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        $this->assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /**
     * Test data for InvalidVerificationWindowException::getWindow().
     *
     * @return \Generator
     */
    public function dataForTestGetWindow(): Generator
    {
        yield from [
            "typicalMinus1" => [-1,],
            "extremeIntMin" => [PHP_INT_MIN,],
        ];

        for ($idx = 0; $idx < 100; ++$idx) {
            yield "random" . sprintf("%02d", $idx) => [mt_rand(PHP_INT_MIN, -1),];
        }
    }

    /**
     * Test the InvalidVerificationWindowException::getWindow() method.
     *
     * @dataProvider dataForTestGetWindow
     *
     * @param int $window The window to test with.
     */
    public function testGetWindow(int $window): void
    {
        $exception = new InvalidVerificationWindowException($window);
        $this->assertEquals($window, $exception->getWindow(), "Invalid window retrieved from exception was not as expected.");
    }
}
