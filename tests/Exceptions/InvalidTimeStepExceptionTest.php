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

use Equit\Totp\Exceptions\InvalidTimeStepException;
use Equit\Totp\Tests\Framework\TestCase;
use Exception;
use Generator;
use TypeError;

/**
 * Unit test for the InvalidTimeStepException class.
 */
class InvalidTimeStepExceptionTest extends TestCase
{

    /**
     * Test data for InvalidTimeStepException constructor.
     *
     * @return array The test data.
     */
    public function dataForTestConstructor(): array
    {
        return [
            "typical0" => [0],
            "typicalTimeStepMessageAndCode" => [0, "0 is not a valid time step.", 12,],
            "typicalTimeStepMessageCodeAndPrevious" => [0, "0 is not a valid time step.", 12, new Exception("foo"),],
            "extremeMinus1" => [-1,],
            "extremeIntMin" => [PHP_INT_MIN,],
            "invalidNullTimeStep" => [null, "null is not a valid time step.", 12, new Exception("foo"), TypeError::class],
            "invalidStringTimeStep" => ["0", "'0'' is not a valid time step.", 12, new Exception("foo"), TypeError::class],
            "invalidFloatTimeStep" => [0.15, "0.15 is not a valid time step.", 12, new Exception("foo"), TypeError::class],
            "invalidTrueTimeStep" => [true, "true is not a valid time step.", 12, new Exception("foo"), TypeError::class],
            "invalidFalseTimeStep" => [false, "false is not a valid time step.", 12, new Exception("foo"), TypeError::class],
            "invalidObjectTimeStep" => [(object)["time step" => 1,], "This is not a valid time step.", 12, new Exception("foo"), TypeError::class],
            "invalidArrayTimeStep" => [[0,], "[0] is not a valid time step.", 12, new Exception("foo"), TypeError::class],
        ];
    }

    /**
     * Test for the InvalidTimeStepException constructor.
     *
     * @dataProvider dataForTestConstructor
     *
     * @param mixed $timeStep The invalid time step for the test exception.
     * @param mixed $message The message for the test exception. Defaults to an empty string.
     * @param mixed $code The error code for the test exception. Defaults to 0.
     * @param mixed|null $previous The previous throwable for the test exception. Defaults to null.
     * @param string|null $exceptionClass The class name of the exception that is expected during the test, if any.
     */
    public function testConstructor(mixed $timeStep, mixed $message = "", mixed $code = 0, mixed $previous = null, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $exception = new InvalidTimeStepException($timeStep, $message, $code, $previous);
        $this->assertEquals($timeStep, $exception->getTimeStep(), "Invalid time step retrieved from exception was not as expected.");
        $this->assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        $this->assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        $this->assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /**
     * Test data for InvalidTimeStepException::getTimeStep().
     *
     * @return \Generator
     */
    public function dataForTestGetTimeStep(): Generator
    {
        yield from [
            "typical" => [0,],
            "extremeMinus1" => [-1,],
            "extremeIntMin" => [PHP_INT_MIN,],
        ];

        for ($idx = 0; $idx < 100; ++$idx) {
            yield "random" . sprintf("%02d", $idx) => [mt_rand(PHP_INT_MIN, 0),];
        }
    }

    /**
     * Test the InvalidTimeStepException::getTimeStep() method.
     *
     * @dataProvider dataForTestGetTimeStep
     *
     * @param int $timeStep The time step to test with.
     */
    public function testGetTimeStep(int $timeStep): void
    {
        $exception = new InvalidTimeStepException($timeStep);
        $this->assertEquals($timeStep, $exception->getTimeStep(), "Invalid time step retrieved from exception was not as expected.");
    }
}
