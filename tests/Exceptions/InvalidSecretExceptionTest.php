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

use Equit\Totp\Exceptions\InvalidSecretException;
use Equit\Totp\Tests\Framework\TestCase;
use Exception;
use Generator;
use TypeError;

/**
 * Unit test for the InvalidSecretException class.
 */
class InvalidSecretExceptionTest extends TestCase
{
    /**
     * Test data for InvalidSecretException constructor.
     *
     * @return array The test data.
     */
    public function dataForTestConstructor(): array
    {
        return [
            "typicalSecretOnly" => ["blah_:",],
            "typicalSecretAndMessage" => ["blah_:", "'blah_:' is not a valid TOTP secret.",],
            "typicalSecretMessageAndCode" => ["blah_:", "'blah_:' is not a valid TOTP secret.", 12,],
            "typicalSecretMessageCodeAndPrevious" => ["blah_:", "'blah_:' is not a valid TOTP secret.", 12, new Exception("foo"),],
            "invalidNullSecret" => [null, "null is not a valid TOTP secret.", 12, new Exception("foo"), TypeError::class],
            "invalidStringableSecret" => [self::createStringable("blah_:"), "'blah_:' is not a valid TOTP secret.", 12, new Exception("foo"), TypeError::class],
            "invalidIntSecret" => [1, "1 is not a valid TOTP secret.", 12, new Exception("foo"), TypeError::class],
            "invalidFloatSecret" => [1.115, "1.115 is not a valid TOTP secret.", 12, new Exception("foo"), TypeError::class],
            "invalidTrueSecret" => [true, "true is not a valid TOTP secret.", 12, new Exception("foo"), TypeError::class],
            "invalidFalseSecret" => [false, "false is not a valid TOTP secret.", 12, new Exception("foo"), TypeError::class],
            "invalidObjectSecret" => [(object)["secret" => "blah_:",], "object is not a valid TOTP secret.", 12, new Exception("foo"), TypeError::class],
            "invalidArraySecret" => [["blah_:",], "'blah_:' is not a valid TOTP secret.", 12, new Exception("foo"), TypeError::class],
        ];
    }

    /**
     * Test for the InvalidSecretException constructor.
     *
     * @dataProvider dataForTestConstructor
     *
     * @param mixed $secret The invalid secret for the test exception.
     * @param mixed $message The message for the test exception. Defaults to an empty string.
     * @param mixed $code The error code for the test exception. Defaults to 0.
     * @param mixed|null $previous The previous throwable for the test exception. Defaults to null.
     * @param string|null $exceptionClass The class name of the exception that is expected during the test, if any.
     */
    public function testConstructor(mixed $secret, mixed $message = "", mixed $code = 0, mixed $previous = null, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $exception = new InvalidSecretException($secret, $message, $code, $previous);
        $this->assertEquals($secret, $exception->getSecret(), "Invalid secret retrieved from exception was not as expected.");
        $this->assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        $this->assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        $this->assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /**
     * Test data for InvalidSecretException::getSecret().
     *
     * @return Generator
     */
    public function dataForTestGetSecret(): Generator
    {
        yield from [
            "typical" => ["fizzbuzz",],
            "extremeEmpty" => ["",],
            "extremeNearestInvalid" => ["bvcoaw872bkjsdn",],
        ];

        for ($idx = 0; $idx < 100; ++$idx) {
            yield "typicalRandom" . sprintf("%02d", $idx) => [self::randomInvalidSecret(),];
        }
    }

    /**
     * Test the InvalidSecretException::getSecret() method.
     *
     * @dataProvider dataForTestGetSecret
     *
     * @param string $secret The secret to test with.
     */
    public function testGetSecret(string $secret): void
    {
        $exception = new InvalidSecretException($secret);
        $this->assertEquals($secret, $exception->getSecret(), "Invalid secret retrieved from exception was not as expected.");
    }
}
