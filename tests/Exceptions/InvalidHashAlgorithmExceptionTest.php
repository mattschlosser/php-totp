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

use Equit\Totp\Exceptions\InvalidHashAlgorithmException;
use Equit\Totp\Tests\Framework\TestCase;
use Equit\Totp\Totp;
use Exception;
use Generator;
use TypeError;

/**
 * Unit test for the InvalidHashAlgorithmException class.
 */
class InvalidHashAlgorithmExceptionTest extends TestCase
{
    /**
     * Generate a random string that is guaranteed not to be a valid TOTP hash algorithm.
     *
     * The string returned will be one of the algorithms that is supported by PHP but is not valid for TOTP.
     *
     * @return string The generated invalid algorithm.
     */
    private static function randomInvalidAlgorithm(): string
    {
        static $algorithms = null;

        if (!isset($algorithms)) {
            $algorithms = array_values(array_filter(hash_algos(), fn(string $algorithm): bool => match ($algorithm) {
                Totp::Sha1Algorithm, Totp::Sha256Algorithm, Totp::Sha512Algorithm => false,
                default => true,
            }));
        }

        return $algorithms[mt_rand(0, count($algorithms) - 1)];
    }

    /**
     * Test data for InvalidHashAlgorithmException constructor.
     *
     * @return array The test data.
     */
    public function dataForTestConstructor(): array
    {
        return [
            "typicalAlgorithmOnly" => ["md5",],
            "typicalAlgorithmAndMessage" => ["md5", "'md5' is not a valid TOTP hash algorithm.",],
            "typicalAlgorithmMessageAndCode" => ["md5", "'md5' is not a valid TOTP hash algorithm.", 12,],
            "typicalAlgorithmMessageCodeAndPrevious" => ["md5", "'md5' is not a valid TOTP hash algorithm.", 12, new Exception("foo"),],
            "invalidNullAlgorithm" => [null, "null is not a valid TOTP hash algorithm.", 12, new Exception("foo"), TypeError::class],
            "invalidStringableAlgorithm" => [self::createStringable("md5"), "'md5' is not a valid TOTP hash algorithm.", 12, new Exception("foo"), TypeError::class],
            "invalidIntAlgorithm" => [1, "1 is not a valid TOTP hash algorithm.", 12, new Exception("foo"), TypeError::class],
            "invalidFloatAlgorithm" => [1.115, "1.115 is not a valid TOTP hash algorithm.", 12, new Exception("foo"), TypeError::class],
            "invalidTrueAlgorithm" => [true, "true is not a valid TOTP hash algorithm.", 12, new Exception("foo"), TypeError::class],
            "invalidFalseAlgorithm" => [false, "false is not a valid TOTP hash algorithm.", 12, new Exception("foo"), TypeError::class],
            "invalidArrayAlgorithm" => [["md5",], "'md5' is not a valid TOTP hash algorithm.", 12, new Exception("foo"), TypeError::class],
        ];
    }

    /**
     * Test for the InvalidHashAlgorithmException constructor.
     *
     * @dataProvider dataForTestConstructor
     *
     * @param mixed $hashAlgorithm The invalid algorithm for the test exception.
     * @param mixed $message The message for the test exception. Defaults to an empty string.
     * @param mixed $code The error code for the test exception. Defaults to 0.
     * @param mixed|null $previous The previous throwable for the test exception. Defaults to null.
     * @param string|null $exceptionClass The class name of the exception that is expected during the test, if any.
     */
    public function testConstructor(mixed $hashAlgorithm, mixed $message = "", mixed $code = 0, mixed $previous = null, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $exception = new InvalidHashAlgorithmException($hashAlgorithm, $message, $code, $previous);
        $this->assertEquals($hashAlgorithm, $exception->getHashAlgorithm(), "Invalid hash algorithm retrieved from exception was not as expected.");
        $this->assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        $this->assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        $this->assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /**
     * Test data for InvalidHashAlgorithmException::getAlgorithm().
     *
     * @return Generator
     */
    public function dataForTestGetAlgorithm(): Generator
    {
        yield from [
            "typical" => ["md5",],
            "extremeEmpty" => ["",],
            "extremeNearlyValid" => ["sha1 ",],
        ];

        for ($idx = 0; $idx < 100; ++$idx) {
            yield "typicalRandom" . sprintf("%02d", $idx) => [self::randomInvalidAlgorithm(),];
        }
    }

    /**
     * Test the InvalidHashAlgorithmException::getHashAlgorithm() method.
     *
     * @dataProvider dataForTestGetAlgorithm
     *
     * @param string $secret The algorithm to test with.
     */
    public function testGetAlgorithm(string $secret): void
    {
        $exception = new InvalidHashAlgorithmException($secret);
        $this->assertEquals($secret, $exception->getHashAlgorithm(), "Invalid hash algorithm retrieved from exception was not as expected.");
    }
}
