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

namespace Equit\TotpTests\Exceptions\UrlGenerator;

use Equit\Totp\Exceptions\UrlGenerator\InvalidUserException;
use Equit\TotpTests\Framework\TestCase;
use Exception;
use Generator;
use TypeError;

/**
 * Unit test for the InvalidUserException class.
 */
class InvalidUserExceptionTest extends TestCase
{
    /**
     * Generate a random user string.
     *
     * @return string The generated user.
     */
    private static function randomUser(): string
    {
        static $users = [
            "darren", "Susan", "clive", "mo.iqbal", "peggy-sue", "Art.Garfunkel", "david", "superuser", "administrator", "COLIN",
            "MARK", "abney", "Abbey", "abi", "sami", "Usman", "imran", "urma", "Ootha", "forbes",
            "ruariadh", "conor", "chuck", "Chet", "mowgli", "abu", "Herman", "FRANCOISE", "cortana", "siri",
            "alexa", "mortimer", "zbigniew", "Alasdair", "Michael", "filip", "Sven", "jacqui", "peter", "petra",
        ];

        return $users[mt_rand(0, count($users) - 1)];
    }

    /**
     * Test data for InvalidUserException constructor.
     *
     * @return array The test data.
     */
    public function dataForTestConstructor(): array
    {
        return [
            "typicalUserOnly" => ["",],
            "typicalUserAndMessage" => ["", "'' is not a valid user.",],
            "typicalUserMessageAndCode" => ["", "'' is not a valid user.", 12,],
            "typicalUserMessageCodeAndPrevious" => ["", "'' is not a valid user.", 12, new Exception("foo"),],
            "invalidNullUser" => [null, "null is not a valid user.", 12, new Exception("foo"), TypeError::class],
            "invalidStringableUser" => [self::createStringable(""), "'' is not a valid user.", 12, new Exception("foo"), TypeError::class],
            "invalidIntUser" => [1, "1 is not a valid user.", 12, new Exception("foo"), TypeError::class],
            "invalidFloatUser" => [1.115, "1.115 is not a valid user.", 12, new Exception("foo"), TypeError::class],
            "invalidTrueUser" => [true, "true is not a valid user.", 12, new Exception("foo"), TypeError::class],
            "invalidFalseUser" => [false, "false is not a valid user.", 12, new Exception("foo"), TypeError::class],
            "invalidArrayUser" => [["",], "[''] is not a valid user.", 12, new Exception("foo"), TypeError::class],
        ];
    }

    /**
     * Test for the InvalidUserException constructor.
     *
     * @dataProvider dataForTestConstructor
     *
     * @param mixed $user The invalid user for the test exception.
     * @param mixed $message The message for the test exception. Defaults to an empty string.
     * @param mixed $code The error code for the test exception. Defaults to 0.
     * @param mixed|null $previous The previous throwable for the test exception. Defaults to null.
     * @param string|null $exceptionClass The class name of the exception that is expected during the test, if any.
     */
    public function testConstructor(mixed $user, mixed $message = "", mixed $code = 0, mixed $previous = null, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $exception = new InvalidUserException($user, $message, $code, $previous);
        $this->assertEquals($user, $exception->getUser(), "Invalid user retrieved from exception was not as expected.");
        $this->assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        $this->assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        $this->assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /**
     * Test data for InvalidUserException::getUser().
     *
     * @return Generator
     */
    public function dataForTestGetUser(): Generator
    {
        yield from [
            "typicalEmpty" => ["",],
            "typicalFilled" => ["darren",],
        ];

        for ($idx = 0; $idx < 100; ++$idx) {
            yield "typicalRandom" . sprintf("%02d", $idx) => [self::randomUser(),];
        }
    }

    /**
     * Test the InvalidUserException::getUser() method.
     *
     * @dataProvider dataForTestGetUser
     *
     * @param string $user The user to test with.
     */
    public function testGetUser(string $user): void
    {
        $exception = new InvalidUserException($user);
        $this->assertEquals($user, $exception->getUser(), "Invalid user retrieved from exception was not as expected.");
    }
}
