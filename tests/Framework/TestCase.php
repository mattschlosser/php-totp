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

namespace Equit\Totp\Tests\Framework;

use Equit\Totp\Tests\Framework\Constraints\AllCharactersHaveChanged;
use Equit\Totp\Tests\Framework\Constraints\EquivalentOtpAuthUrl;
use Equit\Totp\Tests\Framework\Constraints\StringContainsOnly;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Stringable;

/**
 * Base class for all test cases in the php-totp library.
 */
class TestCase extends BaseTestCase
{
    /**
     * Helper to create a Stringable instance for testing purposes.
     *
     * The stringable will always return the provided string from its __toString() method.
     *
     * @param string $str
     *
     * @return \Stringable
     */
    protected static function createStringable(string $str): Stringable
    {
        return new class($str) implements Stringable
        {
            public string $str;

            public function __construct(string $str)
            {
                $this->str = $str;
            }

            public function __toString(): string
            {
                return $this->str;
            }
        };
    }

    /**
     * Generate a random binary string.
     *
     * A string of random bytes is generated of a given length. If no length is provided, a random length between 0 and
     * 200 is used. This means an empty string could be generated. The random string is not guaranteed to be
     * cryptographically secure.
     *
     * @param int|null $length The length of the string required.
     *
     * @return string A random binary string.
     */
    protected static function randomBinaryString(?int $length = null): string
    {
        if (!isset($length)) {
            $length = mt_rand(0, 200);
        }

        $str = "";

        for ($idx = 0; $idx < $length; ++$idx) {
            $str .= chr(mt_rand(0, 255));
        }

        return $str;
    }

    /**
     * Generate a random cryptographically-secure secret.
     *
     * A string of random bytes is generated of a given length. The length must be a valid TOTP secret length - that is,
     * between 16 and 64 bytes. If no length is provided, a random length between 16 and 64 is used. The random string
     * is guaranteed to be generated from cryptographically secure random data.
     *
     * @param int|null $length The length of the string required.
     *
     * @return string A random secret.
     * @throws \Exception if random_bytes() is not able to generate cryptographically-secure random data.
     */
    protected static function randomValidSecret(?int $length = null): string
    {
        if (!isset($length)) {
            $length = mt_rand(16, 64);
        }

        return random_bytes($length);
    }

    /**
     * Generate a random cryptographically-secure secret.
     *
     * A string of random bytes is generated of a given length. The length must be an invalid TOTP secret length - that
     * is, between 0 and 15 bytes. If no length is provided, a random length between 0 and 15 is used. The random string
     * is guaranteed to be generated from cryptographically secure random data.
     *
     * @param int|null $length The length of the string required. It must be between 0 and 15 inclusive.
     *
     * @return string A random invalid secret.
     * @throws \Exception if random_bytes() is not able to generate cryptographically-secure random data.
     */
    protected static function randomInvalidSecret(?int $length = null): string
    {
        if (!isset($length)) {
            $length = mt_rand(0, 15);
        }

        if (0 === $length) {
            return "";
        }

        return random_bytes($length);
    }

    /**
     * Assert that a string contains only characters that are present in another string.
     *
     * @param string $allowableCharacters The string containing the allowable characters.
     * @param string $actualString The string to test.
     * @param string $message Optional message for use when the assertion fails.
     */
    public static function assertStringContainsOnly(string $allowableCharacters, string $actualString, string $message = ""): void
    {
        static::assertThat($actualString, new StringContainsOnly($allowableCharacters), $message);
    }

    /**
     * Assert that a string's characters have all changed from a given previous content.
     *
     * @param string $before The content of the string before it underwent the process that is required to have changed
     * all the characters.
     * @param string $after The content of the string after the process.
     * @param string $message Optional message for use when the assertion fails.
     */
    public static function assertAllCharactersHaveChanged(string $before, string $after, string $message = ""): void
    {
        static::assertThat($after, new AllCharactersHaveChanged($before), $message);
    }

    /**
     * Assert that an OTP provisioning URL is equivalent to another.
     *
     * @param string $referenceUrl The URL that the tested URL should match.
     * @param string $actualUrl The URL to test.
     * @param string $message Optional message for use when the assertion fails.
     *
     * @throws \Equit\Totp\Tests\Framework\Exceptions\InvalidOtpUrlException if the reference URL is found not to be
     *     valid.
     */
    public static function assertOtpUrlIsEquivalentTo(string $referenceUrl, string $actualUrl, string $message = ""): void
    {
        static::assertThat($actualUrl, new EquivalentOtpAuthUrl($referenceUrl), $message);
    }
}
