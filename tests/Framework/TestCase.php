<?php

declare(strict_types=1);

namespace Equit\Totp\Tests\Framework;

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
     * Assert that an OTP provisioning URL is equivalent to another.
     *
     * @param string $referenceUrl The URL that the tested URL should match.
     * @param string $actualUrl The URL to test.
     * @param string $message Optional message for use when the assertion fails.
     *
     * @throws \Equit\Totp\Tests\Framework\Exceptions\InvalidOtpUrlException if the reference URL is found not to be valid.
     */
    public static function assertOtpUrlIsEquivalentTo(string $referenceUrl, string $actualUrl, string $message = ""): void
    {
        static::assertThat($actualUrl, new EquivalentOtpAuthUrl($referenceUrl), $message);
    }
}