<?php

declare(strict_types=1);

namespace Equit\Totp\Tests;

use PHPUnit\Framework\TestCase as FrameworkTestCase;

class TestCase extends FrameworkTestCase
{
	/**
	 * Assert that a string contains only characters that are present in another string.
	 *
	 * @param string $allowableCharacters The string containing the allowable characters.
	 * @param string $actualString The string to test.
	 * @param string $message Optional message for use when the assertion fails.
	 */
	public static function assertStringContainsOnly(string $allowableCharacters, string $actualString, string $message = "")
	{
		static::assertThat($actualString, new Constraints\StringContainsOnly($allowableCharacters), $message);
	}
}