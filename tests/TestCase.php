<?php

declare(strict_types=1);

namespace Equit\Totp\Tests;

use PHPUnit\Framework\TestCase as FrameworkTestCase;

class TestCase extends FrameworkTestCase
{
	public static function assertStringContainsOnly(string $allowableCharacters, string $actualString, string $message = "")
	{
		static::assertThat($actualString, new Constraints\StringContainsOnly($allowableCharacters), $message);
	}
}