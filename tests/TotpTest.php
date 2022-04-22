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

namespace Equit\Totp\Tests;

use DateTime;
use DateTimeZone;
use Equit\Totp\Exceptions\InvalidHashAlgorithmException;
use Equit\Totp\Exceptions\InvalidIntervalException;
use Equit\Totp\Exceptions\InvalidSecretException;
use Equit\Totp\Exceptions\InvalidTimeException;
use Equit\Totp\Exceptions\InvalidVerificationWindowException;
use Equit\Totp\Renderers\EightDigits;
use Equit\Totp\Renderers\Integer;
use Equit\Totp\Renderers\Renderer;
use Equit\Totp\Renderers\SixDigits;
use Equit\Totp\Tests\Framework\TestCase;
use Equit\Totp\Totp;
use Equit\Totp\TotpSecret;
use Generator;
use InvalidArgumentException;
use ReflectionException;
use ReflectionMethod;
use ReflectionProperty;
use TypeError;

/**
 * Unit test for the Totp class.
 *
 * TODO tests for hmac methods
 */
class TotpTest extends TestCase
{
	/**
	 * Just a random secret to use to initialise a Totp instance for testing.
	 */
	protected const TestSecret = "hNDl963Ns6a1gp9d5aZ6";

	/**
	 * Helper to create a "vanilla" Totp test instance.
	 *
	 * @return \Equit\Totp\Totp
	 */
	protected static function createTotp(): Totp
	{
		return new Totp(self::TestSecret);
	}

	/**
	 * The full test data for the test cases outlined in RFC 6238 (page 15).
	 *
	 * Note that in most versions of the RFC available online the SHA256 and SHA512 passwords appear to be incorrect.
	 * The values in the data below have been externally verified using oathtool (https://www.nongnu.org/oath-toolkit/).
	 *
	 * @return array[]
	 * @noinspection PhpDocMissingThrowsInspection The DateTime constructor will not throw in these cases.
	 */
	protected static function rfcTestData(): array
	{
		/** @noinspection PhpUnhandledExceptionInspection The DateTime constructor will not throw in these cases. */
		return [
			"rfcTestData-sha1-59" => [
				"algorithm" => "sha1",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 59,
				"time" => new DateTime("1970-01-01 00:00:59", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x00\x00\x00\x01",
				"passwords" => [
					"8" => "94287082",
					"7" => "4287082",
					"6" => "287082",
				],
			],
			"rfcTestData-sha1-1111111109" => [
				"algorithm" => "sha1",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 1111111109,
				"time" => new DateTime("2005-03-18 01:58:29", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x02\x35\x23\xEC",
				"passwords" => [
					"8" => "07081804",
					"7" => "7081804",
					"6" => "081804",
				],
			],
			"rfcTestData-sha1-1111111111" => [
				"algorithm" => "sha1",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 1111111111,
				"time" => new DateTime("2005-03-18 01:58:31", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x02\x35\x23\xED",
				"passwords" => [
					"8" => "14050471",
					"7" => "4050471",
					"6" => "050471",
				],
			],
			"rfcTestData-sha1-1234567890" => [
				"algorithm" => "sha1",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 1234567890,
				"time" => new DateTime("2009-02-13 23:31:30", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x02\x73\xEF\x07",
				"passwords" => [
					"8" => "89005924",
					"7" => "9005924",
					"6" => "005924",
				],
			],
			"rfcTestData-sha1-2000000000" => [
				"algorithm" => "sha1",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 2000000000,
				"time" => new DateTime("2033-05-18 03:33:20", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x03\xF9\x40\xAA",
				"passwords" => [
					"8" => "69279037",
					"7" => "9279037",
					"6" => "279037",
				],
			],
			"rfcTestData-sha1-20000000000" => [
				"algorithm" => "sha1",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 20000000000,
				"time" => new DateTime("2603-10-11 11:33:20", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x27\xBC\x86\xAA",
				"passwords" => [
					"8" => "65353130",
					"7" => "5353130",
					"6" => "353130",
				],
			],
			"rfcTestData-sha256-59" => [
				"algorithm" => "sha256",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 59,
				"time" => new DateTime("1970-01-01 00:00:59", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x00\x00\x00\x01",
				"passwords" => [
					"8" => "32247374",
					"7" => "2247374",
					"6" => "247374",
				],
			],
			"rfcTestData-sha256-1111111109" => [
				"algorithm" => "sha256",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 1111111109,
				"time" => new DateTime("2005-03-18 01:58:29", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x02\x35\x23\xEC",
				"passwords" => [
					"8" => "34756375",
					"7" => "4756375",
					"6" => "756375",
				],
			],
			"rfcTestData-sha256-1111111111" => [
				"algorithm" => "sha256",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 1111111111,
				"time" => new DateTime("2005-03-18 01:58:31", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x02\x35\x23\xED",
				"passwords" => [
					"8" => "74584430",
					"7" => "4584430",
					"6" => "584430",
				],
			],
			"rfcTestData-sha256-1234567890" => [
				"algorithm" => "sha256",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 1234567890,
				"time" => new DateTime("2009-02-13 23:31:30", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x02\x73\xEF\x07",
				"passwords" => [
					"8" => "42829826",
					"7" => "2829826",
					"6" => "829826",
				],
			],
			"rfcTestData-sha256-2000000000" => [
				"algorithm" => "sha256",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 2000000000,
				"time" => new DateTime("2033-05-18 03:33:20", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x03\xF9\x40\xAA",
				"passwords" => [
					"8" => "78428693",
					"7" => "8428693",
					"6" => "428693",
				],
			],
			"rfcTestData-sha256-20000000000" => [
				"algorithm" => "sha256",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 20000000000,
				"time" => new DateTime("2603-10-11 11:33:20", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x27\xBC\x86\xAA",
				"passwords" => [
					"8" => "24142410",
					"7" => "4142410",
					"6" => "142410",
				],
			],
			"rfcTestData-sha512-59" => [
				"algorithm" => "sha512",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 59,
				"time" => new DateTime("1970-01-01 00:00:59", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x00\x00\x00\x01",
				"passwords" => [
					"8" => "69342147",
					"7" => "9342147",
					"6" => "342147",
				],
			],
			"rfcTestData-sha512-1111111109" => [
				"algorithm" => "sha512",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 1111111109,
				"time" => new DateTime("2005-03-18 01:58:29", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x02\x35\x23\xEC",
				"passwords" => [
					"8" => "63049338",
					"7" => "3049338",
					"6" => "049338",
				],
			],
			"rfcTestData-sha512-1111111111" => [
				"algorithm" => "sha512",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 1111111111,
				"time" => new DateTime("2005-03-18 01:58:31", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x02\x35\x23\xED",
				"passwords" => [
					"8" => "54380122",
					"7" => "4380122",
					"6" => "380122",
				],
			],
			"rfcTestData-sha512-1234567890" => [
				"algorithm" => "sha512",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 1234567890,
				"time" => new DateTime("2009-02-13 23:31:30", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x02\x73\xEF\x07",
				"passwords" => [
					"8" => "76671578",
					"7" => "6671578",
					"6" => "671578",
				],
			],
			"rfcTestData-sha512-2000000000" => [
				"algorithm" => "sha512",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 2000000000,
				"time" => new DateTime("2033-05-18 03:33:20", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x03\xF9\x40\xAA",
				"passwords" => [
					"8" => "56464532",
					"7" => "6464532",
					"6" => "464532",
				],
			],
			"rfcTestData-sha512-20000000000" => [
				"algorithm" => "sha512",
				"referenceTimestamp" => 0,
				"referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
				"interval" => 30,
				"timestamp" => 20000000000,
				"time" => new DateTime("2603-10-11 11:33:20", new DateTimeZone("UTC")),
				"secret" => [
					"raw" => "12345678901234567890",
					"base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
					"base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
				],
				"counterBytes" => "\x00\x00\x00\x00\x27\xBC\x86\xAA",
				"passwords" => [
					"8" => "69481994",
					"7" => "9481994",
					"6" => "481994",
				],
			],
		];
	}

	/**
	 * Helper to get a user-readable string representation of a binary string.
	 *
	 * The binary is converted to a sequence of hex values between 0x00 and 0xff inclusive.
	 *
	 * @param string $binaryString The binary string to convert.
	 *
	 * @return string The user-readable string.
	 */
	protected static function hexOf(string $binaryString): string
	{
		return "0x" . implode(" 0x", str_split(bin2hex($binaryString), 2));
	}

	/**
	 * Helper to get a number of years as an approximate number of seconds.
	 *
	 * Used when generating test data for the baseline date methods. Doesn't account for leap years or leap seconds.
	 *
	 * @param int $years The number of years.
	 *
	 * @return int The number of seconds.
	 */
	protected static function yearsInSeconds(int $years): int
	{
		return $years * 365 * 24 * 60 * 60;
	}

	/**
	 * Helper to get a number of days as a number of seconds.
	 *
	 * Used when generating test data for the baseline date methods.
	 *
	 * @param int $days The number of days.
	 *
	 * @return int The number of seconds.
	 */
	protected static function daysInSeconds(int $days): int
	{
		return $days * 24 * 60 * 60;
	}

	/**
	 * Helper to provide some test data for testConstructor.
	 *
	 * This method provides 100 datasets each with a random valid secret.
	 *
	 * @return Generator.
	 * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	protected function randomSecretTestDataForTestConstructor(): Generator
	{
		// 100 x random secrets
		for ($idx = 0; $idx < 100; ++$idx) {
			$secret = random_bytes(20);

			yield "randomValidSecret" . sprintf("%02d", $idx) => [
				[$secret,],
				[
					"secret" => $secret,
				],
			];
		}
	}

	/**
	 * Helper to provide some test data for testConstructor.
	 *
	 * This method provides test data focused on examining the limits of valid Totp secrets.
	 *
	 * @return array The test datasets.
	 * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	protected function specificSecretTestDataForTestConstructor(): array
	{
		return [
			"invalidShortSecret" => [
				["too short",],
				[],
				InvalidSecretException::class,
			],
			"invalidMarginallyShortSecret" => [
				[random_bytes(15),],
				[],
				InvalidSecretException::class,
			],
			"shortestValidSecret" => [
				[$secret = random_bytes(16),],
				[
					"secret" => $secret,
				],
			],
		];
	}

	/**
	 * Helper to provide some test data for testConstructor.
	 *
	 * This method yields 100 datasets with random valid intervals then 100 datasets with random invalid intervals.
	 *
	 * @return \Generator
	 * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	protected function randomIntervalTestDataForTestConstructor(): Generator
	{
		// 100 x random valid intervals between 1s and 1h
		for ($idx = 0; $idx < 100; ++$idx) {
			$interval = mt_rand(1, 3600);

			yield [
				[random_bytes(16), null, $interval,],
				[
					"interval" => $interval,
				],
			];
		}

		// 100 x random invalid intervals
		for ($idx = 0; $idx < 100; ++$idx) {
			yield [
				[random_bytes(16), null, mt_rand(PHP_INT_MIN, 0),],
				[],
				InvalidIntervalException::class,
			];
		}
	}

	/**
	 * Helper to provide some test data for testConstructor.
	 *
	 * This method provides test data focused on examining the limits of valid Totp intervals.
	 *
	 * @return array The test datasets.
	 * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	protected function specificIntervalTestDataForTestConstructor(): array
	{
		return [
			"shortestValidInterval" => [
				[random_bytes(16), null, 1,],
				[
					"interval" => 1,
				],
			],

			"closestInvalidInterval" => [
				[random_bytes(16), null, 0,],
				[],
				InvalidIntervalException::class,
			],
		];
	}

	/**
	 * Helper to provide some test data for testConstructor.
	 *
	 * Yields 100 datasets each with a valid secret and interval
	 *
	 * @return \Generator
	 * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	protected function randomSecretAndIntervalTestDataForTestConstructor(): Generator
	{
		// 100 x specified secret and interval
		for ($idx = 0; $idx < 100; ++$idx) {
			// random secret of between 16 and 20 bytes
			$secret = random_bytes(mt_rand(16, 20));
			// random interval up to 1 hour, on a 10-second boundary
			$interval = 10 * mt_rand(1, 360);

			yield "validSecretAndInterval" . sprintf("%02d", $idx) => [
				[$secret, null, $interval],
				[
					"secret" => $secret,
					"interval" => $interval,
				],
			];
		}
	}

	/**
	 * Helper to provide some test data for testConstructor.
	 *
	 * Yields 100 datasets each with a valid secret, interval and reference timestamp, then 100 datasets each with a
	 * valid secret, interval and reference DateTime.
	 *
	 * @return \Generator
	 * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	protected function randomSecretIntervalAndReferenceTimeTestDataForTestConstructor(): Generator
	{
		// 100 x specified secret, interval and reference time as timestamp
		for ($idx = 0; $idx < 100; ++$idx) {
			// random secret of between 16 and 20 bytes
			$secret = random_bytes(mt_rand(16, 20));
			// random interval up to 1 hour, on a 10-second boundary
			$interval           = 10 * mt_rand(1, 360);
			$referenceTimestamp = mt_rand(0, time());

			yield "validSecretIntervalAndTimestamp" . sprintf("%02d", $idx) => [
				[$secret, null, $interval, $referenceTimestamp],
				[
					"secret" => $secret,
					"interval" => $interval,
					"referenceTimestamp" => $referenceTimestamp,
				],
			];
		}

		// 100 x specified secret, interval and reference time as DateTime
		for ($idx = 0; $idx < 100; ++$idx) {
			// random secret of between 16 and 20 bytes
			$secret = random_bytes(mt_rand(16, 20));
			// random interval up to 1 hour, on a 10-second boundary
			$interval = 10 * mt_rand(1, 360);
			$referenceTime = new DateTime("@" . mt_rand(0, time()));

			yield "validSecretIntervalAndDateTime" . sprintf("%02d", $idx) => [
				[$secret, null, $interval, $referenceTime],
				[
					"secret" => $secret,
					"interval" => $interval,
					"referenceDateTime" => $referenceTime,
				],
			];
		}
	}

	/**
	 * Helper to provide some test data for testConstructor.
	 *
	 * Provides datasets to test specific scenarios for the reference time provided to the constructor.
	 *
	 * @return array
	 * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	protected function specificReferenceTimeTestDataForTestConstructor(): array
	{
		return [
			"nullReferenceTime" => [
				[random_bytes(20), null, 30, null,],
				[],
				TypeError::class,
			],
			"stringReferenceTimeNow" => [
				[random_bytes(20), null, 30, "now",],
				[],
				TypeError::class,
			],
			"stringReferenceTimeInt" => [
				[random_bytes(20), null, 30, "0",],
				[],
				TypeError::class,
			],
			"stringReferenceTimeDateString" => [
				[random_bytes(20), null, 30, "1970-01-01 00:00:00",],
				[],
				TypeError::class,
			],
			"objectReferenceTime" => [
				[random_bytes(20), null, 30, new class{},],
				[],
				TypeError::class,
			],
			"arrayReferenceTime" => [
				[random_bytes(20), null, 30, [0],],
				[],
				TypeError::class,
			],
		];
	}

	/**
	 * Data provider for the constructor test.
	 *
	 * @return \Generator
	 * @throws \Exception if random_bytes() is unable to generate cryptographically-secure random data.
	 */
	public function dataForTestConstructor(): Generator
	{
		yield from $this->randomSecretTestDataForTestConstructor();
		yield from $this->specificSecretTestDataForTestConstructor();
		yield from $this->randomIntervalTestDataForTestConstructor();
		yield from $this->specificIntervalTestDataForTestConstructor();
		yield from $this->specificReferenceTimeTestDataForTestConstructor();
		yield from $this->randomSecretAndIntervalTestDataForTestConstructor();
		yield from $this->randomSecretIntervalAndReferenceTimeTestDataForTestConstructor();
	}

	/**
	 * @dataProvider dataForTestConstructor
	 *
	 * @param array $args The arguments to pass to the constructor.
	 * @param array $expectations An array whose keys are methods on the Totp instance to call and whose values are
	 * either the expected return value, or an array containing the arguments for the method call and its expected
	 * return value.
	 * @param string|null $exceptionClass The exception that is expected from the constructor call, if any.
	 */
	public function testConstructor(array $args, array $expectations, ?string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = new Totp(...$args);

		foreach ($expectations as $method => $expected) {
			if (is_array($expected)) {
				$args = $expected["args"];
				$expected = $expected["expected"];
			} else {
				$args = [];
			}

			$actual = $totp->$method(...$args);
			$this->assertEquals($expected, $actual, "Return value from {$method}() not as expected.");
		}
	}

	/**
	 * Test data for testDestructor().
	 *
	 * @return \Generator
	 * @throws \Exception if random_bytes() is unable to generate cryptographically-secure random data.
	 */
	public function dataForTestDestructor(): Generator
	{
		yield "typicalAsciiSecret" => ["password-password"];
		yield "nullBytes16Secret" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"];
		yield "nullBytes20Secret" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"];

		// yield 100 random valid secrets
		for ($idx = 0; $idx < 100; ++$idx) {
			yield [random_bytes(mt_rand(16, 20)),];
		}
	}

	/**
	 * Test the Totp destructor.
	 *
	 * @dataProvider dataForTestDestructor
	 *
	 * @param string $secret The secret to use to initialise the Totp object.
	 *
	 * @noinspection PhpDocMissingThrowsInspection Totp constructor won't throw, secret is guaranteed by the data
	 * provider to be valid. ReflectionProperty won't throw because we know the property exists.
	 */
	public function testDestructor(string $secret): void
	{
		/** @noinspection PhpUnhandledExceptionInspection */
		$totp = new Totp($secret);

		/** @noinspection PhpUnhandledExceptionInspection */
		$secretProperty = new ReflectionProperty($totp, "m_secret");
		$secretProperty->setAccessible(true);
		$totp->__destruct();
		$this->assertNotEquals($secret, $secretProperty->getValue($totp), "The secret was not overwritten with random data.");
	}

	/**
	 * Test data for testSixDigitTotp().
	 *
	 * @return array The RFC test data mapped to the correct arrangement for the test arguments.
	 */
	public function dataForTestSixDigitTotp(): array
	{
		$testData = array_map(function(array $testData): array {
			return [
				$testData["secret"]["raw"],
				$testData["interval"],
				$testData["referenceTimestamp"],
				$testData["algorithm"],
				[
					"passwordAt" => [
						"args" => [$testData["timestamp"]],
						"value" => $testData["passwords"]["6"],
					],
					"counterBytesAt" => [
						"args" => [$testData["timestamp"]],
						"value" => $testData["counterBytes"],
					],
				],
			];
		}, self::rfcTestData());

		// invalid secrets
		$testData[] = ["", 30, 0, Totp::Sha1Algorithm, [], InvalidSecretException::class,];
		$testData[] = ["password-passwo", 30, 0, Totp::Sha1Algorithm, [], InvalidSecretException::class,];
		$testData[] = [random_bytes(1), 30, 0, Totp::Sha1Algorithm, [], InvalidSecretException::class,];
		$testData[] = [random_bytes(15), 30, 0, Totp::Sha1Algorithm, [], InvalidSecretException::class,];

		// invalid intervals
		$testData[] = [random_bytes(20), 0, 0, Totp::Sha1Algorithm, [], InvalidIntervalException::class,];
		$testData[] = [random_bytes(20), -1, 0, Totp::Sha1Algorithm, [], InvalidIntervalException::class,];
		$testData[] = [random_bytes(20), -50, 0, Totp::Sha1Algorithm, [], InvalidIntervalException::class,];
		$testData[] = [random_bytes(20), PHP_INT_MIN, 0, Totp::Sha1Algorithm, [], InvalidIntervalException::class,];

		// invalid algorithms
		$testData[] = [random_bytes(20), 30, 0, "", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "foobar", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "md5", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "SHA1", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "Sha1", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "sHa1", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "sHA1", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "shA1", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "SHa1", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "SHA256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "Sha256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "sHa256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "shA256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "SHa256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "sHA256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "ShA256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "SHA512", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "Sha512", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "sHa512", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "shA512", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "SHa512", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "sHA512", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "ShA512", [], InvalidHashAlgorithmException::class,];

		// 100 random valid combinations
		for ($idx = 0; $idx < 100; ++$idx) {
			$testData[] = [
				random_bytes(64),
				10 * mt_rand(1, 360),
				mt_rand(0, time() - (20 * 365 * 24 * 60 * 60)),
				match (mt_rand(0, 2)) {
					0 => Totp::Sha1Algorithm,
					1 => Totp::Sha256Algorithm,
					2 => Totp::Sha512Algorithm,
				},
			];
		}

		return $testData;	}

	/**
	 * @dataProvider dataForTestSixDigitTotp
	 *
	 * @param string $secret The secret for the Totp.
	 * @param int $interval The interval for the Totp.
	 * @param int|\DateTime $referenceTime The reference time for the Totp.
	 * @param string $hashAlgorithm The hash algorithm for the Totp.
	 * @param array $expectations An array of expected return values from method calls. Each expectation is keyed with
	 * the method name, and has a tuple of "args" and "value" as its value. The args element is an array of arguments to
	 * provide in the method call; the value element is the expected return value.
	 */
	public function testSixDigitTotp(string $secret, int $interval = Totp::DefaultInterval, int | DateTime $referenceTime = Totp::DefaultReferenceTime, string $hashAlgorithm = Totp::DefaultAlgorithm, array $expectations = [], string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = Totp::sixDigitTotp(secret: $secret, interval: $interval, referenceTime: $referenceTime, hashAlgorithm: $hashAlgorithm);
		$this->assertEquals($secret, $totp->secret(), "Secret in Totp object does not match expected secret.");
		$this->assertEquals($interval, $totp->interval(), "Interval in Totp object does not match expected interval.");
		$this->assertEquals($hashAlgorithm, $totp->hashAlgorithm(), "Hash algorithm in Totp object does not match expected algorithm.");

		if ($referenceTime instanceof DateTime) {
			$referenceTimestamp = $referenceTime->getTimestamp();
		} else {
			$referenceTimestamp = $referenceTime;
			/** @noinspection PhpUnhandledExceptionInspection */
			$referenceTime = new DateTime("@{$referenceTime}", new DateTimeZone("UTC"));
		}

		$this->assertInstanceOf(SixDigits::class, $totp->renderer(), "The Totp does not have the expected renderer type.");
		$this->assertEquals(6, $totp->renderer()->digits(), "The Totp renderer does not use the expected number of digits.");
		$this->assertEquals($referenceTime, $totp->referenceDateTime(), "Reference DateTime in Totp object does not match expected DateTime.");
		$this->assertEquals($referenceTimestamp, $totp->referenceTimestamp(), "Reference timestamp in Totp object does not match expected timestamp.");

		$password = $totp->currentPassword();
		$this->assertEquals(6, strlen($password), "Password from Totp object is not 6 digits.");
		$this->assertStringContainsOnly("0123456789", $password, "Password contains some invalid content.");

		foreach ($expectations as $methodName => $details) {
			try {
				$method = new ReflectionMethod($totp, $methodName);
				$method->setAccessible(true);
				$method = $method->getClosure($totp);
				$expected = $details["value"];
				$actual = $method(...$details["args"]);
				$this->assertEquals($expected, $actual, "Expected return value from {$methodName} not found.");
			}
			catch (ReflectionException $e) {
				$this->fail("Invalid method name in expectations given to testSixDigitTotp().");
			}
		}
	}

	/**
	 * Test data for testEightDigitTotp().
	 *
	 * @return array The RFC test data mapped to the correct arrangement for the test arguments.
	 */
	public function dataForTestEightDigitTotp(): array
	{
		$testData = array_map(function(array $testData): array {
			return [
				$testData["secret"]["raw"],
				$testData["interval"],
				$testData["referenceTimestamp"],
				$testData["algorithm"],
				[
					"passwordAt" => [
						"args" => [$testData["timestamp"]],
						"value" => $testData["passwords"]["8"],
					],
					"counterBytesAt" => [
						"args" => [$testData["timestamp"]],
						"value" => $testData["counterBytes"],
					],
				],
			];
		}, self::rfcTestData());

		// invalid secrets
		$testData[] = ["", 30, 0, Totp::Sha1Algorithm, [], InvalidSecretException::class,];
		$testData[] = ["password-passwo", 30, 0, Totp::Sha1Algorithm, [], InvalidSecretException::class,];
		$testData[] = [random_bytes(1), 30, 0, Totp::Sha1Algorithm, [], InvalidSecretException::class,];
		$testData[] = [random_bytes(15), 30, 0, Totp::Sha1Algorithm, [], InvalidSecretException::class,];

		// invalid intervals
		$testData[] = [random_bytes(20), 0, 0, Totp::Sha1Algorithm, [], InvalidIntervalException::class,];
		$testData[] = [random_bytes(20), -1, 0, Totp::Sha1Algorithm, [], InvalidIntervalException::class,];
		$testData[] = [random_bytes(20), -50, 0, Totp::Sha1Algorithm, [], InvalidIntervalException::class,];
		$testData[] = [random_bytes(20), PHP_INT_MIN, 0, Totp::Sha1Algorithm, [], InvalidIntervalException::class,];

		// invalid algorithms
		$testData[] = [random_bytes(20), 30, 0, "", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "foobar", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "md5", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "SHA1", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "Sha1", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "sHa1", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "sHA1", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "shA1", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "SHa1", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "SHA256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "Sha256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "sHa256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "shA256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "SHa256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "sHA256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "ShA256", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "SHA512", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "Sha512", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "sHa512", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "shA512", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "SHa512", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "sHA512", [], InvalidHashAlgorithmException::class,];
		$testData[] = [random_bytes(20), 30, 0, "ShA512", [], InvalidHashAlgorithmException::class,];

		// 100 random valid combinations
		for ($idx = 0; $idx < 100; ++$idx) {
			$testData[] = [
				random_bytes(64),
				10 * mt_rand(1, 360),
				mt_rand(0, time() - (20 * 365 * 24 * 60 * 60)),
				match (mt_rand(0, 2)) {
					0 => Totp::Sha1Algorithm,
					1 => Totp::Sha256Algorithm,
					2 => Totp::Sha512Algorithm,
				},
			];
		}

		return $testData;
	}

	/**
	 * @dataProvider dataForTestEightDigitTotp
	 *
	 * @param string $secret The secret for the Totp.
	 * @param int $interval The interval for the Totp.
	 * @param int|\DateTime $referenceTime The reference time for the Totp.
	 * @param string $hashAlgorithm The hash algorithm for the Totp.
	 * @param array $expectations An array of expected return values from method calls. Each expectation is keyed with
	 * the method name, and has a tuple of "args" and "value" as its value. The args element is an array of arguments to
	 * provide in the method call; the value element is the expected return value.
	 */
	public function testEightDigitTotp(string $secret, int $interval = Totp::DefaultInterval, int | DateTime $referenceTime = Totp::DefaultReferenceTime, string $hashAlgorithm = Totp::DefaultAlgorithm, array $expectations = [], string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = Totp::eightDigitTotp(secret: $secret, interval: $interval, referenceTime: $referenceTime, hashAlgorithm: $hashAlgorithm);
		$this->assertEquals($secret, $totp->secret(), "Secret in Totp object does not match expected secret.");
		$this->assertEquals($interval, $totp->interval(), "Interval in Totp object does not match expected interval.");
		$this->assertEquals($hashAlgorithm, $totp->hashAlgorithm(), "Hash algorithm in Totp object does not match expected algorithm.");

		if ($referenceTime instanceof DateTime) {
			$referenceTimestamp = $referenceTime->getTimestamp();
		} else {
			$referenceTimestamp = $referenceTime;
			/** @noinspection PhpUnhandledExceptionInspection */
			$referenceTime = new DateTime("@{$referenceTime}", new DateTimeZone("UTC"));
		}

		$this->assertInstanceOf(EightDigits::class, $totp->renderer(), "The Totp does not have the expected renderer type.");
		$this->assertEquals(8, $totp->renderer()->digits(), "The Totp renderer does not use the expected number of digits.");
		$this->assertEquals($referenceTime, $totp->referenceDateTime(), "Reference DateTime in Totp object does not match expected DateTime.");
		$this->assertEquals($referenceTimestamp, $totp->referenceTimestamp(), "Reference timestamp in Totp object does not match expected timestamp.");

		$password = $totp->currentPassword();
		$this->assertEquals(8, strlen($password), "Password from Totp object is not 6 digits.");
		$this->assertStringContainsOnly("0123456789", $password, "Password contains some invalid content.");

		foreach ($expectations as $methodName => $details) {
			try {
				$method = new ReflectionMethod($totp, $methodName);
				$method->setAccessible(true);
				$method = $method->getClosure($totp);
				$expected = $details["value"];
				$actual = $method(...$details["args"]);
				$this->assertEquals($expected, $actual, "Expected return value from {$methodName} not found.");
			}
			catch (ReflectionException $e) {
				$this->fail("Invalid method name in expectations given to testSixDigitTotp().");
			}
		}
	}

	/**
	 * Data provider for testSetBase32Secret().
	 *
	 * @return array The test data.
	 */
	public function dataForTestSetBase32Secret(): array
	{
		return [
			"typicalPlainText" => ["OBQXG43XN5ZGILLQMFZXG53POJSA====", "password-password",],
			"typicalBinary" => ["CVYNPLS6RDRTYW2JY6U46JPTD7N2Z645", "\x15\x70\xd7\xae\x5e\x88\xe3\x3c\x5b\x49\xc7\xa9\xcf\x25\xf3\x1f\xdb\xac\xfb\x9d",],
			"invalidEmpty" => ["", null, InvalidSecretException::class,],
			"invalidTooShort" => ["OBQXG43XN5ZGI===", null, InvalidSecretException::class,],
			"invalidWrongTypeNull" => [null, null, TypeError::class,],
			"invalidWrongTypeStringable" => [self::createStringable("OBQXG43XN5ZGILLQMFZXG53POJSA===="), null, TypeError::class,],
		];
	}

	/**
	 * @dataProvider dataForTestSetBase32Secret
	 *
	 * @param mixed $base32 The base32-encoded secret to set.
	 * @param string|null $raw The raw secret expected.
	 * @param string|null $exceptionClass The class name of the exception expected to be thrown, if any.
	 */
	public function testSetBase32Secret(mixed $base32, string|null $raw, ?string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = self::createTotp();
		$totp->setSecret(TotpSecret::fromBase32($base32));
		$this->assertSame($base32, $totp->base32Secret());

		if (isset($raw)) {
			$this->assertSame($raw, $totp->secret());
		}
	}

	/**
	 * Data provider for testSetBase32Secret().
	 *
	 * @return array The test data.
	 */
	public function dataForTestSetBase64Secret(): array
	{
		return [
			"typicalPlainText" => ["cGFzc3dvcmQtcGFzc3dvcmQ=", "password-password",],
			"typicalBinary" => ["FXDXrl6I4zxbScepzyXzH9us+50=", "\x15\x70\xd7\xae\x5e\x88\xe3\x3c\x5b\x49\xc7\xa9\xcf\x25\xf3\x1f\xdb\xac\xfb\x9d",],
			"invalidEmpty" => ["", null, InvalidSecretException::class,],
			"invalidTooShort" => ["cGFzc3dvcmQ=", null, InvalidSecretException::class,],
			"invalidWrongTypeNull" => [null, null, TypeError::class,],
			"invalidWrongTypeStringable" => [self::createStringable("cGFzc3dvcmQtcGFzc3dvcmQ="), null, TypeError::class,],
		];
	}

	/**
	 * @dataProvider dataForTestSetBase64Secret
	 *
	 * @param mixed $base64 The base64-encoded secret to set.
	 * @param string|null $raw The raw secret expected.
	 * @param string|null $exceptionClass The class name of the exception expected to be thrown, if any.
	 */
	public function testSetBase64Secret(mixed $base64, string|null $raw, ?string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = self::createTotp();
		$totp->setSecret(TotpSecret::fromBase64($base64));
		$this->assertSame($base64, $totp->base64Secret());

		if (isset($raw)) {
			$this->assertSame($raw, $totp->secret());
		}
	}

	/**
	 * Test data for testBase32Secret().
	 *
	 * @return array The test data.
	 */
	public function dataForTestBase32Secret(): array
	{
		return [
			"typicalPlainText" => ["password-password", "OBQXG43XN5ZGILLQMFZXG53POJSA====",],
			"typicalBinary" => ["\x15\x70\xd7\xae\x5e\x88\xe3\x3c\x5b\x49\xc7\xa9\xcf\x25\xf3\x1f\xdb\xac\xfb\x9d", "CVYNPLS6RDRTYW2JY6U46JPTD7N2Z645",],
			"extremeBinaryZeroes" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",],
			"extremeBinaryOnes" => ["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", "77777777777777777777777777777777",],
			"extremeLongBinary" => [
				"\x4d\x51\xa7\x96\x6f\x8f\xf6\xcb\x19\xb5\x61\x2f\xe8\x77\xa8\x78\x26\xb7\xcc\x92\x09\xa0\xe0\x6c\x1a\x8e\x99\x30\x61\x1c\xfc\x18\xd4\x9e\xae\x78\x0c\xc0\x5e\x73\x0c\xd5\x55\x25\x5b\x39\x2a\xd9\x64\x95\xf5\x36\xa5\xe8\x64\x06\xf0\x73\x58\xfc\xfa\x27\xd5\x15\xe5\xa9\x62\xce\x0c\x04\x1e\xa6\xbd\xbc\xde\x61\xb5\x95\xca\x42\x94\xb5\x1b\x1e\xe3\x8c\xde\x14\xb2\x8a\x00\x10\xd4\x96\xa8\xd0\x33\xf6\x7e\x85\xc4\x3e\x94\x5c\xe2\xe5\x6a\x24\x5a\x5e\x27\x2c\xd0\xed\xb0\x33\xe4\x4e\x1a\xcc",
				"JVI2PFTPR73MWGNVMEX6Q55IPATLPTESBGQOA3A2R2MTAYI47QMNJHVOPAGMAXTTBTKVKJK3HEVNSZEV6U3KL2DEA3YHGWH47IT5KFPFVFRM4DAED2TL3PG6MG2ZLSSCSS2RWHXDRTPBJMUKAAINJFVI2AZ7M7UFYQ7JIXHC4VVCIWS6E4WNB3NQGPSE4GWM",
			],
		];
	}

	/**
	 * @dataProvider dataForTestBase32Secret
	 *
	 * @param string $raw The raw secret.
	 * @param string $base32 The expected Base32 for the raw secret.
	 */
	public function testBase32Secret(string $raw, string $base32): void
	{
		$totp = self::createTotp();
		$totp->setSecret($raw);
		$this->assertSame($base32, $totp->base32Secret(), "The base32 of the raw secret '" . self::hexOf($raw) . "' did not match the expected string.");
	}

	/**
	 * Test data for testBase64Secret().
	 *
	 * @return array The test data.
	 */
	public function dataForTestBase64Secret(): array
	{
		return [
			"typicalPlainText" => ["password-password", "cGFzc3dvcmQtcGFzc3dvcmQ=",],
			"typicalBinary" => ["\x15\x70\xd7\xae\x5e\x88\xe3\x3c\x5b\x49\xc7\xa9\xcf\x25\xf3\x1f\xdb\xac\xfb\x9d", "FXDXrl6I4zxbScepzyXzH9us+50=",],
			"extremeBinaryZeroes" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=",],
			"extremeBinaryOnes" => ["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", "//////////////////////////8=",],
			"extremeLongBinary" => [
				"\x4d\x51\xa7\x96\x6f\x8f\xf6\xcb\x19\xb5\x61\x2f\xe8\x77\xa8\x78\x26\xb7\xcc\x92\x09\xa0\xe0\x6c\x1a\x8e\x99\x30\x61\x1c\xfc\x18\xd4\x9e\xae\x78\x0c\xc0\x5e\x73\x0c\xd5\x55\x25\x5b\x39\x2a\xd9\x64\x95\xf5\x36\xa5\xe8\x64\x06\xf0\x73\x58\xfc\xfa\x27\xd5\x15\xe5\xa9\x62\xce\x0c\x04\x1e\xa6\xbd\xbc\xde\x61\xb5\x95\xca\x42\x94\xb5\x1b\x1e\xe3\x8c\xde\x14\xb2\x8a\x00\x10\xd4\x96\xa8\xd0\x33\xf6\x7e\x85\xc4\x3e\x94\x5c\xe2\xe5\x6a\x24\x5a\x5e\x27\x2c\xd0\xed\xb0\x33\xe4\x4e\x1a\xcc",
				"TVGnlm+P9ssZtWEv6HeoeCa3zJIJoOBsGo6ZMGEc/BjUnq54DMBecwzVVSVbOSrZZJX1NqXoZAbwc1j8+ifVFeWpYs4MBB6mvbzeYbWVykKUtRse44zeFLKKABDUlqjQM/Z+hcQ+lFzi5WokWl4nLNDtsDPkThrM",
			],
		];
	}

	/**
	 * @dataProvider dataForTestBase64Secret
	 *
	 * @param string $raw The raw secret.
	 * @param string $base64 The expected Base64 for the raw secret.
	 */
	public function testBase64Secret(string $raw, string $base64): void
	{
		$totp = self::createTotp();
		$totp->setSecret($raw);
		$this->assertSame($base64, $totp->base64Secret(), "The base64 of the raw secret '" . self::hexOf($raw) . "' did not match the expected string.");
	}

	/**
	 * Data provider for testSetHashAlgorithm().
	 *
	 * @return array The test data.
	 */
	public function dataForTestSetHashAlgorithm(): array
	{
		return [
			"typicalSha1" => [Totp::Sha1Algorithm,],
			"typicalSha256" => [Totp::Sha256Algorithm,],
			"typicalSha512" => [Totp::Sha512Algorithm,],
			"invalidStringMD5Upper" => ["MD5", InvalidHashAlgorithmException::class,],
			"invalidStringMD5Lower" => ["md5", InvalidHashAlgorithmException::class,],
			"invalidEmptyString" => ["", InvalidHashAlgorithmException::class,],
			"invalidNonsenseString" => ["foobarfizzbuzz", InvalidHashAlgorithmException::class,],
			"invalidEmpty" => ["", InvalidHashAlgorithmException::class,],
			"invalidSHA1-1" => ["SHA1", InvalidHashAlgorithmException::class,],
			"invalidSHA1-2" => ["Sha1", InvalidHashAlgorithmException::class,],
			"invalidSHA1-3" => ["sHa1", InvalidHashAlgorithmException::class,],
			"invalidSHA1-4" => ["shA1", InvalidHashAlgorithmException::class,],
			"invalidSHA1-5" => ["ShA1", InvalidHashAlgorithmException::class,],
			"invalidSHA1-6" => ["sHA1", InvalidHashAlgorithmException::class,],
			"invalidSHA1-7" => ["ShA1", InvalidHashAlgorithmException::class,],
			"invalidSHA256-1" => ["SHA256", InvalidHashAlgorithmException::class,],
			"invalidSHA256-2" => ["Sha256", InvalidHashAlgorithmException::class,],
			"invalidSHA256-3" => ["sHa256", InvalidHashAlgorithmException::class,],
			"invalidSHA256-4" => ["shA256", InvalidHashAlgorithmException::class,],
			"invalidSHA256-5" => ["ShA256", InvalidHashAlgorithmException::class,],
			"invalidSHA256-6" => ["sHA256", InvalidHashAlgorithmException::class,],
			"invalidSHA256-7" => ["ShA256", InvalidHashAlgorithmException::class,],
			"invalidSHA512-1" => ["SHA512", InvalidHashAlgorithmException::class,],
			"invalidSHA512-2" => ["Sha512", InvalidHashAlgorithmException::class,],
			"invalidSHA512-3" => ["sHa512", InvalidHashAlgorithmException::class,],
			"invalidSHA512-4" => ["shA512", InvalidHashAlgorithmException::class,],
			"invalidSHA512-5" => ["ShA512", InvalidHashAlgorithmException::class,],
			"invalidSHA512-6" => ["sHA512", InvalidHashAlgorithmException::class,],
			"invalidSHA512-7" => ["ShA512", InvalidHashAlgorithmException::class,],
			"invalidNull" => [null, TypeError::class,],
			"invalidInt0" => [0, TypeError::class,],
			"invalidInt1" => [1, TypeError::class,],
			"invalidInt256" => [256, TypeError::class,],
			"invalidInt512" => [512, TypeError::class,],
			"invalidFloat0.0" => [0.0, TypeError::class,],
			"invalidFloat1.0" => [1.0, TypeError::class,],
			"invalidFloat256.0" => [256.0, TypeError::class,],
			"invalidFloat512.0" => [512.0, TypeError::class,],
			"invalidStringableSha1" => [self::createStringable("Sha1"), TypeError::class,],
			"invalidStringableSha256" => [self::createStringable("Sha256"), TypeError::class,],
			"invalidStringableSha512" => [self::createStringable("Sha512"), TypeError::class,],
			"invalidArray" => [[Totp::Sha1Algorithm,], TypeError::class,],
        ];
	}

	/**
	 * Test the setHashAlgorithm() method.
	 *
	 * @dataProvider dataForTestSetHashAlgorithm
	 *
	 * @param mixed $algorithm The algorithm to set.
	 * @param string|null $exceptionClass The type of exception expected to be thrown, if any.
	 */
	public function testSetHashAlgorithm(mixed $algorithm, ?string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = self::createTotp();
		$totp->setHashAlgorithm($algorithm);
		$this->assertSame($algorithm, $totp->hashAlgorithm(), "The has algorithm was expected to be {$algorithm} but {$totp->hashAlgorithm()} was reported.");
	}

	/**
	 * Data provider for testHashAlgorithm().
	 *
	 * @return array The test data.
	 */
	public function dataForTestHashAlgorithm(): array
	{
		return [
			"typicalSha1" => [Totp::Sha1Algorithm,],
			"typicalSha256" => [Totp::Sha256Algorithm,],
			"typicalSha512" => [Totp::Sha512Algorithm,],
		];
	}

	/**
	 * Test the hashAlgorithm() method.
	 *
	 * Note that each run of this test asserts that the default algorithm is SHA1.
	 *
	 * @dataProvider dataForTestHashAlgorithm
	 *
	 * @param string $algorithm The algorithm to test with.
	 */
	public function testHashAlgorithm(string $algorithm): void
	{
		$totp = self::createTotp();
		$this->assertSame(Totp::Sha1Algorithm, $totp->hashAlgorithm(), "The default hash algorithm was expected to be " . Totp::Sha1Algorithm . " but {$totp->hashAlgorithm()} was reported.");
		$totp->setHashAlgorithm($algorithm);
		$this->assertSame($algorithm, $totp->hashAlgorithm(), "The hash algorithm was expected to be {$algorithm} but {$totp->hashAlgorithm()} was reported.");
	}

	/**
	 * Data provider for testSetReferenceTime()
	 *
	 * @return array The test data.
	 */
	public function dataForTestSetReferenceTime(): array
	{
		return [
			"typicalEpochAsInt" => [0,],
			"typicalEpochAsDateTime" => [new DateTime("@0"),],
			"typicalEpochAsDateTimeUtc+4" => [new DateTime("@0", new DateTimeZone("UTC")),],
			"typicalNowAsTimestamp" => [time(),],
			"typical10YearsAgoAsTimestamp" => [time() - self::yearsInSeconds(10),],
			"typical10DaysAgoAsTimestamp" => [time() - self::daysInSeconds(10),],
			"typical10YearsAfterEpoch" => [self::yearsInSeconds(10),],
			"typical20YearsAfterEpoch" => [self::yearsInSeconds(20),],
			"typical30YearsAfterEpoch" => [self::yearsInSeconds(30),],
			"typical10SecondsAfterEpoch" => [self::daysInSeconds(10),],
			"typical20SecondsAfterEpoch" => [self::daysInSeconds(20),],
			"typical30SecondsAfterEpoch" => [self::daysInSeconds(30),],
			"typical40SecondsAfterEpoch" => [self::daysInSeconds(40),],
			"typical50SecondsAfterEpoch" => [self::daysInSeconds(50),],
			"typical60SecondsAfterEpoch" => [self::daysInSeconds(60),],
			"typical70SecondsAfterEpoch" => [self::daysInSeconds(70),],
			"typical80SecondsAfterEpoch" => [self::daysInSeconds(80),],
			"typical90SecondsAfterEpoch" => [self::daysInSeconds(90),],
			"typical100SecondsAfterEpoch" => [self::daysInSeconds(100),],

			// NOTE we don't use "now" because it creates a time with fractional seconds which aren't preserved in the
			// conversion to a unix timestamp, and which therefore causes a failed test assertion
			"typicalNowAsDateTime" => [new DateTime("@" . time()),],
			"typicalDateTimeUtc" => [new DateTime("23-04-1974", new DateTimeZone("UTC")),],
			"typicalDateTimeUtc-4" => [new DateTime("28-01-1978", new DateTimeZone("-0400")),],
			"typicalDateTimeUtc+4" => [new DateTime("19-07-2000", new DateTimeZone("+0400")),],
			"typicalDateTimeUtc-6" => [new DateTime("04-03-1984", new DateTimeZone("-0600")),],
			"typicalDateTimeUtc+6" => [new DateTime("31-12-1999", new DateTimeZone("+0600")),],
			"invalidNull" => [null, TypeError::class],
			"invalidEmptyString" => ["", TypeError::class],
			"invalidDateTimeParseableString" => ["now", TypeError::class],
		];
	}

	/**
	 * @dataProvider dataForTestSetReferenceTime
	 *
	 * @param int|\DateTime $time
	 * @param string|null $exceptionClass
	 */
	public function testSetReferenceTime(mixed $time, ?string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = self::createTotp();
		$totp->setReferenceTime($time);

		if (is_int($time)) {
			$this->assertSame($time, $totp->referenceTimestamp());
		} else if ($time instanceof DateTime) {
			$this->assertInstanceOf(DateTime::class, $totp->referenceDateTime(), "referenceDateTime() failed to return a DateTime object with input DateTime '" . $time->format("Y-m-d H:i:s") . "'");
			$this->assertEquals($time, $totp->referenceDateTime());
		}
	}

	/**
	 * Date provider for dataForTestReferenceTimestamp().
	 *
	 * @return array The test data.
	 */
	public function dataForTestReferenceTimestamp(): array
	{
		return [
			"epoch" => [0,],
			"epochAsDateTime" => [new DateTime("@0"), 0,],
			"epochAsDateTimeUtc+4" => [new DateTime("@0", new DateTimeZone("UTC")), 0,],
			"nowAsTimestamp" => [time(),],
			"10YearsAgoAsTimestamp" => [time() - self::yearsInSeconds(10),],
			"10DaysAgoAsTimestamp" => [time() - self::daysInSeconds(10),],
			"10YearsAfterEpoch" => [self::yearsInSeconds(10),],
			"20YearsAfterEpoch" => [self::yearsInSeconds(20),],
			"30YearsAfterEpoch" => [self::yearsInSeconds(30),],
			"10SecondsAfterEpoch" => [self::daysInSeconds(10),],
			"20SecondsAfterEpoch" => [self::daysInSeconds(20),],
			"30SecondsAfterEpoch" => [self::daysInSeconds(30),],
			"40SecondsAfterEpoch" => [self::daysInSeconds(40),],
			"50SecondsAfterEpoch" => [self::daysInSeconds(50),],
			"60SecondsAfterEpoch" => [self::daysInSeconds(60),],
			"70SecondsAfterEpoch" => [self::daysInSeconds(70),],
			"80SecondsAfterEpoch" => [self::daysInSeconds(80),],
			"90SecondsAfterEpoch" => [self::daysInSeconds(90),],
			"100SecondsAfterEpoch" => [self::daysInSeconds(100),],
			"nowAsDateTime" => [new DateTime("@" . time()), time(),],
			"dateTimeUtc" => [new DateTime("23-04-1974", new DateTimeZone("UTC")), 135907200,],
			"dateTimeUtc-4" => [new DateTime("28-01-1978", new DateTimeZone("-0400")), 254808000,],
			"dateTimeUtc+4" => [new DateTime("19-07-2000", new DateTimeZone("+0400")), 963950400,],
			"dateTimeUtc-6" => [new DateTime("04-03-1984", new DateTimeZone("-0600")), 447228000,],
			"dateTimeUtc+6" => [new DateTime("31-12-1999", new DateTimeZone("+0600")), 946576800,],
		];
	}

	/**
	 * @dataProvider dataForTestReferenceTimestamp
	 *
	 * @param int|\DateTime $time The time to set in the Totp as the reference.
	 * @param int|null $expectedTimestamp What referenceTimestamp() is expected to return.
	 */
	public function testReferenceTimestamp(int | DateTime $time, ?int $expectedTimestamp = null): void
	{
		if (!isset($expectedTimestamp)) {
			if (!is_int($time)) {
				throw new InvalidArgumentException("Test data for testReferenceTimestamp expects \$time to be an int if \$expectedTimestamp is not specified.");
			}

			$expectedTimestamp = $time;
		}

		$totp = self::createTotp();
		$totp->setReferenceTime($time);
		$this->assertSame($expectedTimestamp, $totp->referenceTimestamp());
	}

	/**
	 * Date provider for testReferenceDateTime().
	 *
	 * @return array The test data.
	 */
	public function dataForTestReferenceDateTime(): array
	{
		$now = time();
		
		return [
			"epoch" => [0, new DateTime("@0")],
			"epochAsDateTime" => [new DateTime("@0"),],
			"epochAsDateTimeUtc+4" => [new DateTime("@0", new DateTimeZone("UTC")),],
			"nowAsTimestamp" => [$now, new DateTime("@{$now}")],
			"10YearsAgoAsTimestamp" => [$now - self::yearsInSeconds(10), new DateTime("@" . ($now - self::yearsInSeconds(10))),],
			"10DaysAgoAsTimestamp" => [$now - self::daysInSeconds(10), new DateTime("@" . ($now - self::daysInSeconds(10))),],
			"10YearsAfterEpoch" => [self::yearsInSeconds(10), new DateTime("@" . self::yearsInSeconds(10)),],
			"20YearsAfterEpoch" => [self::yearsInSeconds(20), new DateTime("@" . self::yearsInSeconds(20)),],
			"30YearsAfterEpoch" => [self::yearsInSeconds(30), new DateTime("@" . self::yearsInSeconds(30)),],
			"10SecondsAfterEpoch" => [self::daysInSeconds(10), new DateTime("@" . self::daysInSeconds(10)),],
			"20SecondsAfterEpoch" => [self::daysInSeconds(20), new DateTime("@" . self::daysInSeconds(20)),],
			"30SecondsAfterEpoch" => [self::daysInSeconds(30), new DateTime("@" . self::daysInSeconds(30)),],
			"40SecondsAfterEpoch" => [self::daysInSeconds(40), new DateTime("@" . self::daysInSeconds(40)),],
			"50SecondsAfterEpoch" => [self::daysInSeconds(50), new DateTime("@" . self::daysInSeconds(50)),],
			"60SecondsAfterEpoch" => [self::daysInSeconds(60), new DateTime("@" . self::daysInSeconds(60)),],
			"70SecondsAfterEpoch" => [self::daysInSeconds(70), new DateTime("@" . self::daysInSeconds(70)),],
			"80SecondsAfterEpoch" => [self::daysInSeconds(80), new DateTime("@" . self::daysInSeconds(80)),],
			"90SecondsAfterEpoch" => [self::daysInSeconds(90), new DateTime("@" . self::daysInSeconds(90)),],
			"100SecondsAfterEpoch" => [self::daysInSeconds(100), new DateTime("@" . self::daysInSeconds(100)),],
			"nowAsDateTime" => [new DateTime("@{$now}"),],
			"dateTimeUtc" => [new DateTime("23-04-1974", new DateTimeZone("UTC")),],
			"dateTimeUtc-4" => [new DateTime("28-01-1978", new DateTimeZone("-0400")),],
			"dateTimeUtc+4" => [new DateTime("19-07-2000", new DateTimeZone("+0400")),],
			"dateTimeUtc-6" => [new DateTime("04-03-1984", new DateTimeZone("-0600")),],
			"dateTimeUtc+6" => [new DateTime("31-12-1999", new DateTimeZone("+0600")),],
		];
	}

	/**
	 * @dataProvider dataForTestReferenceDateTime
	 *
	 * @param int|\DateTime $time The time to set in the Totp as the reference.
	 * @param DateTime|null $expectedDateTime What referenceDateTime() is expected to return.
	 */
	public function testReferenceDateTime(int | DateTime $time, ?DateTime $expectedDateTime = null): void
	{
		if (!isset($expectedDateTime)) {
			if (!($time instanceof DateTime)) {
				throw new InvalidArgumentException("Test data for testReferenceTimestamp expects \$time to be a DateTime instance if \$expectedDateTime is not specified.");
			}

			$expectedDateTime = $time;
		}

		$totp = self::createTotp();
		$totp->setReferenceTime($time);
		$actual = $totp->referenceDateTime();
		$this->assertInstanceOf(DateTime::class, $actual);
		$this->assertEquals($expectedDateTime, $actual);
	}

	/**
	 * Data provider for testSetInterval()
	 *
	 * @return array The test data.
	 */
	public function dataForTestSetInterval(): array
	{
		return [
			"typical30" => [30,],
			"typical60" => [60,],
			"typical10" => [10,],
			"typical20" => [20,],

			// these type casts should both result in (int) 0 - PHP type casts just truncate floats
			"invalidFloat0.99CastInt" => [(int) 0.99,InvalidIntervalException::class],
			"invalidFloat0.49CastInt" => [(int) 0.49, InvalidIntervalException::class],
			"invalidFloat0.49" => [0.49, TypeError::class,],
			"invalidFloat0.51" => [0.51, TypeError::class,],
			"invalid0" => [0, InvalidIntervalException::class,],
			"invalidMinus1" => [-1, InvalidIntervalException::class,],
			"invalidMinus30" => [-30, InvalidIntervalException::class,],
			"invalidNull" => [null, TypeError::class,],
			"invalidString" => ["30", TypeError::class,],
			"invalidObject" => [new class {}, TypeError::class,],
		];
	}

	/**
	 * Test for setInterval() method.
	 *
	 * @dataProvider dataForTestSetInterval
	 *
	 * @param mixed $interval The interval to set.
	 * @param class-string|null $exceptionClass The type of exception that is expected, if any.
	 */
	public function testSetInterval(mixed $interval, ?string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = self::createTotp();
		$totp->setInterval($interval);
		$this->assertSame($interval, $totp->interval(), "The interval {$interval} was expected but {$totp->interval()} was reported.");
	}

	/**
	 * Data provider for testInterval()
	 *
	 * @return Generator The test data.
	 */
	public function dataForTestInterval(): Generator
	{
		// test with all valid intervals up to 1 hour
		for ($interval = 1; $interval <= 3600; ++$interval) {
			yield [$interval,];
		}

		// throw some random valid intervals at it for good measure
		for ($idx = 0; $idx < 5000; ++$idx) {
			yield [mt_rand(1, 3600),];
		}
	}

	/**
	 * Test the interval() method.
	 *
	 * @dataProvider dataForTestInterval
	 *
	 * @param int $interval The interval to test with.
	 */
	public function testInterval(int $interval): void
	{
		$totp = self::createTotp();
		$totp->setInterval($interval);
		$this->assertSame($interval, $totp->interval(), "The interval {$interval} was expected but {$totp->interval()} was reported.");
	}

	/**
	 * Test data for testSetSecret.
	 *
	 * @return \Generator
	 * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	public function dataForTestSetSecret(): Generator
	{
		// 100 datasets with random valid secrets
		for ($idx = 0; $idx < 100; ++$idx) {
			yield "validSecret" . sprintf("%02d", $idx) => [random_bytes(mt_rand(16, 20)),];
		}

		// 100 datasets with random invalid secrets
		for ($idx = 0; $idx < 100; ++$idx) {
			$len = mt_rand(0, 15);
			yield "invalidSecret" . sprintf("%02d", $idx) => [(0 == $len ? "" : random_bytes($len)), InvalidSecretException::class,];
		}

		// tests for specific scenarios
		yield "marginallyInvalidSecret" => [random_bytes(15), InvalidSecretException::class,];
		yield "emptySecret" => ["", InvalidSecretException::class,];
		yield "nullSecret" => [null, TypeError::class,];
		yield "intSecret" => [1234567890123456, TypeError::class,];	// NOTE requires 64-bit int type
		yield "floatSecret" => [1234567890123456.12345, TypeError::class,];
		yield "objectSecret" => [new class{}, TypeError::class,];
		yield "arraySecret" => [["12345678901234567890",], TypeError::class,];
	}

	/**
	 * Test for the setSecret() method.
	 *
	 * @dataProvider dataForTestSetSecret
	 *
	 * @param mixed $secret The secret to set.
	 * @param string|null $exceptionClass The class name of the expected exception, if any.
	 * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	public function testSetSecret(mixed $secret, ?string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = self::createTotp();
		$totp->setSecret($secret);
		$this->assertSame($secret, $totp->secret(), "Secret was not as expected.");
	}

	/**
	 * Test data for testSecret.
	 *
	 * @return \Generator
	 * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	public function dataForTestSecret(): Generator
	{
		// 100 datasets with random valid secrets
		for ($idx = 0; $idx < 100; ++$idx) {
			yield "secret" . sprintf("%02d", $idx) => [random_bytes(mt_rand(16, 20)),];
		}
	}

	/**
	 * @dataProvider dataForTestSecret
	 * @param string $secret
	 * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	public function testSecret(string $secret): void
	{
		$totp = self::createTotp();
		$totp->setSecret($secret);
		$this->assertSame($secret, $totp->secret(), "The secret returned from Totp::secret() is not as expected.");
	}

	/**
	 * Test data for testSetRenderer()
	 *
	 * @return array
	 */
	public function dataForTestSetRenderer(): array
	{
		return [
			"sixDigits" => [new SixDigits(),],
			"eightDigits" => [new EightDigits(),],
			"integer6Digits" => [new Integer(6),],
			"integer7Digits" => [new Integer(7),],
			"integer8Digits" => [new Integer(8),],
			"integer9Digits" => [new Integer(9),],
			"integer10Digits" => [new Integer(10),],
			"anonymousClass" => [new class implements Renderer {
				public function render(string $hmac): string{
					return "insecure";
				}
			},],
			"invalidNull" => [null, TypeError::class,],
			"invalidInt" => [6, TypeError::class,],
			"invalidFloat" => [6.5, TypeError::class,],
			"invalidString" => ["foo", TypeError::class,],
			"invalidObject" => [new class{}, TypeError::class,],
			"invalidArray" => [["render" => function(string $hmac): string {
				return "insecure";
			}], TypeError::class,],
			"invalidStdClass" => [(object) ["render" => function(string $hmac): string {
				return "insecure";
			}], TypeError::class,],
		];
	}

	/**
	 * @dataProvider dataForTestSetRenderer
	 *
	 * @param mixed $renderer The renderer to set.
	 * @param string|null $exceptionClass The class name of an exception that is expected to be thrown, if any.
	 */
	public function testSetRenderer(mixed $renderer, ?string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = self::createTotp();
		$totp->setRenderer($renderer);
		$this->assertSame($renderer, $totp->renderer(), "Renderer set was not returned from renderer() method.");
	}

	/**
	 * Test data for testSetRenderer()
	 *
	 * @return array
	 */
	public function dataForTestRenderer(): array
	{
		return [
			"sixDigits" => [new SixDigits(),],
			"eightDigits" => [new EightDigits(),],
			"integer6Digits" => [new Integer(6),],
			"integer7Digits" => [new Integer(7),],
			"integer8Digits" => [new Integer(8),],
			"integer9Digits" => [new Integer(9),],
			"integer10Digits" => [new Integer(10),],
			"anonymousClass" => [new class implements Renderer {
				public function render(string $hmac): string{
					return "insecure";
				}
			},],
		];
	}

	/**
	 * @dataProvider dataForTestRenderer
	 *
	 * @param \Equit\Totp\Renderers\Renderer $renderer
	 *
	 * @return void
	 */
	public function testRenderer(Renderer $renderer): void
	{
		$totp = self::createTotp();
		$totp->setRenderer($renderer);
		$this->assertSame($renderer, $totp->renderer(), "Unexpected object returned from renderer() method.");
	}

	/**
	 * Test data for testCounterAt().
	 *
	 * Each dataset consists of the current time at which the counter should be checked and the expected value for the
	 * counter. In all cases, the TOTP has its reference date set to the Unix epoch and an interval of 30 seconds.
	 *
	 * @return \int[][]
	 */
	public function dataForTestCounterAt(): array
	{
		return [
			// test data from RFC 6238
			[59, 1,],
			[1111111109, 37037036,],
			[1111111111, 37037037,],
			[1234567890, 41152263,],
			[2000000000, 66666666,],
			[20000000000, 666666666,],

			// test data for non-default reference time
			[119, 1, 60,],
			[121, 2, 60,],

			// test data for non-default interval
			[59, 5, null, 10,],
			[61, 6, null, 10,],

			// test data for non-default interval and non-default reference time
			[119, 5, 60, 10,],
			[121, 6, 60, 10,],

            // test for invalid time
            [60, 0, 120, 30, InvalidTimeException::class,],
		];
	}

	/**
	 * @dataProvider dataForTestCounterAt
	 *
	 * @param int|\DateTime $currentTime The time at which to test the byttes.
	 * @param int $expectedCounter The expected value for the counter.
	 * @param int|\DateTime|null $referenceTime The reference time for the test TOTP. Default is null: the default for
	 * the Totp will be used (the Unix epoch).
	 * @param int|null $interval The interval for the test TOTP. Default is null: the default for the Totp will be used
	 * (30 seconds).
     * @param class-string|null $exceptionClass The class of exception expected to be thrown, if any.
	 */
	public function testCounterAt(int | DateTime $currentTime, int $expectedCounter, int | DateTime $referenceTime = null, ?int $interval = null, ?string $exceptionClass = null): void
	{
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

		$totp = $this->createTotp();

		if (isset($referenceTime)) {
			$totp->setReferenceTime($referenceTime);
		}

		if (isset($interval)) {
			$totp->setInterval($interval);
		}

		$actualCounter = $totp->counterAt($currentTime);
		$this->assertSame($expectedCounter, $actualCounter, "The counter is expected to be {$expectedCounter} but is actually {$actualCounter}.");
	}

	/**
	 * Test data for the counterBytes() method.
	 *
	 * @return array The test data.
	 * @noinspection PhpDocMissingThrowsInspection The DateTime constructor will not throw in any of these cases.
	 */
	public function dataForTestCounter(): array
	{
		return [
			"sha1-6digit-1970" => [],
			"sha256-6digit-1970" => [null, Totp::Sha256Algorithm,],
			"sha512-6digit-1970" => [null, Totp::Sha512Algorithm,],
			"sha1-6digit-1974"=> [null, Totp::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
			"sha256-6digit-1974"=> [null, Totp::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
			"sha512-6digit-1974"=> [null, Totp::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
		];
	}

	/**
	 * @dataProvider dataForTestCounter
	 *
	 * @param string|null $secret The TOTP secret. If null, a random secret will be chosen.
	 * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
	 * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
	 */
	public function testCounter(string $secret = null, string $algorithm = Totp::Sha1Algorithm, int | DateTime $referenceTime = 0): void
	{
		// The logic behind this test is this: counter() can't return a pre-known value because it produces a value that
		// is dependent on an external factor - the current system time. So we use counterAt() as our source of
		// expectations on the assumption that it provides a correct value. It's safe to do this because we have a test
		// for counterAt() and that test will tell us if it's not working. In order mitigate against the outside chance
		// that the system time ticks over to the next TOTP interval between the point in time at which we call time()
		// and the point in time at which we fetch the actual counter bytes from the Totp object, we ensure that the
		// time after retrieving the bytes from the Totp object is the same as the time we're using as our source of
		// expectation.
		//
		// Note that while debugging, if you put a breakpoint on the call to Totp::counterBytes() you are more likely
		// to trigger a repeat of the loop
		$totp = new Totp(secret: $secret, referenceTime: $referenceTime, hashAlgorithm: $algorithm);

		// unless you've set a breakpoint we should traverse this loop no more than twice
		do {
			$time = time();
			$actual = $totp->counter();
            $expected = $totp->counterAt($time);
			$repeat = (time() !== $time);
		} while($repeat);

		$this->assertSame($expected, $actual, "The generated current counter did not match the expected counter.");
	}

	/**
	 * @return array
	 */
	public function dataForTestCounterBytesAt(): array
	{
		return [
			// test data from RFC 6238
			[59, "\x00\x00\x00\x00\x00\x00\x00\x01",],
			[1111111109, "\x00\x00\x00\x00\x02\x35\x23\xEC",],
			[1111111111, "\x00\x00\x00\x00\x02\x35\x23\xED",],
			[1234567890, "\x00\x00\x00\x00\x02\x73\xEF\x07",],
			[2000000000, "\x00\x00\x00\x00\x03\xF9\x40\xAA",],
			[20000000000, "\x00\x00\x00\x00\x27\xBC\x86\xAA",],

			// test data for non-default reference time
			[119, "\x00\x00\x00\x00\x00\x00\x00\x01", 60,],
			[121, "\x00\x00\x00\x00\x00\x00\x00\x02", 60,],

			// test data for non-default interval time
			[59, "\x00\x00\x00\x00\x00\x00\x00\x05", null, 10,],
			[61, "\x00\x00\x00\x00\x00\x00\x00\x06", null, 10,],

			// test data for non-default interval and non-default reference time
			[119, "\x00\x00\x00\x00\x00\x00\x00\x05", 60, 10,],
			[121, "\x00\x00\x00\x00\x00\x00\x00\x06", 60, 10,],
		];
	}

	/**
	 * @dataProvider dataForTestCounterBytesAt
	 *
	 * @param int|\DateTime $currentTime The time at which to test the byttes.
	 * @param string $expectedBytes The expected bytes for the counter. Must be of length 8.
	 * @param int|\DateTime|null $referenceTime The reference time for the test TOTP. Default is null: the default for
	 * the Totp will be used (the Unix epoch).
	 * @param int|null $interval The interval for the test TOTP. Default is null: the default for the Totp will be used
	 * (30 seconds).
	 */
	public function testCounterBytesAt(int | DateTime $currentTime, string $expectedBytes, int | DateTime $referenceTime = null, ?int $interval = null): void
	{
		$totp = $this->createTotp();

		if (isset($referenceTime)) {
			$totp->setReferenceTime($referenceTime);
		}

		if (isset($interval)) {
			$totp->setInterval($interval);
		}

		$counterBytesAt = new ReflectionMethod($totp, "counterBytesAt");
		$counterBytesAt->setAccessible(true);
		$counterBytesAt = $counterBytesAt->getClosure($totp);

		$actualBytes = $counterBytesAt($currentTime);
		$this->assertSame($expectedBytes, $actualBytes, "The counter is expected to be " . self::hexOf($expectedBytes) . " but is actually " . self::hexOf($actualBytes) . ".");
	}

	/**
	 * Test data for the counterBytes() method.
	 *
	 * @return array The test data.
	 * @noinspection PhpDocMissingThrowsInspection The DateTime constructor will not throw in any of these cases.
	 */
	public function dataForTestCounterBytes(): array
	{
		return [
			"sha1-6digit-1970" => [],
			"sha256-6digit-1970" => [null, Totp::Sha256Algorithm,],
			"sha512-6digit-1970" => [null, Totp::Sha512Algorithm,],
			"sha1-6digit-1974"=> [null, Totp::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
			"sha256-6digit-1974"=> [null, Totp::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
			"sha512-6digit-1974"=> [null, Totp::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
		];
	}

	/**
	 * @dataProvider dataForTestCounterBytes
	 *
	 * @param string|null $secret The TOTP secret. If null, a random secret will be chosen.
	 * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
	 * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
	 */
	public function testCounterBytes(string $secret = null, string $algorithm = Totp::Sha1Algorithm, int | DateTime $referenceTime = 0): void
	{
		// The logic behind this test is this: counterBytes() can't return a pre-known value because it produces a
		// 64-bit value that is dependent on an external factor - the current system time. So we use counterBytesAt() as
		// our source of expectations on the assumption that it provides a correct value. It's safe to do this because
		// we have a test for counterBytesAt() and that test will tell us if it's not working. In order mitigate against
		// the outside chance that the system time ticks over to the next TOTP interval between the point in time at
		// which we call time() and the point in time at which we fetch the actual counter bytes from the Totp object,
		// we ensure that the time after retrieving the bytes from the Totp object is the same as the time we're using
		// as our source of expectation.
		//
		// Note that while debugging, if you put a breakpoint on the call to Totp::counterBytes() you are more likely
		// to trigger a repeat of the loop
		$totp = new Totp(secret: $secret, referenceTime: $referenceTime, hashAlgorithm: $algorithm);

		$counterBytes = new ReflectionMethod(Totp::class, "counterBytes");
		$counterBytes->setAccessible(true);
		$counterBytes = $counterBytes->getClosure($totp);

		$counterBytesAt = new ReflectionMethod(Totp::class, "counterBytesAt");
		$counterBytesAt->setAccessible(true);
		$counterBytesAt = $counterBytesAt->getClosure($totp);

		// unless you've set a breakpoint we should traverse this loop no more than twice
		do {
			$time = time();
			$actual = $counterBytes();
            $expected = $counterBytesAt($time);
			$repeat = (time() !== $time);
		} while($repeat);

		$this->assertSame($expected, $actual, "The generated counter bytes did not match the expected counter bytes.");
	}

	/**
	 * Test data for the currentPassword() method.
	 *
	 * @return array The test data.
	 * @noinspection PhpDocMissingThrowsInspection The DateTime constructor will not throw in any of these cases.
	 */
	public function dataForTestCurrentPassword(): array
	{
		return [
			"sha1-6digit-1970" => [],
			"sha1-7digit-1970" => [null, 7,],
			"sha1-8digit-1970" => [null, 8,],
			"sha256-6digit-1970" => [null, 6, Totp::Sha256Algorithm,],
			"sha256-7digit-1970" => [null, 7, Totp::Sha256Algorithm,],
			"sha256-8digit-1970" => [null, 8, Totp::Sha256Algorithm,],
			"sha512-6digit-1970" => [null, 6, Totp::Sha512Algorithm,],
			"sha512-7digit-1970" => [null, 7, Totp::Sha512Algorithm,],
			"sha512-8digit-1970" => [null, 8, Totp::Sha512Algorithm,],
			"sha1-6digit-1974"=> [null, 6, Totp::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
			"sha1-7digit-1974"=> [null, 7, Totp::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
			"sha1-8digit-1974"=> [null, 8, Totp::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
			"sha256-6digit-1974"=> [null, 6, Totp::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
			"sha256-7digit-1974"=> [null, 7, Totp::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
			"sha256-8digit-1974"=> [null, 8, Totp::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
			"sha512-6digit-1974"=> [null, 6, Totp::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
			"sha512-7digit-1974"=> [null, 7, Totp::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
			"sha512-8digit-1974"=> [null, 8, Totp::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
		];
	}

	/**
	 * @dataProvider dataForTestCurrentPassword
	 *
	 * @param string|null $secret The TOTP secret. If null, a random secret will be chosen.
	 * @param int $digits The number of digits for the password. Defaults to 6.
	 * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
	 * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
	 */
	public function testCurrentPassword(string $secret = null, int $digits = 6, string $algorithm = Totp::Sha1Algorithm, int | DateTime $referenceTime = 0): void
	{
		// The logic behind this test is this: currentPassword() can't return a pre-known value because it produces a
		// password dependent on an external factor - the current system time. So we use passwordAt() as our source of
		// expectations on the assumption that it provides a correct value. It's safe to do this because we have a test
		// for passwordAt() and that test will tell us if it's not working. In order mitigate against the outside chance
		// that the system time ticks over to the next TOTP interval between the point in time at which we call
		// time() and the point in time at which we fetch the actual password from the Totp object, we ensure that
		// the time after retrieving the password from the Totp object is the same as the time we're using as our
		// source of expectation.
		//
		// Note that while debugging, if you put a breakpoint on the call to Totp::currentPassword() you are more likely
		// to trigger a repeat of the loop
		$totp = new Totp(secret: $secret, renderer: new Integer($digits), referenceTime: $referenceTime, hashAlgorithm: $algorithm);

		// unless you've set a breakpoint we should traverse this loop no more than twice
		do {
			$time = time();
			$actual = $totp->currentPassword();
			$repeat = (time() !== $time);
		} while($repeat);

		$expected = $totp->passwordAt($time);
		$this->assertSame($expected, $actual, "The generated password did not match the expected password.");
	}

    /**
     * Test data for testPasswordAt().
     *
     * @return Generator The test data.
     * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
     */
	public function dataForTestPasswordAt(): Generator
	{
		// transform the RFC test data into the args required for testPasswordAt()
		yield from array_map(
			function(array $testData) use (&$digits): array {
				return [$testData["secret"]["raw"], 0, $testData["timestamp"], $testData["passwords"]["8"], $testData["algorithm"],];
			},
			self::rfcTestData()
		);
        
        // test for times before TOTP reference time
        yield [random_bytes(20), 120, 1, "", Totp::Sha1Algorithm, InvalidTimeException::class,];
        yield [random_bytes(32), 120, 1, "", Totp::Sha256Algorithm, InvalidTimeException::class,];
        yield [random_bytes(64), 120, 1, "", Totp::Sha512Algorithm, InvalidTimeException::class,];
	}

	/**
	 * @dataProvider dataForTestPasswordAt
	 *
	 * Tests the generated passwords. The provided password is expected to be 8 digits. It will be tested with Integer
	 * renderers of 8, 7 and 6 digits using a substring of the password where appropriate.
	 *
	 * @param string $secret The TOTP secret.
	 * @param int|\DateTime $referenceTime The TOTP reference time.
	 * @param int|\DateTime $currentTime The time at which to test the password.
	 * @param string $password The 8 digits of the expected password.
	 * @param string|null $algorithm The hash algorithm for the TOTP.
	 * @param class-string|null $exceptionClass The class name of the exception exptected to be thrown, if any.
	 */
	public function testPasswordAt(string $secret, int | DateTime $referenceTime, int | DateTime $currentTime, string $password, ?string $algorithm = Totp::Sha1Algorithm, ?string $exceptionClass = null): void
	{
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }
        
		$renderer = new Integer(8);
		$totp = new Totp(secret: $secret, renderer: $renderer, interval: 30, referenceTime: $referenceTime);
		$totp->setHashAlgorithm($algorithm);
		$this->assertSame(
			$password,
			$totp->passwordAt($currentTime),
			"Unexpected 6-digit password at " .
			($currentTime instanceof DateTime ? $currentTime : new DateTime("@{$currentTime}"))->format("Y-m-d H:i:s") .
			" with secret '" . self::hexOf($secret) . "', algorithm {$totp->hashAlgorithm()}, reference time " .
			$totp->referenceDateTime()->format("Y-m-d H:i:s") . ", interval {$totp->interval()}"
		);

		$renderer->setDigits(7);

		$this->assertSame(
			substr($password, 1),
			$totp->passwordAt($currentTime),
			"Unexpected 7-digit password at " .
			($currentTime instanceof DateTime ? $currentTime : new DateTime("@{$currentTime}"))->format("Y-m-d H:i:s") .
			" with secret '" . self::hexOf($secret) . "', algorithm {$totp->hashAlgorithm()}, reference time " .
			$totp->referenceDateTime()->format("Y-m-d H:i:s") . ", interval {$totp->interval()}"
		);

		$renderer->setDigits(6);

		$this->assertSame(
			substr($password, 2),
			$totp->passwordAt($currentTime),
			"Unexpected 8-digit password at " .
			($currentTime instanceof DateTime ? $currentTime : new DateTime("@{$currentTime}"))->format("Y-m-d H:i:s") .
			" with secret '" . self::hexOf($secret) . "', algorithm {$totp->hashAlgorithm()}, reference time " .
			$totp->referenceDateTime()->format("Y-m-d H:i:s") . ", interval {$totp->interval()}"
		);
	}

	/**
	 * Test data for testVerify()
	 *
	 * @return \Generator
     * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	public function dataForTestVerify(): Generator
	{
		// yield 100 random valid configurations for a Totp
		for ($idx = 0; $idx < 100; ++$idx) {
			yield "randomConfiguration" . sprintf("%02d", $idx) => [
				random_bytes(64),
				mt_rand(6, 8),
				match(mt_rand(0, 2)) {
					0 => Totp::Sha1Algorithm,
					1 => Totp::Sha256Algorithm,
					2 => Totp::Sha512Algorithm,
				},
				mt_rand(0, time() - 20 * 365 * 24 * 60 * 60),
			];
		}
	}

	/**
	 * @dataProvider dataForTestVerify
	 *
	 * @param string|null $secret The TOTP secret. If null, a random secret will be chosen.
	 * @param int $digits The number of digits for the password. Defaults to 6.
	 * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
	 * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
	 */
	public function testVerify(string $secret = null, int $digits = 6, string $algorithm = Totp::Sha1Algorithm, int | DateTime $referenceTime = 0): void
	{
		// The logic behind this test is this: verify() can't return a pre-known value because it is dependent on an
		// external factor - the current system time. So we fetch the current password, which we know should pass
		// verification, and verify that on the assumption that currentPassword() provides the correct value. It's
		// safe to do this because we have a test for currentPassword() and that test will tell us if it's not working.
		// In order mitigate against the outside chance that the system time ticks over to the next TOTP interval
		// between the point in time at which we call time() and the point in time at which we do the verification, we
		// ensure that the time after doing the verification is the same as the time before it, ensuring that we've
		// called verify at the same second as we fetched the password. We also change one digit of the password and
		// test with that as well, to ensure we have both positive and negative tests for verify().
		//
		// Note that while debugging, if you put a breakpoint on the call to Totp::verify() you are more likely
		// to trigger a repeat of the loop
		$totp = new Totp(secret: $secret, renderer: new Integer($digits), referenceTime: $referenceTime, hashAlgorithm: $algorithm);

		// unless you've set a breakpoint we should traverse this loop no more than twice
		do {
			$time = time();
			$correctPassword = $totp->currentPassword();
			// change one digit of the correct password by one, making it incorrect
			$incorrectPassword = $correctPassword;
			$incorrectPassword[3] = "" . ((intval($incorrectPassword[3]) + 1) % 10);
			$correctPasswordVerified = $totp->verify($correctPassword);
			$incorrectPasswordVerified = $totp->verify($incorrectPassword);
			$repeat = (time() !== $time);
		} while($repeat);

		$this->assertTrue($correctPasswordVerified, "Totp::verified() did not verify the correct password.");
		$this->assertFalse($incorrectPasswordVerified, "Totp::verified() incorrectly verified the incorrect password.");
	}

	/**
	 * Test data for testVerifyAt().
	 *
	 * @return Generator The test data.
     * @throws \Exception if random_bytes() is not able to provide cryptographically-secure data.
	 */
	public function dataForTestVerifyAt(): Generator
	{
		// transforms the RFC data into the structure required for this test
		$extractData = function(array $testData) use (&$digits, &$window): array {
			return [
				[
					"secret" => $testData["secret"]["raw"],
					"digits" => $digits,
					"referenceTime" => $testData["referenceTimestamp"],
					"interval" => $testData["interval"],
					"hashAlgorithm" => $testData["algorithm"],
				],
				// add intervals to the "current" time to ensure that the password at the oldest interval within the
				// window is the one that is expected to match the password
				$testData["timestamp"] + ($window * $testData["interval"]),
				$window,
				$testData["passwords"]["{$digits}"],
				true,
			];
		};

        // test the RFC data with windows of 0, 1 and 2 intervals
        $rfcData = self::rfcTestData();

        for ($window = 0; $window < 3; ++$window) {
			for ($digits = 6; $digits <= 8; ++$digits) {
                foreach ($rfcData as $key => $value) {
                    yield "{$key}-{$digits}-{$window}" => $extractData($value);
                }
			}
		}

        yield from [
            "emptyPassword6digitsSha1" => [["secret" => random_bytes(20), "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "", false,],
            "emptyPassword6digitsSha256" => [["secret" => random_bytes(32), "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "", false,],
            "emptyPassword6digitsSha512" => [["secret" => random_bytes(64), "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "", false,],

            "emptyPassword7digitsSha1" => [["secret" => random_bytes(20), "digits" => 7, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "", false,],
            "emptyPassword7digitsSha256" => [["secret" => random_bytes(32), "digits" => 7, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "", false,],
            "emptyPassword7digitsSha512" => [["secret" => random_bytes(64), "digits" => 7, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "", false,],

            "emptyPassword8digitsSha1" => [["secret" => random_bytes(20), "digits" => 8, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "", false,],
            "emptyPassword8digitsSha256" => [["secret" => random_bytes(32), "digits" => 8, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "", false,],
            "emptyPassword8digitsSha512" => [["secret" => random_bytes(64), "digits" => 8, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "", false,],

            "alphaPassword6digitsSha1" => [["secret" => random_bytes(20), "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "ABCDEF", false,],
            "alphaPassword6digitsSha256" => [["secret" => random_bytes(32), "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "ABCDEF", false,],
            "alphaPassword6digitsSha512" => [["secret" => random_bytes(64), "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "ABCDEF", false,],

            "alphaPassword7digitsSha1" => [["secret" => random_bytes(20), "digits" => 7, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "ABCDEFG", false,],
            "alphaPassword7digitsSha256" => [["secret" => random_bytes(32), "digits" => 7, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "ABCDEFG", false,],
            "alphaPassword7digitsSha512" => [["secret" => random_bytes(64), "digits" => 7, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "ABCDEFG", false,],

            "alphaPassword8digitsSha1" => [["secret" => random_bytes(20), "digits" => 8, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "ABCDEFGH", false,],
            "alphaPassword8digitsSha256" => [["secret" => random_bytes(32), "digits" => 8, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "ABCDEFGH", false,],
            "alphaPassword8digitsSha512" => [["secret" => random_bytes(64), "digits" => 8, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "ABCDEFGH", false,],

            // RFC data with one digit in the password changed by 1
            "numericPassword6digitsSha1Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "287081", false,],
            "numericPassword6digitsSha256Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "247375", false,],
            "numericPassword6digitsSha512Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "342146", false,],

            "numericPassword6digitsSha1Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "287072", false,],
            "numericPassword6digitsSha256Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "247364", false,],
            "numericPassword6digitsSha512Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "342137", false,],

            "numericPassword6digitsSha1Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "287182", false,],
            "numericPassword6digitsSha256Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "247474", false,],
            "numericPassword6digitsSha512Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "342247", false,],

            "numericPassword6digitsSha1Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "288082", false,],
            "numericPassword6digitsSha256Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "248374", false,],
            "numericPassword6digitsSha512Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "343147", false,],

            "numericPassword6digitsSha1Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "277082", false,],
            "numericPassword6digitsSha256Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "237374", false,],
            "numericPassword6digitsSha512Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "332147", false,],

            "numericPassword6digitsSha1Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "187082", false,],
            "numericPassword6digitsSha256Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "147374", false,],
            "numericPassword6digitsSha512Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "242147", false,],

            "numericPassword7digitsSha1Digit7Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "4287083", false,],
            "numericPassword7digitsSha256Digit7Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "2247375", false,],
            "numericPassword7digitsSha512Digit7Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "9342146", false,],

            "numericPassword7digitsSha1Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "4287092", false,],
            "numericPassword7digitsSha256Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "2247384", false,],
            "numericPassword7digitsSha512Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "9342157", false,],

            "numericPassword7digitsSha1Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "4287182", false,],
            "numericPassword7digitsSha256Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "2247274", false,],
            "numericPassword7digitsSha512Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "9342047", false,],

            "numericPassword7digitsSha1Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "4288082", false,],
            "numericPassword7digitsSha256Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "2248374", false,],
            "numericPassword7digitsSha512Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "9343147", false,],

            "numericPassword7digitsSha1Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "4297082", false,],
            "numericPassword7digitsSha256Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "2257374", false,],
            "numericPassword7digitsSha512Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "9352147", false,],

            "numericPassword7digitsSha1Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "4187082", false,],
            "numericPassword7digitsSha256Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "2147374", false,],
            "numericPassword7digitsSha512Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "9242147", false,],

            "numericPassword7digitsSha1Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "3287082", false,],
            "numericPassword7digitsSha256Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "1247374", false,],
            "numericPassword7digitsSha512Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "8342147", false,],

            "numericPassword8digitsSha1Digit8Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "94287083", false,],
            "numericPassword8digitsSha256Digit8Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "32247375", false,],
            "numericPassword8digitsSha512Digit8Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "69342148", false,],

            "numericPassword8digitsSha1Digit7Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "94287092", false,],
            "numericPassword8digitsSha256Digit7Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "32247384", false,],
            "numericPassword8digitsSha512Digit7Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "69342157", false,],

            "numericPassword8digitsSha1Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "94287182", false,],
            "numericPassword8digitsSha256Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "32247474", false,],
            "numericPassword8digitsSha512Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "69342247", false,],

            "numericPassword8digitsSha1Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "94286082", false,],
            "numericPassword8digitsSha256Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "32246374", false,],
            "numericPassword8digitsSha512Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "69343147", false,],

            "numericPassword8digitsSha1Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "94297082", false,],
            "numericPassword8digitsSha256Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "32257374", false,],
            "numericPassword8digitsSha512Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "69352147", false,],

            "numericPassword8digitsSha1Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "94387082", false,],
            "numericPassword8digitsSha256Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "32347374", false,],
            "numericPassword8digitsSha512Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "69242147", false,],

            "numericPassword8digitsSha1Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "95287082", false,],
            "numericPassword8digitsSha256Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "31247374", false,],
            "numericPassword8digitsSha512Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "68342147", false,],

            "numericPassword8digitsSha1Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "2287082", false,],
            "numericPassword8digitsSha256Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 0, "0247374", false,],
            "numericPassword8digitsSha512Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha512Algorithm,], 59, 0, "7342147", false,],

            // time specified as DateTime
            "currentTimeAsDateTime01" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], new DateTime("@59", new DateTimeZone("UTC")), 0, "287082", true,],
            "currentTimeAsDateTime02" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], new DateTime("@59", new DateTimeZone("UTC")), 0, "287072", false,],

            // invalid window
            "invalidWindowMinus1" => [["secret" => random_bytes(20), "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, -1, "", false, InvalidVerificationWindowException::class,],
            "invalidWindowBeyondReferenceTime" => [["secret" => random_bytes(32), "digits" => 6, "referenceTime" => 0, "interval" => 30, "hashAlgorithm" => Totp::Sha256Algorithm,], 59, 2, "", false, InvalidVerificationWindowException::class,],

            // invalid "current" time
            "invalidTime" => [["secret" => random_bytes(20), "digits" => 6, "referenceTime" => 240, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 59, 0, "", false, InvalidTimeException::class,],
            "marginallyInvalidTime" => [["secret" => random_bytes(20), "digits" => 6, "referenceTime" => 240, "interval" => 30, "hashAlgorithm" => Totp::Sha1Algorithm,], 239, 0, "", false, InvalidTimeException::class,],
        ];
	}

	/**
	 * @dataProvider dataForTestVerifyAt
	 *
	 * @param array $totpSpec The values to use to initialise the Totp object.
	 * @param int|\DateTime $currentTime The timestamp at which to check verification.
	 * @param int $window The verification window, expressed in intervals.
	 * @param string $userPassword The password to verify.
	 * @param bool $expectedVerification Whether Totp::verifyAt() should verify the password at the time.
	 * @param class-string|null $exceptionClass The class name of an exception expected to be thrown, if any.
	 */
	public function testVerifyAt(array $totpSpec, int | DateTime $currentTime, int $window, string $userPassword, bool $expectedVerification, string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = Totp::integerTotp(digits: $totpSpec["digits"], secret: $totpSpec["secret"], interval: $totpSpec["interval"], referenceTime: $totpSpec["referenceTime"], hashAlgorithm: $totpSpec["hashAlgorithm"]);
		$this->assertEquals($expectedVerification, $totp->verifyAt(password: $userPassword, time: $currentTime, window: $window), "Verification not as expected.");
	}

	/**
	 * Test the defaultRenderer() method.
	 */
	public function testDefaultRenderer(): void
	{
		$defaultRenderer = new ReflectionMethod(Totp::class, "defaultRenderer");
		$defaultRenderer->setAccessible(true);
		$defaultRenderer = $defaultRenderer->getClosure();
		$renderer = $defaultRenderer();
		$this->assertInstanceOf(SixDigits::class, $renderer);
	}

    /**
     * Test the randomSecret() method.
     */
    public function testRandomSecret(): void
    {
        // NOTE can't test case where randomSecret() throws because we can't force random_bytes() to throw
        for ($idx = 0; $idx < 100; ++$idx) {
            $this->assertGreaterThanOrEqual(64, strlen(Totp::randomSecret()), "randomSecret() did not return a sufficiently large byte sequence.");
        }
    }
}
