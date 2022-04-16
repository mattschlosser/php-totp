<?php

declare(strict_types=1);

namespace Equit\Totp;

use DateTime;
use DateTimeZone;
use Equit\Totp\Exceptions\InvalidHashAlgorithmException;
use Equit\Totp\Exceptions\InvalidIntervalException;
use Equit\Totp\Exceptions\InvalidSecretException;
use Generator;
use PHPUnit\Framework\TestCase;
use Stringable;
use TypeError;

/**
 * Unit test for the Totp class.
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
			"invalidWrongTypeStringable" => [new class implements Stringable
			{
				public function __toString(): string
				{
					return "OBQXG43XN5ZGILLQMFZXG53POJSA====";
				}
			}, null, TypeError::class,],
		];
	}

	/**
	 * @dataProvider dataForTestSetBase32Secret
	 *
	 * @param mixed $base32 The base32-encoded secret to set.
	 * @param string|null $raw The raw secret expected.
	 * @param string|null $exceptionClass The class name of the exception expected to be thrown, if any.
	 */
	public function testSetBase32Secret(mixed $base32, string|null $raw, ?string $exceptionClass = null)
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = self::createTotp();
		$totp->setBase32Secret($base32);
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
			"invalidWrongTypeStringable" => [new class implements Stringable
			{
				public function __toString(): string
				{
					return "cGFzc3dvcmQtcGFzc3dvcmQ=";
				}
			}, null, TypeError::class,],
		];
	}

	/**
	 * @dataProvider dataForTestSetBase64Secret
	 *
	 * @param mixed $base64 The base64-encoded secret to set.
	 * @param string|null $raw The raw secret expected.
	 * @param string|null $exceptionClass The class name of the exception expected to be thrown, if any.
	 */
	public function testSetBase64Secret(mixed $base64, string|null $raw, ?string $exceptionClass = null)
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$totp = self::createTotp();
		$totp->setBase64Secret($base64);
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
	public function testBase32Secret(string $raw, string $base32)
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
	public function testBase64Secret(string $raw, string $base64)
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
			"invalidNull" => [null, TypeError::class,],
			"invalidInt" => [1, TypeError::class,],
			"invalidObject" => [new class{}, TypeError::class,],
			"invalidStringMD5Upper" => ["MD5", InvalidHashAlgorithmException::class,],
			"invalidStringMD5Lower" => ["md5", InvalidHashAlgorithmException::class,],
			"invalidStringSHA1" => ["SHA1", InvalidHashAlgorithmException::class,],
			"invalidStringSHA256" => ["SHA256", InvalidHashAlgorithmException::class,],
			"invalidStringSHA512" => ["SHA512", InvalidHashAlgorithmException::class,],
			"invalidEmptyString" => ["", InvalidHashAlgorithmException::class,],
			"invalidNonsenseString" => ["foobarfizzbuzz", InvalidHashAlgorithmException::class,],
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
	public function testSetHashAlgorithm(mixed $algorithm, ?string $exceptionClass = null)
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
	public function testHashAlgorithm(string $algorithm)
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
	 *
	 * @return void
	 */
	public function testSetReferenceTime(mixed $time, ?string $exceptionClass = null)
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

//	public function testReferenceTimestamp()
//	{
//	}
//
//	public function testReferenceDateTime()
//	{
//	}

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
	public function testSetInterval(mixed $interval, ?string $exceptionClass = null)
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
	public function testInterval(int $interval)
	{
		$totp = self::createTotp();
		$totp->setInterval($interval);
		$this->assertSame($interval, $totp->interval(), "The interval {$interval} was expected but {$totp->interval()} was reported.");
	}

//	public function testSetSecret()
//	{
//	}
//
//	public function testSecret()
//	{
//	}
//
//	public function testPasswordAt()
//	{
//	}
//
//	public function testCurrentPassword()
//	{
//	}
//
//	public function testVerify()
//	{
//	}
//
//	public function testVerifyAt()
//	{
//	}
}
