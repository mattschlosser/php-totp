<?php

declare(strict_types=1);

namespace Equit\Totp\Tests;

use Equit\Totp\Exceptions\InvalidBase32DataException;
use Equit\Totp\Exceptions\InvalidBase64DataException;
use Equit\Totp\Exceptions\InvalidSecretException;
use Equit\Totp\TotpSecret;
use Generator;
use Stringable;
use TypeError;

/**
 * Tests for the TotpSecret class.
 */
class TotpSecretTest extends TestCase
{
	/**
	 * Test data for TotpSecret::fromRaw()
	 *
	 * @return array The test data.
	 */
	public function dataForTestFromRaw(): array
	{
		return  [
			"typicalAscii" => ["password-password",],
			"typicalBinary01" => ["\x10\x72\x47\x33\x70\xd1\x5a\xd7\xad\xee\x38\xb3\x48\x9f\x6b\x23\x3f\x40\x55\x5a",],
			"typicalBinary02" => ["\xca\x1e\x10\xfa\x3d\x56\x65\xb7\x21\x3c\x36\xb6\x7d\x35\xa5\xa9\xa0\x08\x61\x53",],
			"typicalBinary03" => ["\x99\x7e\x5e\xb4\x9e\x2e\x13\x5d\x59\xd3\xbf\x22\xa3\x45\xa0\x37\x7c\x0e\x58\xb9\x60\x5a\x09\xcb\xd9\xee\x4d\xc1\x22\xbd\x6d\xfc",],
			"typicalBinary04" => ["\xb4\x73\x19\xa7\x82\xa0\x95\x91\x96\x61\xd1\x94\x1b\x49\xae\xa5\xc4\x48\x1b\xbb\x38\x5f\x73\xc7\x27\xd1\xae\x78\x2b\xe6\xc9\x82\x2e\x56\xa6\x6a\xc0\xe8\xe6\xde\x36\xaf\x0c\x0c\x5f\x91\xfb\x21\x79\xcb\xfd\x0e\xda\xb3\x31\x8b\x08\xfb\xe5\x33\x3f\x24\xeb\xe0",],
			"typicalBinary05" => ["\x22\x71\x3e\xa7\xb1\x30\x3c\x28\x33\xe7\xd7\xea\x86\x35\x50\x8a\xf0\x3d\xf2\xff\xb2\xff\x74\x60\x9d\x0d\x3a\x94\xbf\xe0\xc2\x56\x4c\x75\x35\x52\xd5\x25\x5f\x58\xbd\x12\xff\xc9\x61\x31\x98\x0e\xc8\xe5\x20\x51\x9d\x27\x2d\x77\xd9\xca\xfa\xc0\x37\x6f\x02\x85",],
			"typicalBinary06" => ["\xf9\xee\xee\x58\xa0\x90\xcc\xcf\xda\xa1\x42\x9a\xd9\xd2\x24\x88\x98\xe4\x26\x03\xdd\xb3\xe6\x1a\xeb\x25\x22\x4a\x58\x73\x41\x92",],
			"typicalBinary07" => ["\x8b\x81\xf7\xb0\xf5\x0a\x2b\x6e\x15\x98\x15\x62\xd6\x92\x73\xf5\x79\xa0\x2f\xdf",],
			"typicalBinary08" => ["\xfa\xc7\xac\x80\x81\x3d\xf7\x3c\xa7\x8e\xc9\x49\x17\x9b\x52\x64\x89\x79\xe1\x11",],
			"typicalBinary09" => ["\x8b\xd8\x91\x02\x35\x45\xbb\x16\xbc\x58\x4a\xb6\x73\x14\x3b\x61\xb0\x54\xba\xe7",],
			"typicalBinary10" => ["\x1b\x9a\xef\x5d\x2e\xfb\x82\x11\xf6\x48\xe4\x5a\x4f\x54\x1c\xf5\x1e\x55\xa5\x6a",],
			"typicalBinary11" => ["\x08\xc5\x71\xe6\xbc\xd5\xbf\x51\x28\x0c\x2b\xf3\x79\xf9\x20\x0e\x0a\x5e\x5c\xb1\x0b\x09\x17\x9e\xff\xd6\x95\xb1\x7f\x92\x3c\xa1",],
			"typicalBinary12" => ["\xaa\x63\xac\x40\x62\x0b\xcc\xde\xcd\x75\xe9\x81\x8b\x26\xca\xfd\x57\x99\xb3\x7e\xa6\x7b\xb9\x4b\x4a\x23\xcf\x34\x2f\xd0\xcc\x63",],
			"typicalBinary13" => ["\x5d\x72\x22\xbd\x2b\x02\x74\x51\x7e\xe2\x35\x89\x08\xeb\x42\x53\xfa\x1c\x44\x6c\x35\x6d\xaf\xd2\xe0\xf7\x64\x83\x07\xa8\x6c\x0e\x06\x4e\x0f\xbb\xd1\x5b\x07\x46\xe4\x3d\x9c\x37\x01\x07\x73\x69\x26\x53\xbd\x63\x56\xca\xc1\x18\x89\x6f\x0d\x2a\xfb\x41\xed\x44",],
			"typicalBinary14" => ["\x89\xd0\x16\xd5\x98\x35\xef\xcd\x4d\xeb\x02\xe9\x0c\x19\x33\xe0\x6a\x8b\xb2\x9d\xfc\xd3\x15\x30\x5f\x06\xc8\x63\xcb\x34\xab\x41\x93\xc7\x39\x16\x38\x96\x45\x96\xd4\xc1\xf1\x3e\x7a\x9a\xff\xce\xb5\x06\x56\xad\x84\xaf\xec\x60\x91\xad\xc6\x65\xb7\xfe\x7d\x94",],
			"typicalBinary15" => ["\x5d\xbf\x15\x97\x77\x17\xab\x94\xc7\xa7\x30\xd6\x8b\x70\xb6\x2f\x06\xb6\xca\xcb",],
			"typicalBinary16" => ["\xb1\x02\x74\xa3\x2f\x08\xcc\x71\xfe\x54\x2f\x49\x2b\x6e\xb5\xb7\xf6\x43\x85\x70\x8c\x1a\xe2\xde\x94\x9c\xd2\x13\x24\xec\x8c\x37",],
			"extremeShortestAscii" => ["!sixteen--bytes!",],
			"extremeNullBinary16" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",],
			"extremeNullBinary20" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",],
			"extremeNullBinary32" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",],
			"extremeNullBinary64" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",],
			"invalidJustTooShortAscii" => ["!fifteen-bytes!", InvalidSecretException::class,],
			"invalidJustTooShortBinary" => ["\x10\x72\x47\x33\x70\xd1\x5a\xd7\xad\xee\x38\xb3\x48\x9f\x6b", InvalidSecretException::class,],
			"invalidJustTooShortNullBinary" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", InvalidSecretException::class,],
			"invalidNull" => [null, TypeError::class],
			"invalidStringable" => [new class implements Stringable {
				public function __toString(): string
				{
					return "\x10\x72\x47\x33\x70\xd1\x5a\xd7\xad\xee\x38\xb3\x48\x9f\x6b\x23\x3f\x40\x55\x5a";
				}
			}, TypeError::class],
			"invalidArray" => [["\x10\x72\x47\x33\x70\xd1\x5a\xd7\xad\xee\x38\xb3\x48\x9f\x6b\x23\x3f\x40\x55\x5a",], TypeError::class],
			"invalidInt" => [16, TypeError::class],
			"invalidFloat" => [1234567890123456.789, TypeError::class],
			"invalidTrue" => [true, TypeError::class],
			"invalidFalse" => [false, TypeError::class],
		];
	}

	/**
	 * @dataProvider dataForTestFromRaw
	 *
	 * @param mixed $raw
	 * @param string|null $exceptionClass
	 */
	public function testFromRaw(mixed $raw, string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}
		
		$secret = TotpSecret::fromRaw($raw);
		$this->assertEquals($raw, $secret->raw(), "Raw bytes in TotpSecret are not as expected.");
	}
	
	/**
	 * Test data for TotpSecret::fromBase32()
	 *
	 * @return array The test data.
	 */
	public function dataForTestFromBase32(): array
	{
		return  [
			"typicalAscii" => ["OBQXG43XN5ZGILLQMFZXG53POJSA====", "password-password",],
			"typicalBinary01" => ["CBZEOM3Q2FNNPLPOHCZURH3LEM7UAVK2", "\x10\x72\x47\x33\x70\xd1\x5a\xd7\xad\xee\x38\xb3\x48\x9f\x6b\x23\x3f\x40\x55\x5a",],
			"typicalBinary02" => ["ZIPBB6R5KZS3OIJ4G23H2NNFVGQAQYKT", "\xca\x1e\x10\xfa\x3d\x56\x65\xb7\x21\x3c\x36\xb6\x7d\x35\xa5\xa9\xa0\x08\x61\x53",],
			"typicalBinary03" => ["TF7F5NE6FYJV2WOTX4RKGRNAG56A4WFZMBNATS6Z5ZG4CIV5NX6A====", "\x99\x7e\x5e\xb4\x9e\x2e\x13\x5d\x59\xd3\xbf\x22\xa3\x45\xa0\x37\x7c\x0e\x58\xb9\x60\x5a\x09\xcb\xd9\xee\x4d\xc1\x22\xbd\x6d\xfc",],
			"typicalBinary04" => ["WRZRTJ4CUCKZDFTB2GKBWSNOUXCEQG53HBPXHRZH2GXHQK7GZGBC4VVGNLAORZW6G2XQYDC7SH5SC6OL7UHNVMZRRMEPXZJTH4SOXYA=", "\xb4\x73\x19\xa7\x82\xa0\x95\x91\x96\x61\xd1\x94\x1b\x49\xae\xa5\xc4\x48\x1b\xbb\x38\x5f\x73\xc7\x27\xd1\xae\x78\x2b\xe6\xc9\x82\x2e\x56\xa6\x6a\xc0\xe8\xe6\xde\x36\xaf\x0c\x0c\x5f\x91\xfb\x21\x79\xcb\xfd\x0e\xda\xb3\x31\x8b\x08\xfb\xe5\x33\x3f\x24\xeb\xe0",],
			"typicalBinary05" => ["EJYT5J5RGA6CQM7H27VIMNKQRLYD34X7WL7XIYE5BU5JJP7AYJLEY5JVKLKSKX2YXUJP7SLBGGMA5SHFEBIZ2JZNO7M4V6WAG5XQFBI=", "\x22\x71\x3e\xa7\xb1\x30\x3c\x28\x33\xe7\xd7\xea\x86\x35\x50\x8a\xf0\x3d\xf2\xff\xb2\xff\x74\x60\x9d\x0d\x3a\x94\xbf\xe0\xc2\x56\x4c\x75\x35\x52\xd5\x25\x5f\x58\xbd\x12\xff\xc9\x61\x31\x98\x0e\xc8\xe5\x20\x51\x9d\x27\x2d\x77\xd9\xca\xfa\xc0\x37\x6f\x02\x85",],
			"typicalBinary06" => ["7HXO4WFASDGM7WVBIKNNTURERCMOIJQD3WZ6MGXLEUREUWDTIGJA====", "\xf9\xee\xee\x58\xa0\x90\xcc\xcf\xda\xa1\x42\x9a\xd9\xd2\x24\x88\x98\xe4\x26\x03\xdd\xb3\xe6\x1a\xeb\x25\x22\x4a\x58\x73\x41\x92",],
			"typicalBinary07" => ["ROA7PMHVBIVW4FMYCVRNNETT6V42AL67", "\x8b\x81\xf7\xb0\xf5\x0a\x2b\x6e\x15\x98\x15\x62\xd6\x92\x73\xf5\x79\xa0\x2f\xdf",],
			"typicalBinary08" => ["7LD2ZAEBHX3TZJ4OZFERPG2SMSEXTYIR", "\xfa\xc7\xac\x80\x81\x3d\xf7\x3c\xa7\x8e\xc9\x49\x17\x9b\x52\x64\x89\x79\xe1\x11",],
			"invalidJustTooShortAscii" => ["EFTGSZTUMVSW4LLCPF2GK4ZB", "!fifteen-bytes!", InvalidSecretException::class,],
			"invalidJustTooShortBinary" => ["CBZEOM3Q2FNNPLPOHCZURH3L", "\x10\x72\x47\x33\x70\xd1\x5a\xd7\xad\xee\x38\xb3\x48\x9f\x6b", InvalidSecretException::class,],
			"invalidJustTooShortNullBinary" => ["AAAAAAAAAAAAAAAAAAAAAAAA", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", InvalidSecretException::class,],
			"invalidNonBase32Characters" => ["cBZEOM3Q2FNNPLPOHCZURH3L", "", InvalidBase32DataException::class,],
			"invalidBadBase32" => ["7HXO4WFASDGM7WVBIKNNTURERCMOIJQD3WZ6MGXLEUREUWDTIGJA===", "", InvalidBase32DataException::class,],
			"invalidNull" => [null, "", TypeError::class],
			"invalidStringable" => [new class implements Stringable {
				public function __toString(): string
				{
					return "7HXO4WFASDGM7WVBIKNNTURERCMOIJQD3WZ6MGXLEUREUWDTIGJA====";
				}
			}, "", TypeError::class],
			"invalidArray" => [["7HXO4WFASDGM7WVBIKNNTURERCMOIJQD3WZ6MGXLEUREUWDTIGJA====",], "", TypeError::class],
			"invalidInt" => [16, "", TypeError::class],
			"invalidFloat" => [1234567890123456.789, "", TypeError::class],
			"invalidTrue" => [true, "", TypeError::class],
			"invalidFalse" => [false, "", TypeError::class],
		];
	}

	/**
	 * @dataProvider dataForTestFromBase32
	 *
	 * @param mixed $raw
	 * @param string|null $exceptionClass
	 */
	public function testFromBase32(mixed $base32, string $raw, string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$secret = TotpSecret::fromBase32($base32);
		$this->assertEquals($base32, $secret->base32(), "Base32 in TotpSecret is not as expected.");
		$this->assertEquals($raw, $secret->raw(), "Raw bytes in TotpSecret are not as expected.");
	}
	
	/**
	 * Test data for TotpSecret::fromBase64()
	 *
	 * @return array The test data.
	 */
	public function dataForTestFromBase64(): array
	{
		return  [
			"typicalAscii" => ["cGFzc3dvcmQtcGFzc3dvcmQ=", "password-password",],
			"typicalBinary01" => ["i9iRAjVFuxa8WEq2cxQ7YbBUuuc=", "\x8b\xd8\x91\x02\x35\x45\xbb\x16\xbc\x58\x4a\xb6\x73\x14\x3b\x61\xb0\x54\xba\xe7",],
			"typicalBinary02" => ["G5rvXS77ghH2SORaT1Qc9R5VpWo=", "\x1b\x9a\xef\x5d\x2e\xfb\x82\x11\xf6\x48\xe4\x5a\x4f\x54\x1c\xf5\x1e\x55\xa5\x6a",],
			"typicalBinary03" => ["CMVx5rzVv1EoDCvzefkgDgpeXLELCRee/9aVsX+SPKE=", "\x08\xc5\x71\xe6\xbc\xd5\xbf\x51\x28\x0c\x2b\xf3\x79\xf9\x20\x0e\x0a\x5e\x5c\xb1\x0b\x09\x17\x9e\xff\xd6\x95\xb1\x7f\x92\x3c\xa1",],
			"typicalBinary04" => ["qmOsQGILzN7NdemBiybK/VeZs36me7lLSiPPNC/QzGM=", "\xaa\x63\xac\x40\x62\x0b\xcc\xde\xcd\x75\xe9\x81\x8b\x26\xca\xfd\x57\x99\xb3\x7e\xa6\x7b\xb9\x4b\x4a\x23\xcf\x34\x2f\xd0\xcc\x63",],
			"typicalBinary05" => ["XXIivSsCdFF+4jWJCOtCU/ocRGw1ba/S4PdkgweobA4GTg+70VsHRuQ9nDcBB3NpJlO9Y1bKwRiJbw0q+0HtRA==", "\x5d\x72\x22\xbd\x2b\x02\x74\x51\x7e\xe2\x35\x89\x08\xeb\x42\x53\xfa\x1c\x44\x6c\x35\x6d\xaf\xd2\xe0\xf7\x64\x83\x07\xa8\x6c\x0e\x06\x4e\x0f\xbb\xd1\x5b\x07\x46\xe4\x3d\x9c\x37\x01\x07\x73\x69\x26\x53\xbd\x63\x56\xca\xc1\x18\x89\x6f\x0d\x2a\xfb\x41\xed\x44",],
			"typicalBinary06" => ["idAW1Zg1781N6wLpDBkz4GqLsp380xUwXwbIY8s0q0GTxzkWOJZFltTB8T56mv/OtQZWrYSv7GCRrcZlt/59lA==", "\x89\xd0\x16\xd5\x98\x35\xef\xcd\x4d\xeb\x02\xe9\x0c\x19\x33\xe0\x6a\x8b\xb2\x9d\xfc\xd3\x15\x30\x5f\x06\xc8\x63\xcb\x34\xab\x41\x93\xc7\x39\x16\x38\x96\x45\x96\xd4\xc1\xf1\x3e\x7a\x9a\xff\xce\xb5\x06\x56\xad\x84\xaf\xec\x60\x91\xad\xc6\x65\xb7\xfe\x7d\x94",],
			"typicalBinary07" => ["Xb8Vl3cXq5THpzDWi3C2Lwa2yss=", "\x5d\xbf\x15\x97\x77\x17\xab\x94\xc7\xa7\x30\xd6\x8b\x70\xb6\x2f\x06\xb6\xca\xcb",],
			"typicalBinary08" => ["sQJ0oy8IzHH+VC9JK261t/ZDhXCMGuLelJzSEyTsjDc=", "\xb1\x02\x74\xa3\x2f\x08\xcc\x71\xfe\x54\x2f\x49\x2b\x6e\xb5\xb7\xf6\x43\x85\x70\x8c\x1a\xe2\xde\x94\x9c\xd2\x13\x24\xec\x8c\x37",],
			"invalidJustTooShortAscii" => ["IWZpZnRlZW4tYnl0ZXMh", "!fifteen-bytes!", InvalidSecretException::class,],
			"invalidJustTooShortBinary" => ["EHJHM3DRWtet7jizSJ9r", "\x10\x72\x47\x33\x70\xd1\x5a\xd7\xad\xee\x38\xb3\x48\x9f\x6b", InvalidSecretException::class,],
			"invalidJustTooShortNullBinary" => ["AAAAAAAAAAAAAAAAAAAA", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", InvalidSecretException::class,],
			"invalidNonBase64Characters" => ["_HJHM3DRWtet7jizSJ9r", "", InvalidBase64DataException::class,],
			"invalidBadBase64" => ["cGFzc3dvcmQtcGFzc3dvcmQ", "", InvalidBase64DataException::class,],
			"invalidNull" => [null, "", TypeError::class],
			"invalidStringable" => [new class implements Stringable {
				public function __toString(): string
				{
					return "cGFzc3dvcmQtcGFzc3dvcmQ=";
				}
			}, "", TypeError::class],
			"invalidArray" => [["cGFzc3dvcmQtcGFzc3dvcmQ=",], "", TypeError::class],
			"invalidInt" => [16, "", TypeError::class],
			"invalidFloat" => [1234567890123456.789, "", TypeError::class],
			"invalidTrue" => [true, "", TypeError::class],
			"invalidFalse" => [false, "", TypeError::class],
		];
	}

	/**
	 * @dataProvider dataForTestFromBase64
	 *
	 * @param mixed $raw
	 * @param string|null $exceptionClass
	 */
	public function testFromBase64(mixed $base64, string $raw, string $exceptionClass = null): void
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$secret = TotpSecret::fromBase64($base64);
		$this->assertEquals($base64, $secret->base64(), "Base64 in TotpSecret is not as expected.");
		$this->assertEquals($raw, $secret->raw(), "Raw bytes in TotpSecret are not as expected.");
	}

	/**
	 * Test data for testRaw().
	 *
	 * @return \Generator
	 * @throws \Exception if random_bytes can't generate secure random data.
	 */
	public function dataForTestRaw(): Generator
	{
		yield from [
			["password-password"],
			["\x10\x72\x47\x33\x70\xd1\x5a\xd7\xad\xee\x38\xb3\x48\x9f\x6b\x23\x3f\x40\x55\x5a",],
			["\xca\x1e\x10\xfa\x3d\x56\x65\xb7\x21\x3c\x36\xb6\x7d\x35\xa5\xa9\xa0\x08\x61\x53",],
			["\x99\x7e\x5e\xb4\x9e\x2e\x13\x5d\x59\xd3\xbf\x22\xa3\x45\xa0\x37\x7c\x0e\x58\xb9\x60\x5a\x09\xcb\xd9\xee\x4d\xc1\x22\xbd\x6d\xfc",],
			["\xb4\x73\x19\xa7\x82\xa0\x95\x91\x96\x61\xd1\x94\x1b\x49\xae\xa5\xc4\x48\x1b\xbb\x38\x5f\x73\xc7\x27\xd1\xae\x78\x2b\xe6\xc9\x82\x2e\x56\xa6\x6a\xc0\xe8\xe6\xde\x36\xaf\x0c\x0c\x5f\x91\xfb\x21\x79\xcb\xfd\x0e\xda\xb3\x31\x8b\x08\xfb\xe5\x33\x3f\x24\xeb\xe0",],
			["\x22\x71\x3e\xa7\xb1\x30\x3c\x28\x33\xe7\xd7\xea\x86\x35\x50\x8a\xf0\x3d\xf2\xff\xb2\xff\x74\x60\x9d\x0d\x3a\x94\xbf\xe0\xc2\x56\x4c\x75\x35\x52\xd5\x25\x5f\x58\xbd\x12\xff\xc9\x61\x31\x98\x0e\xc8\xe5\x20\x51\x9d\x27\x2d\x77\xd9\xca\xfa\xc0\x37\x6f\x02\x85",],
			["\xf9\xee\xee\x58\xa0\x90\xcc\xcf\xda\xa1\x42\x9a\xd9\xd2\x24\x88\x98\xe4\x26\x03\xdd\xb3\xe6\x1a\xeb\x25\x22\x4a\x58\x73\x41\x92",],
			["\x8b\x81\xf7\xb0\xf5\x0a\x2b\x6e\x15\x98\x15\x62\xd6\x92\x73\xf5\x79\xa0\x2f\xdf",],
			["\xfa\xc7\xac\x80\x81\x3d\xf7\x3c\xa7\x8e\xc9\x49\x17\x9b\x52\x64\x89\x79\xe1\x11",],
			["\x8b\xd8\x91\x02\x35\x45\xbb\x16\xbc\x58\x4a\xb6\x73\x14\x3b\x61\xb0\x54\xba\xe7",],
			["\x1b\x9a\xef\x5d\x2e\xfb\x82\x11\xf6\x48\xe4\x5a\x4f\x54\x1c\xf5\x1e\x55\xa5\x6a",],
			["\x08\xc5\x71\xe6\xbc\xd5\xbf\x51\x28\x0c\x2b\xf3\x79\xf9\x20\x0e\x0a\x5e\x5c\xb1\x0b\x09\x17\x9e\xff\xd6\x95\xb1\x7f\x92\x3c\xa1",],
			["\xaa\x63\xac\x40\x62\x0b\xcc\xde\xcd\x75\xe9\x81\x8b\x26\xca\xfd\x57\x99\xb3\x7e\xa6\x7b\xb9\x4b\x4a\x23\xcf\x34\x2f\xd0\xcc\x63",],
			["\x5d\x72\x22\xbd\x2b\x02\x74\x51\x7e\xe2\x35\x89\x08\xeb\x42\x53\xfa\x1c\x44\x6c\x35\x6d\xaf\xd2\xe0\xf7\x64\x83\x07\xa8\x6c\x0e\x06\x4e\x0f\xbb\xd1\x5b\x07\x46\xe4\x3d\x9c\x37\x01\x07\x73\x69\x26\x53\xbd\x63\x56\xca\xc1\x18\x89\x6f\x0d\x2a\xfb\x41\xed\x44",],
			["\x89\xd0\x16\xd5\x98\x35\xef\xcd\x4d\xeb\x02\xe9\x0c\x19\x33\xe0\x6a\x8b\xb2\x9d\xfc\xd3\x15\x30\x5f\x06\xc8\x63\xcb\x34\xab\x41\x93\xc7\x39\x16\x38\x96\x45\x96\xd4\xc1\xf1\x3e\x7a\x9a\xff\xce\xb5\x06\x56\xad\x84\xaf\xec\x60\x91\xad\xc6\x65\xb7\xfe\x7d\x94",],
			["\x5d\xbf\x15\x97\x77\x17\xab\x94\xc7\xa7\x30\xd6\x8b\x70\xb6\x2f\x06\xb6\xca\xcb",],
			["\xb1\x02\x74\xa3\x2f\x08\xcc\x71\xfe\x54\x2f\x49\x2b\x6e\xb5\xb7\xf6\x43\x85\x70\x8c\x1a\xe2\xde\x94\x9c\xd2\x13\x24\xec\x8c\x37",],
		];

		for ($idx = 0; $idx < 100; ++$idx) {
			$bytes = mt_rand(16, 64);
			yield [random_bytes($bytes),];
		}
	}
	
	/**
	 * @dataProvider dataForTestRaw
	 *
	 * @param string $raw The raw secret.
	 */
	public function testRaw(string $raw): void
	{
		$secret = TotpSecret::fromRaw($raw);
		$this->assertEquals($raw, $secret->raw(), "The secret did not contain the expected raw bytes.");
	}
	
	/**
	 * Test data for base32()
	 * 
	 * @return \string[][]
	 */
	public function dataForTestBase32(): array
	{
		return [
			["password-password", "OBQXG43XN5ZGILLQMFZXG53POJSA====",],
			["\x10\x72\x47\x33\x70\xd1\x5a\xd7\xad\xee\x38\xb3\x48\x9f\x6b\x23\x3f\x40\x55\x5a", "CBZEOM3Q2FNNPLPOHCZURH3LEM7UAVK2",],
			["\xca\x1e\x10\xfa\x3d\x56\x65\xb7\x21\x3c\x36\xb6\x7d\x35\xa5\xa9\xa0\x08\x61\x53", "ZIPBB6R5KZS3OIJ4G23H2NNFVGQAQYKT",],
			["\x99\x7e\x5e\xb4\x9e\x2e\x13\x5d\x59\xd3\xbf\x22\xa3\x45\xa0\x37\x7c\x0e\x58\xb9\x60\x5a\x09\xcb\xd9\xee\x4d\xc1\x22\xbd\x6d\xfc", "TF7F5NE6FYJV2WOTX4RKGRNAG56A4WFZMBNATS6Z5ZG4CIV5NX6A====",],
			["\xb4\x73\x19\xa7\x82\xa0\x95\x91\x96\x61\xd1\x94\x1b\x49\xae\xa5\xc4\x48\x1b\xbb\x38\x5f\x73\xc7\x27\xd1\xae\x78\x2b\xe6\xc9\x82\x2e\x56\xa6\x6a\xc0\xe8\xe6\xde\x36\xaf\x0c\x0c\x5f\x91\xfb\x21\x79\xcb\xfd\x0e\xda\xb3\x31\x8b\x08\xfb\xe5\x33\x3f\x24\xeb\xe0", "WRZRTJ4CUCKZDFTB2GKBWSNOUXCEQG53HBPXHRZH2GXHQK7GZGBC4VVGNLAORZW6G2XQYDC7SH5SC6OL7UHNVMZRRMEPXZJTH4SOXYA=",],
			["\x22\x71\x3e\xa7\xb1\x30\x3c\x28\x33\xe7\xd7\xea\x86\x35\x50\x8a\xf0\x3d\xf2\xff\xb2\xff\x74\x60\x9d\x0d\x3a\x94\xbf\xe0\xc2\x56\x4c\x75\x35\x52\xd5\x25\x5f\x58\xbd\x12\xff\xc9\x61\x31\x98\x0e\xc8\xe5\x20\x51\x9d\x27\x2d\x77\xd9\xca\xfa\xc0\x37\x6f\x02\x85", "EJYT5J5RGA6CQM7H27VIMNKQRLYD34X7WL7XIYE5BU5JJP7AYJLEY5JVKLKSKX2YXUJP7SLBGGMA5SHFEBIZ2JZNO7M4V6WAG5XQFBI=",],
			["\xf9\xee\xee\x58\xa0\x90\xcc\xcf\xda\xa1\x42\x9a\xd9\xd2\x24\x88\x98\xe4\x26\x03\xdd\xb3\xe6\x1a\xeb\x25\x22\x4a\x58\x73\x41\x92", "7HXO4WFASDGM7WVBIKNNTURERCMOIJQD3WZ6MGXLEUREUWDTIGJA====",],
			["\x8b\x81\xf7\xb0\xf5\x0a\x2b\x6e\x15\x98\x15\x62\xd6\x92\x73\xf5\x79\xa0\x2f\xdf", "ROA7PMHVBIVW4FMYCVRNNETT6V42AL67",],
			["\xfa\xc7\xac\x80\x81\x3d\xf7\x3c\xa7\x8e\xc9\x49\x17\x9b\x52\x64\x89\x79\xe1\x11", "7LD2ZAEBHX3TZJ4OZFERPG2SMSEXTYIR",],
		];
	}

	/**
	 * @dataProvider dataForTestBase32
	 *
	 * @param string $raw The raw secret.
	 * @param string $expectedBase32 The expected return value from base32().
	 */
	public function testBase32(string $raw, string $expectedBase32): void
	{
		$secret = TotpSecret::fromRaw($raw);
		$this->assertEquals($expectedBase32, $secret->base32(), "The base32 provided by the TotpSecret object is not the same as the expected base32.");
	}
	
	/**
	 * Test data for base64()
	 * 
	 * @return \string[][]
	 */
	public function dataForTestBase64(): array
	{
		return [
			["password-password", "cGFzc3dvcmQtcGFzc3dvcmQ=",],
			["\x8b\xd8\x91\x02\x35\x45\xbb\x16\xbc\x58\x4a\xb6\x73\x14\x3b\x61\xb0\x54\xba\xe7", "i9iRAjVFuxa8WEq2cxQ7YbBUuuc=",],
			["\x1b\x9a\xef\x5d\x2e\xfb\x82\x11\xf6\x48\xe4\x5a\x4f\x54\x1c\xf5\x1e\x55\xa5\x6a", "G5rvXS77ghH2SORaT1Qc9R5VpWo=",],
			["\x08\xc5\x71\xe6\xbc\xd5\xbf\x51\x28\x0c\x2b\xf3\x79\xf9\x20\x0e\x0a\x5e\x5c\xb1\x0b\x09\x17\x9e\xff\xd6\x95\xb1\x7f\x92\x3c\xa1", "CMVx5rzVv1EoDCvzefkgDgpeXLELCRee/9aVsX+SPKE=",],
			["\xaa\x63\xac\x40\x62\x0b\xcc\xde\xcd\x75\xe9\x81\x8b\x26\xca\xfd\x57\x99\xb3\x7e\xa6\x7b\xb9\x4b\x4a\x23\xcf\x34\x2f\xd0\xcc\x63", "qmOsQGILzN7NdemBiybK/VeZs36me7lLSiPPNC/QzGM=",],
			["\x5d\x72\x22\xbd\x2b\x02\x74\x51\x7e\xe2\x35\x89\x08\xeb\x42\x53\xfa\x1c\x44\x6c\x35\x6d\xaf\xd2\xe0\xf7\x64\x83\x07\xa8\x6c\x0e\x06\x4e\x0f\xbb\xd1\x5b\x07\x46\xe4\x3d\x9c\x37\x01\x07\x73\x69\x26\x53\xbd\x63\x56\xca\xc1\x18\x89\x6f\x0d\x2a\xfb\x41\xed\x44", "XXIivSsCdFF+4jWJCOtCU/ocRGw1ba/S4PdkgweobA4GTg+70VsHRuQ9nDcBB3NpJlO9Y1bKwRiJbw0q+0HtRA==",],
			["\x89\xd0\x16\xd5\x98\x35\xef\xcd\x4d\xeb\x02\xe9\x0c\x19\x33\xe0\x6a\x8b\xb2\x9d\xfc\xd3\x15\x30\x5f\x06\xc8\x63\xcb\x34\xab\x41\x93\xc7\x39\x16\x38\x96\x45\x96\xd4\xc1\xf1\x3e\x7a\x9a\xff\xce\xb5\x06\x56\xad\x84\xaf\xec\x60\x91\xad\xc6\x65\xb7\xfe\x7d\x94", "idAW1Zg1781N6wLpDBkz4GqLsp380xUwXwbIY8s0q0GTxzkWOJZFltTB8T56mv/OtQZWrYSv7GCRrcZlt/59lA==",],
			["\x5d\xbf\x15\x97\x77\x17\xab\x94\xc7\xa7\x30\xd6\x8b\x70\xb6\x2f\x06\xb6\xca\xcb", "Xb8Vl3cXq5THpzDWi3C2Lwa2yss=",],
			["\xb1\x02\x74\xa3\x2f\x08\xcc\x71\xfe\x54\x2f\x49\x2b\x6e\xb5\xb7\xf6\x43\x85\x70\x8c\x1a\xe2\xde\x94\x9c\xd2\x13\x24\xec\x8c\x37", "sQJ0oy8IzHH+VC9JK261t/ZDhXCMGuLelJzSEyTsjDc=",],
		];
	}

	/**
	 * @dataProvider dataForTestBase64
	 *
	 * @param string $raw The raw secret.
	 * @param string $expectedBase64 The expected return value from base64().
	 */
	public function testBase64(string $raw, string $expectedBase64): void
	{
		$secret = TotpSecret::fromRaw($raw);
		$this->assertEquals($expectedBase64, $secret->base64(), "The base64 provided by the TotpSecret object is not the same as the expected base64.");
	}
}