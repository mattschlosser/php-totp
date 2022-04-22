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

use Equit\Totp\Base32;
use Equit\Totp\Exceptions\InvalidBase32DataException;
use Equit\Totp\Tests\Framework\TestCase;
use Error;

/**
 * Test case for the Base32 codec.
 */
class Base32Test extends TestCase
{
	/**
	 * Data provider for testConstructor()
	 *
	 * @return array
	 */
	public function dataForTestConstructor(): array
	{
		return [
			"typicalData" => ["test-data-to-encode",],
			"typicalBinaryData" => ["\xff\xfe\xfd\xfc\xfb\xfa\xf8\xf7",],
			"extremeEmptyData" => ["",],
			"invalidNullData" => [null, Error::class],
			"invalidStringableData" => [self::createStringable("test-data-to-encode"), Error::class,],
		];
	}

	/**
	 * Test the Base32 codec constructor.
	 *
	 * @dataProvider dataForTestConstructor
	 *
	 * @param mixed $plainData
	 * @param class-string|null $exceptionClass
	 */
	public function testConstructor(mixed $plainData, ?string $exceptionClass = null)
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$actual = new Base32($plainData);

		if (!isset($exceptionClass)) {
			$this->assertSame($plainData, $actual->raw());
		}
	}

	/**
	 * Data provider for testSetPlain()
	 *
	 * @return array
	 */
	public function dataForTestSetRaw(): array
	{
		return $this->dataForTestConstructor();
	}

	/**
	 * Test setting plain data for a Base32 codec.
	 *
	 * @dataProvider dataForTestSetRaw
	 *
	 * @param mixed $plainData
	 * @param string|null $exceptionClass
	 */
	public function testSetRaw(mixed $plainData, ?string $exceptionClass = null)
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$base32 = new Base32("");
		$base32->setRaw($plainData);

		if (!isset($exceptionClass)) {
			$actual = $base32->raw();
			$this->assertSame($plainData, $actual);
		}
	}

	/**
	 * Data provider for testSetEncoded().
	 *
	 * @return array
	 */
	public function dataForTestSetEncoded(): array
	{
		return [
			"typicalAsciiData" => ["ORSXG5BNMRQXIYJNORXS2ZLOMNXWIZI=",],
			"typicalMixedData" => ["ORSXG5BN74WW22LYMVSC3ABNMRQXIYJNAAWXI3ZNR4WWK3TDN5SGKCQK",],
			"typicalBinaryData" => ["777P37H37L4PO===",],
			"typicalPNGImageData" => [
				"RFIE4RYNBINAUAAAAAGUSSCEKIAAAABAAAAAAIAIAYAAAADTPJ5PIAAAAACHGQSJKQEAQCAIPQEGJCAAAAAAS4CILFZQAAAAQMAAAAEDAFRO7O22AAAAAGLUIVMHIU3PMZ2HOYLSMUAHO53XFZUW423TMNQXAZJON5ZGPG7OHQNAAAAACF2EKWDUKRUXI3DFADBYS4LVNF2CATDPM5XR6D3RQAAAAAATORCVQ5CBOV2GQ33SABCGC4TSMVXCARLEMFWGKSVV67KQAAAAHJ2EKWDUIRSXGY3SNFYHI2LPNYAEG6LBNY5CAIZUGFRGEYZTBJGWCZ3FNZ2GCORAENRTCNBTMNRAUWLFNRWG65Z2EARWGYLDGE2DHPJIMBXAAAAAC52EKWDUINZGKYLUNFXW4ICUNFWWKACKOVWHSIBSGAYTPJO7NY7AAAAGE5EUIQKULCC6LF6LR5OEOFOGX7XVJ5PNLP6ZRHVHA7NWG3ADREJBXS4AEKIIYDFREUWLDSAGFFEEQIDWVQIX6BKCBB3LAZILL2AAILDMIWHDGCZQREKMSUIUMNPLNQZEGOJXS6F2PO5OXPVKB2FZTNS3MZTDYSFT4NEFPOSVFKO66557HKTUVFYAODW4NXJGLU4ZCD73ZVUMJWKAU4BAPWSULE4SDHKGHAKSNDGYKRN55OT54XFDVRTCOHY7EXFKZFK2CTVJJIAYTHSKJ7IIOKTESWSYPCSHVR6GF2UDLJDXWFZP3YOPBWUNXPG4UDRGMOM3WA6FBETUVJ4EKOCZ66742WPV77ZWAMALZ6PGVO3CT4SDSAHEUT5IA7UA7ASACTPZZNK3S2XJZCGDYOEX64L2NIQY6ZP57WWV5NRR6OTQKAEPAAQAKFQAHGE2QHVCKASQQBNCIASQECQYNOACVIFSCEIAXICC3FSZJZ62XYVX4YL24LCOOO6N2OH7HESUXJMBL3MR7UIWQKOUQF2IQ4FAHICR3IAOKGOFFHKCTWYSNNMVHIYDVCDVIXEJX5RQ4KJ2T3N43RXJ26TDMVW7LY3BAYIM5CERCGADCRVAOAFAKSJAFIHOXBB5ZSPHP46K7T7KHFMVFTCBUCAHYKC7QFCARSEAM5KQAXCZEEEJEE7RJBD5T34BOOVNQULTWEZHFTCFLCFVEXX2W56XW6ZEZI3ZWICXSZLKZFCLWM7T4VRQI42QOKIXVWO5PDTVCUNODYEGCDYSH7PWTHJYH423S4DHOXR7DQ7B6BYTHMNNV5GE7H742LGFJZ6O7LR2ODUIJBT7VFPZMH775BWPH3XEFVJH6WMTAPP3WXH2ZLP44FPEJOJPQTWCPDQY3UF63ZXRQ7N4H3E7YNQQQRG2F6VNV7L6X6OK2J7NCOGVUYYESCSKOWYA2PGC7ELRU4MIW7GDSRKZPNR6H56VAYO27XCELWDIRBUU3VWAK7TWOZYUJCRGUXMIGRVEYTRFVY2QE4HNXE2EM3YBHJIMCCFICCQ5VNWWXJLECDXXFNGPXX7CHPRYJUQIICZFNZWF5IYK6IWUNJKI3AESVQBOQRYA7FYLS3BUH2NQE4AAGGBBBYY2EFNRUKGU5XLR2VUFRHWIUISGU6CKHUTFGHLIOII2BWUD6GQMOIUKRBAIFBFFVCAZRQAIU3FFT6TAWSJ5TVX6LWJKACRFNH5SIZOCH45L5PAN4LJKRTATEYSTRG45DF2T5FDK35VP72QPYXF3HGZ6AXP6N7XULQEUEJXKUZRZ3TLHWTZOQIWP5NO7PUXWWTK6NC54NGJ2ZCOS5WH46MNGGSCVVBIMLMYQKHSUHK5WXSCUUPQNOJ5FZHAK65A3OWYRDIXEYTOMTSPZVKAVKFVQSBNH3PXBPXZZPWVDPUT74UNW65G7P3V4VD52DNX76VDILB3Z6YW2HCNVJFKPIB22HGQYQ6ECC3S2QRNQJAGXP6RWNLL57MKFS2YGEMRKURSMSBIEII3CMSTJ4JDHU7N63GRQXTOHF33557GJSZPMCF3647DTUJLJLZ3CUQ4XN7FV4MYKTLD67DVQOIQ2MIYFCRCDGQQZMONXF5OZ2WJCV6D334X4P4CQCQC7K5ZXX3OOVENE2MYYSHEGQLENTG7NZGOL77IRX5UWZJJEIRCUYLKIL5DP457HMLQBWBE3FWGN2MALAAFABPAAE2EONGWO5TXPDF3PD4XC3TRMMO67G7LJYVCVA4G44AEOUKGXVJ3W3LLWUBKRCEIWSRDQXUDTSPVZXH7NWY6XMZ7QEYDFG7HQFAA7AD4AXAAOQCL4MNFO57HO6DNAJF5JLAEDYIVQSUKFKRAKTBGRSJQEMYFHPJ3Y5D7G23O7454Z5IX4OAGG4OHQAIUAOO56757WLDZRJQFIJQCYTHQKICARDRDOW4KDBTFAKBZAOAVACBYOXC75C4APY7MPTTFXQ2XZGKAN4HTLYYOBALKE5ERRLYYQQQFEICSQOMIACCUQAAMA2RAKZFFXWUHCYODELBEHACRMIOAEBAYZMBOABTKAUIDWEBUCCWSWAI6REABFHWR6EWIIFUAQL4S22OKKVSGIDWVNUZBNCXBUFDOGUMABBEC6JGHQQD6CRPJCXYIB7CZF65I3M5O52OSTVDBNXDRJLMXTKE4QIVG6ISCOGGFRAMQYWPR7UM2ONS65W63Y5TV5GL467TLPZCLKDAG2Q2PPQPA4NRFZ426OE2A4WBQOKEMAXUQPY4V67HI66PTZX57CZGMCUCIS7ZY2RKIGMH3HH2QR37ZTPIAOBRYAWLO7CDIAN7QYAA7IBGAAUPDDQX6SBKRMEA6PEALYOJF4NMSXNGC3EGWLKMBBQB623Z6Z532AVTQMKAQHIE6NXIVCRIVIJI6ZAJJU6BRBF7YL6QREQL7JCADUWTLFXF2CKDQ5AEA24PTKLGKLJNDQCIAXN5PBZTG242LKSJ4DLDA2XQHPCRTMRHTNKEJWKW4J7MY5UX7RHKH2IDP7AOG4DXTD2EPVDSYAAAAAASKFJZCK4QTAQI======",
			],
			"extremeEmptyData" => ["",],
			"extremeAllValidCharacters" => ["ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",],
			"invalidStringData" => ["ORSXG5BNMRQXIYJNORXS2ZLOMNXWIZi=", InvalidBase32DataException::class,],
			"invalidBinaryData" => ["\xff\xfe\xfd\xfc\xfb\xfa\xf8\xf7", InvalidBase32DataException::class,],
			"invalidNonStringData" => [null, Error::class],
			"invalidStringableData" => [self::createStringable("ORSXG5BNMRQXIYJNORXS2ZLOMNXWIZI="), Error::class,],
			"invalidMixedData" => ["ORSXG5BN74WW22LYMVSC3ABNMRQXIYJNAAWXI3ZNR4WWK3TDN5SGKCQk", InvalidBase32DataException::class,],
			"invalidPaddedData" => ["777P37H37L4PO==", InvalidBase32DataException::class,],
			"invalidPNGImageData" => [
				"RFIE4RYNBINAUAAAAAGUSSCEKIAAAABAAAAAAIAIAYAAAADTPJ5PIAAAAACHGQSJKQEAQCAIPQEGJCAAAAAAS4CILFZQAAAAQMAAAAEDAFRO7O22AAAAAGLUIVMHIU3PMZ2HOYLSMUAHO53XFZUW423TMNQXAZJON5ZGPG7OHQNAAAAACF2EKWDUKRUXI3DFADBYS4LVNF2CATDPM5XR6D3RQAAAAAATORCVQ5CBOV2GQ33SABCGC4TSMVXCARLEMFWGKSVV67KQAAAAHJ2EKWDUIRSXGY3SNFYHI2LPNYAEG6LBNY5CAIZUGFRGEYZTBJGWCZ3FNZ2GCORAENRTCNBTMNRAUWLFNRWG65Z2EARWGYLDGE2DHPJIMBXAAAAAC52EKWDUINZGKYLUNFXW4ICUNFWWKACKOVWHSIBSGAYTPJO7NY7AAAAGE5EUIQKULCC6LF6LR5OEOFOGX7XVJ5PNLP6ZRHVHA7NWG3ADREJBXS4AEKIIYDFREUWLDSAGFFEEQIDWVQIX6BKCBB3LAZILL2AAILDMIWHDGCZQREKMSUIUMNPLNQZEGOJXS6F2PO5OXPVKB2FZTNS3MZTDYSFT4NEFPOSVFKO66557HKTUVFYAODW4NXJGLU4ZCD73ZVUMJWKAU4BAPWSULE4SDHKGHAKSNDGYKRN55OT54XFDVRTCOHY7EXFKZFK2CTVJJIAYTHSKJ7IIOKTESWSYPCSHVR6GF2UDLJDXWFZP3YOPBWUNXPG4UDRGMOM3WA6FBETUVJ4EKOCZ66742WPV77ZWAMALZ6PGVO3CT4SDSAHEUT5IA7UA7ASACTPZZNK3S2XJZCGDYOEX64L2NIQY6ZP57WWV5NRR6OTQKAEPAAQAKFQAHGE2QHVCKASQQBNCIASQECQYNOACVIFSCEIAXICC3FSZJZ62XYVX4YL24LCOOO6N2OH7HESUXJMBL3MR7UIWQKOUQF2IQ4FAHICR3IAOKGOFFHKCTWYSNNMVHIYDVCDVIXEJX5RQ4KJ2T3N43RXJ26TDMVW7LY3BAYIM5CERCGADCRVAOAFAKSJAFIHOXBB5ZSPHP46K7T7KHFMVFTCBUCAHYKC7QFCARSEAM5KQAXCZEEEJEE7RJBD5T34BOOVNQULTWEZHFTCFLCFVEXX2W56XW6ZEZI3ZWICXSZLKZFCLWM7T4VRQI42QOKIXVWO5PDTVCUNODYEGCDYSH7PWTHJYH423S4DHOXR7DQ7B6BYTHMNNV5GE7H742LGFJZ6O7LR2ODUIJBT7VFPZMH775BWPH3XEFVJH6WMTAPP3WXH2ZLP44FPEJOJPQTWCPDQY3UF63ZXRQ7N4H3E7YNQQQRG2F6VNV7L6X6OK2J7NCOGVUYYESCSKOWYA2PGC7ELRU4MIW7GDSRKZPNR6H56VAYO27XCELWDIRBUU3VWAK7TWOZYUJCRGUXMIGRVEYTRFVY2QE4HNXE2EM3YBHJIMCCFICCQ5VNWWXJLECDXXFNGPXX7CHPRYJUQIICZFNZWF5IYK6IWUNJKI3AESVQBOQRYA7FYLS3BUH2NQE4AAGGBBBYY2EFNRUKGU5XLR2VUFRHWIUISGU6CKHUTFGHLIOII2BWUD6GQMOIUKRBAIFBFFVCAZRQAIU3FFT6TAWSJ5TVX6LWJKACRFNH5SIZOCH45L5PAN4LJKRTATEYSTRG45DF2T5FDK35VP72QPYXF3HGZ6AXP6N7XULQEUEJXKUZRZ3TLHWTZOQIWP5NO7PUXWWTK6NC54NGJ2ZCOS5WH46MNGGSCVVBIMLMYQKHSUHK5WXSCUUPQNOJ5FZHAK65A3OWYRDIXEYTOMTSPZVKAVKFVQSBNH3PXBPXZZPWVDPUT74UNW65G7P3V4VD52DNX76VDILB3Z6YW2HCNVJFKPIB22HGQYQ6ECC3S2QRNQJAGXP6RWNLL57MKFS2YGEMRKURSMSBIEII3CMSTJ4JDHU7N63GRQXTOHF33557GJSZPMCF3647DTUJLJLZ3CUQ4XN7FV4MYKTLD67DVQOIQ2MIYFCRCDGQQZMONXF5OZ2WJCV6D334X4P4CQCQC7K5ZXX3OOVENE2MYYSHEGQLENTG7NZGOL77IRX5UWZJJEIRCUYLKIL5DP457HMLQBWBE3FWGN2MALAAFABPAAE2EONGWO5TXPDF3PD4XC3TRMMO67G7LJYVCVA4G44AEOUKGXVJ3W3LLWUBKRCEIWSRDQXUDTSPVZXH7NWY6XMZ7QEYDFG7HQFAA7AD4AXAAOQCL4MNFO57HO6DNAJF5JLAEDYIVQSUKFKRAKTBGRSJQEMYFHPJ3Y5D7G23O7454Z5IX4OAGG4OHQAIUAOO56757WLDZRJQFIJQCYTHQKICARDRDOW4KDBTFAKBZAOAVACBYOXC75C4APY7MPTTFXQ2XZGKAN4HTLYYOBALKE5ERRLYYQQQFEICSQOMIACCUQAAMA2RAKZFFXWUHCYODELBEHACRMIOAEBAYZMBOABTKAUIDWEBUCCWSWAI6REABFHWR6EWIIFUAQL4S22OKKVSGIDWVNUZBNCXBUFDOGUMABBEC6JGHQQD6CRPJCXYIB7CZF65I3M5O52OSTVDBNXDRJLMXTKE4QIVG6ISCOGGFRAMQYWPR7UM2ONS65W63Y5TV5GL467TLPZCLKDAG2Q2PPQPA4NRFZ426OE2A4WBQOKEMAXUQPY4V67HI66PTZX57CZGMCUCIS7ZY2RKIGMH3HH2QR37ZTPIAOBRYAWLO7CDIAN7QYAA7IBGAAUPDDQX6SBKRMEA6PEALYOJF4NMSXNGC3EGWLKMBBQB623Z6Z532AVTQMKAQHIE6NXIVCRIVIJI6ZAJJU6BRBF7YL6QREQL7JCADUWTLFXF2CKDQ5AEA24PTKLGKLJNDQCIAXN5PBZTG242LKSJ4DLDA2XQHPCRTMRHTNKEJWKW4J7MY5UX7RHKH2IDP7AOG4DXTD2EPVDSYAAAAAASKFJZCK4QTAQi======",
				InvalidBase32DataException::class,
			],
		];
	}

	/**
	 * Test setting encoded data for a Base32 codec.
	 *
	 * @dataProvider dataForTestSetEncoded
	 *
	 * @param mixed $encodedData
	 * @param string|null $exceptionClass
	 */
	public function testSetEncoded(mixed $encodedData, ?string $exceptionClass = null)
	{
		$base32Codec = new Base32();

		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$base32Codec->setEncoded($encodedData);

		if (!isset($exceptionClass)) {
			$this->assertSame($encodedData, $base32Codec->encoded());
		}
	}

	/**
	 * Data provider for testEncoding().
	 *
	 * @return array
	 */
	public function dataForTestEncoding(): array
	{
		return [
			"typicalAsciiData" => ["test-data-to-encode", "ORSXG5BNMRQXIYJNORXS2ZLOMNXWIZI=",],
			"typicalMixedData" => ["test-\xff-mixed-\x80-data-\x00-to-\x8f-encode\n\n", "ORSXG5BN74WW22LYMVSC3ABNMRQXIYJNAAWXI3ZNR4WWK3TDN5SGKCQK",],
			"typicalBinaryData" => ["\xff\xfe\xfd\xfc\xfb\xfa\xf8\xf7", "777P37H37L4PO===",],
			"typicalPNGImageData" => [
				"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x20\x00\x00\x00\x20\x08\x06\x00\x00\x00\x73\x7a\x7a\xf4\x00\x00\x00\x04\x73\x42\x49\x54\x08\x08\x08\x08\x7c\x08\x64\x88\x00\x00\x00\x09\x70\x48\x59\x73\x00\x00\x00\x83\x00\x00\x00\x83\x01\x62\xef\xbb\x5a\x00\x00\x00\x19\x74\x45\x58\x74\x53\x6f\x66\x74\x77\x61\x72\x65\x00\x77\x77\x77\x2e\x69\x6e\x6b\x73\x63\x61\x70\x65\x2e\x6f\x72\x67\x9b\xee\x3c\x1a\x00\x00\x00\x11\x74\x45\x58\x74\x54\x69\x74\x6c\x65\x00\xc3\x89\x71\x75\x69\x74\x20\x4c\x6f\x67\x6f\x1f\x0f\x71\x80\x00\x00\x00\x13\x74\x45\x58\x74\x41\x75\x74\x68\x6f\x72\x00\x44\x61\x72\x72\x65\x6e\x20\x45\x64\x61\x6c\x65\x4a\xb5\xf7\xd5\x00\x00\x00\x3a\x74\x45\x58\x74\x44\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x00\x43\x79\x61\x6e\x3a\x20\x23\x34\x31\x62\x62\x63\x33\x0a\x4d\x61\x67\x65\x6e\x74\x61\x3a\x20\x23\x63\x31\x34\x33\x63\x62\x0a\x59\x65\x6c\x6c\x6f\x77\x3a\x20\x23\x63\x61\x63\x31\x34\x33\xbd\x28\x60\x6e\x00\x00\x00\x17\x74\x45\x58\x74\x43\x72\x65\x61\x74\x69\x6f\x6e\x20\x54\x69\x6d\x65\x00\x4a\x75\x6c\x79\x20\x32\x30\x31\x37\xa5\xdf\x6e\x3e\x00\x00\x06\x27\x49\x44\x41\x54\x58\x85\xe5\x97\xcb\x8f\x5c\x47\x15\xc6\xbf\xef\x54\xf5\xed\x5b\xfd\x98\x9e\xa7\x07\xdb\x63\x6c\x03\x89\x12\x1b\xcb\x80\x22\x90\x8c\x0c\xb1\x25\x2c\xb1\xc8\x06\x29\x48\x48\x20\x76\xac\x11\x7f\x05\x42\x08\x76\xb0\x65\x0b\x5e\x80\x04\x2c\x6c\x45\x8e\x33\x0b\x30\x89\x14\xc9\x51\x14\x63\x5e\xb6\xc3\x24\x33\x93\x79\x78\xba\x7b\xba\xeb\xbe\xaa\x0e\x8b\x99\xb6\x5b\x66\x66\x3c\x48\xb3\xe3\x48\x57\xba\x55\x2a\x9d\xef\x77\xbf\x3a\xa7\x4a\x97\x00\x70\xed\xc6\xdd\x26\x5d\x39\x91\x0f\xfb\xcd\x68\xc4\xd9\x40\xa7\x02\x07\xda\x54\x59\x39\x21\x9d\x46\x38\x15\x26\x8c\xd8\x54\x5b\xde\xba\x7d\xe5\xca\x3a\xc6\x62\x71\xf1\xf2\x5c\xaa\xc9\x55\xa1\x4e\xa9\x4a\x01\x89\x9e\x4a\x4f\xd0\x87\x2a\x64\x95\xa5\x87\x8a\x47\xac\x7c\x62\xea\x83\x5a\x47\x7b\x17\x2f\xde\x1c\xf0\xda\x8d\xbb\xcd\xca\x0e\x26\x63\x99\xbb\x03\xc5\x09\x27\x4a\xa7\x84\x53\x85\x9f\x7b\xfc\xd5\x9f\x5f\xff\x36\x03\x00\xbc\xf9\xe6\xab\xb6\x29\xf2\x43\x90\x0e\x4a\x4f\xa8\x07\xe8\x0f\x82\x40\x14\xdf\x9c\xb5\x5b\x96\xae\x9c\x88\xc3\xc3\x89\x7f\x71\x7a\x6a\x21\x8f\x65\xfd\xfd\xad\x5e\xb6\x31\xf3\xa7\x05\x00\x8f\x00\x20\x05\x16\x00\x39\x89\xa8\x1e\xa2\x50\x25\x08\x05\xa2\x40\x25\x02\x0a\x18\x6b\x80\x2a\xa0\xb2\x11\x10\x0b\xa0\x42\xd9\x65\x94\xe7\xda\xbe\x2b\x7e\x61\x7a\xe2\xc4\xe7\x3b\xcd\xd3\x8f\xf3\x92\x54\xba\x58\x15\xed\x91\xfd\x11\x68\x29\xd4\x81\x74\x88\x70\xa0\x3a\x05\x1d\xa0\x0e\x51\x9c\x52\x9d\x42\x9d\xb1\x26\xb5\x95\x3a\x30\x3a\x88\x75\x45\xc8\x9b\xf6\x30\xe2\x93\xa9\xed\xbc\xdc\x6e\x9d\x7a\x63\x65\x6d\xf5\xe3\x61\x06\x10\xce\x88\x91\x11\x80\x31\x46\xa0\x70\x0a\x05\x49\x20\x2a\x0e\xeb\x84\x3d\xcc\x9e\x77\xf3\xca\xfc\xfe\xa3\x95\x95\x2c\xc4\x1a\x08\x07\xc2\x85\xf8\x14\x40\x8c\x88\x06\x75\x50\x05\xc5\x92\x10\x89\x21\x3f\x14\x84\x7d\x9e\xf8\x17\x3a\xad\x85\x17\x3b\x13\x27\x2c\xc4\x55\x88\xb5\x25\xef\xab\x77\xd7\xb7\xb2\x4c\xa3\x79\xb2\x05\x79\x65\x6a\xc9\x44\xbb\x33\xf3\xe5\x63\x04\x73\x50\x72\x91\x7a\xd9\xdd\x78\xe7\x51\x51\xae\x1e\x08\x61\x0f\x12\x3f\xdf\x69\x9d\x38\x3f\x35\xb9\x70\x67\x75\xe3\xf1\xc3\xe1\xf0\x71\x33\xb1\xad\xaf\x4c\x4f\x9f\xfc\xd2\xcc\x54\xe7\xce\xfa\xe3\xa7\x0e\x88\x48\x67\xfa\x95\xf9\x61\xff\xfe\x86\xcf\x3e\xee\x42\xd5\x27\xf5\x99\x30\x3d\xfb\xb5\xcf\xac\xad\xfc\xe1\x5e\x44\xb9\x2f\x84\xec\x27\x8e\x18\xdd\x0b\xed\xe6\xf1\x87\xdb\xc3\xec\x9f\xc3\x61\x08\x44\xda\x2f\xaa\xda\xfd\x7e\xbf\x9c\xad\x27\xed\x13\x8d\x5a\x63\x04\x90\xa4\xa7\x5b\x00\xd3\xcc\x2f\x91\x71\xa7\x18\x8b\x7c\xc3\x94\x55\x97\xb6\x3e\x3f\x7d\x50\x61\xda\xfd\xc4\x45\xd8\x68\x88\x69\x4d\xd6\xc0\x57\xe7\x67\x67\x14\x48\xa2\x6a\x5d\x88\x34\x6a\x4c\x4e\x25\xae\x35\x02\x70\xed\xb9\x34\x46\x6f\x01\x3a\x50\xc1\x08\xa8\x10\xa1\xda\xb6\xd6\xba\x56\x41\x0e\xf7\x2b\x4c\xfb\xdf\xe2\x3b\xe3\x84\xd2\x08\x40\xb2\x56\xe6\xc5\xea\x30\xaf\x22\xd4\x6a\x54\x8d\x80\x92\xac\x02\xe8\x47\x00\xf9\x70\xb9\x6c\x34\x3e\x9b\x02\x70\x00\x31\x82\x10\xe3\x1a\x21\x5b\x1a\x28\xd4\xed\xd7\x1d\x56\x85\x89\xec\x8a\x22\x46\xa7\x84\xa3\xd2\x65\x31\xd6\x87\x21\x1a\x0d\xa8\x3f\x1a\x0c\x72\x28\xa8\x84\x08\x28\x4a\x5a\x88\x19\x8c\x00\x8a\x6c\xa5\x9f\xa6\x0b\x49\x3d\x9d\x6f\xe5\xd9\x2a\x00\xa2\x56\x9f\xb2\x46\x5c\x23\xf3\xab\xeb\xc0\xde\x2d\x2a\x8c\xc1\x32\x62\x53\x89\xb9\xd1\x97\x53\xe9\x46\xad\xf6\xaf\xfe\xa0\xfc\x5c\xbb\x39\xb3\xe0\x5d\xfe\x6f\xef\x45\xc0\x94\x22\x6e\xaa\x66\x39\xdc\xd6\x7b\x4f\x2e\x82\x2c\xfe\xb5\xdf\x7d\x2f\x6b\x4d\x5e\x68\xbb\xc6\x99\x3a\xc8\x9d\x2e\xd8\xfc\xf3\x1a\x63\x48\x55\xa8\x50\xc5\xb3\x10\x51\xe5\x43\xab\xb6\xbc\x85\x4a\x3e\x0d\x72\x7a\x5c\x9c\x0a\xf7\x41\xb7\x5b\x11\x1a\x2e\x4c\x4d\xcc\x9c\x9f\x9a\xa8\x15\x51\x6b\x09\x05\xa7\xdb\xee\x17\xdf\x39\x7d\xaa\x37\xd2\x7f\xe5\x1b\x6f\x74\xdf\x7e\xeb\xca\x8f\xba\x1b\x6f\xff\x54\x68\x58\x77\x9f\x62\xda\x38\x9b\x54\x95\x4f\x40\x75\xa3\x9a\x18\x87\x88\x21\x6e\x5a\x84\x5b\x04\x80\xd7\x7f\xa3\x66\xad\x7d\xfb\x14\x59\x6b\x06\x23\x22\xaa\x46\x4c\x90\x50\x44\x23\x62\x64\xa6\x9e\x24\x67\xa7\xdb\xed\x9a\x30\xbc\xdc\x72\xef\x7d\xef\xcc\x99\x65\xec\x11\x77\xee\x7c\x73\xa2\x56\x95\xe7\x62\xa4\x39\x76\xfc\xb5\xe3\x30\xa9\xac\x7e\xf8\xeb\x07\x22\x1a\x62\x30\x51\x44\x43\x34\x21\x96\x39\xb7\x2f\x5d\x9d\x59\x22\xaf\x87\xbd\xf2\xfc\x7f\x05\x01\x40\x5f\x57\x73\x7b\xed\xce\xa9\x1a\x4d\x33\x18\x91\xc8\x68\x2c\x8d\x99\xbe\xdc\x99\xcb\xff\xd1\x1b\xf6\x96\xca\x52\x44\x44\x54\xc2\xd4\x85\xf4\x6f\xe7\x7e\x76\x2e\x01\xb0\x49\xb2\xd8\xcd\xd3\x00\xb0\x00\xa0\x0b\xc0\x02\x68\x8e\x69\xac\xee\xce\xef\x19\x76\xf1\xf2\xe2\xdc\xe2\xc6\x3b\xdf\x37\xd6\x9c\x54\x55\x07\x0d\xce\x00\x8e\xa2\x8d\x7a\xa7\x76\xda\xd7\x6a\x05\x51\x11\x11\x69\x44\x70\xbd\x07\x39\x3e\xb9\xb9\xfe\xdb\x63\xd7\x66\x7f\x02\x60\x65\x37\xcf\x02\x80\x1f\x00\xf8\x0b\x80\x0e\x80\x97\xc6\x34\xae\xef\xce\xef\x0d\xa0\x49\x7a\x95\x80\x83\xc2\x2b\x09\x51\x45\x54\x40\xa9\x84\xd1\x92\x60\x46\x60\xa7\x7a\x77\x8e\x8f\xe6\xd6\xdd\xfe\x77\x99\xea\x2f\xc7\x00\xc6\xe3\x8f\x00\x22\x80\x73\xbb\xef\xf7\xf6\x58\xf3\x14\xc0\xa8\x4c\x05\x89\x9e\x0a\x40\x81\x11\xc4\x6e\xb7\x14\x30\xcc\xa0\x50\x72\x07\x02\xa0\x10\x70\xeb\x8b\xfd\x17\x00\xfc\x7d\x8f\x9c\xcb\x78\x6a\xf9\x32\x80\xde\x1e\x6b\xc6\x1c\x10\x2d\x44\xe9\x23\x15\xe3\x10\x84\x0a\x44\x0a\x50\x73\x10\x01\x0a\x90\x00\x18\x0d\x44\x0a\xc9\x4b\x7b\x50\xe2\xc3\x86\x45\x84\x87\x00\xa2\xc4\x38\x04\x08\x31\x96\x05\xc0\x0c\xd4\x0a\x20\x76\x20\x68\x21\x5a\x56\x02\x3d\x12\x00\x25\x3d\xa3\xe2\x59\x08\x2d\x01\x05\xf2\x5a\xd3\x94\xaa\xc8\xc8\x1d\xaa\xda\x64\x2d\x15\xc3\x42\x8d\xc6\xa3\x00\x10\x90\x5e\x49\x8f\x08\x0f\xc2\x8b\xd2\x2b\xe1\x01\xf8\xb2\x5f\x75\x1b\x67\x5d\xdd\x3a\x53\xa8\xc2\xdb\x8e\x29\x5b\x2f\x35\x13\x90\x45\x4d\xe4\x48\x4e\x31\x8b\x10\x32\x18\xb3\xe3\xfa\x33\x4e\x6c\xbd\xdb\x7b\x78\xec\xeb\xd3\x2f\x9e\xfc\xd6\xfc\x89\x6a\x18\x0d\xa8\x69\xef\x83\xc1\xc6\xc4\xb9\xe6\xbc\xe2\x68\x1c\xb0\x60\xe5\x11\x80\xbd\x20\xfc\x72\xbe\xf9\xd1\xef\x3e\x79\xbf\x7e\x2c\x99\x82\xa0\x91\x2f\xe7\x1a\x8a\x90\x66\x1f\x67\x3e\xa1\x1d\xff\x33\x7a\x00\xe0\xc7\x00\xb2\xdd\xf1\x0d\x00\x6f\xe1\x80\x03\xe8\x09\x80\x0a\x3c\x63\x85\xfd\x20\xaa\x2c\x20\x3c\xf2\x01\x78\x72\x4b\xc6\xb2\x57\x69\x85\xb2\x1a\xcb\x53\x02\x18\x07\xda\xde\x7d\x9e\xef\x40\xac\xe0\xc5\x02\x07\x41\x3c\xdb\xa2\xa2\x8a\x2a\x84\xa3\xd9\x02\x53\x4f\x06\x21\x2f\xf0\xbf\x42\x24\x82\xfe\x91\x00\x74\xb4\xd6\x5b\x97\x42\x50\xe1\xd0\x10\x1a\xe3\xe6\xa5\x99\x4b\x4b\x47\x01\x20\x17\x6f\x5e\x1c\xcc\xda\xe6\x96\xa9\x27\x83\x58\xc1\xab\xc0\xef\x14\x66\xc8\x9e\x6d\x51\x13\x65\x5b\x89\xfb\x31\xda\x5f\xf1\x3a\x8f\xa4\x0d\xff\x03\x8d\xc1\xde\x63\xd1\x1f\x51\xcb\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82",
				"RFIE4RYNBINAUAAAAAGUSSCEKIAAAABAAAAAAIAIAYAAAADTPJ5PIAAAAACHGQSJKQEAQCAIPQEGJCAAAAAAS4CILFZQAAAAQMAAAAEDAFRO7O22AAAAAGLUIVMHIU3PMZ2HOYLSMUAHO53XFZUW423TMNQXAZJON5ZGPG7OHQNAAAAACF2EKWDUKRUXI3DFADBYS4LVNF2CATDPM5XR6D3RQAAAAAATORCVQ5CBOV2GQ33SABCGC4TSMVXCARLEMFWGKSVV67KQAAAAHJ2EKWDUIRSXGY3SNFYHI2LPNYAEG6LBNY5CAIZUGFRGEYZTBJGWCZ3FNZ2GCORAENRTCNBTMNRAUWLFNRWG65Z2EARWGYLDGE2DHPJIMBXAAAAAC52EKWDUINZGKYLUNFXW4ICUNFWWKACKOVWHSIBSGAYTPJO7NY7AAAAGE5EUIQKULCC6LF6LR5OEOFOGX7XVJ5PNLP6ZRHVHA7NWG3ADREJBXS4AEKIIYDFREUWLDSAGFFEEQIDWVQIX6BKCBB3LAZILL2AAILDMIWHDGCZQREKMSUIUMNPLNQZEGOJXS6F2PO5OXPVKB2FZTNS3MZTDYSFT4NEFPOSVFKO66557HKTUVFYAODW4NXJGLU4ZCD73ZVUMJWKAU4BAPWSULE4SDHKGHAKSNDGYKRN55OT54XFDVRTCOHY7EXFKZFK2CTVJJIAYTHSKJ7IIOKTESWSYPCSHVR6GF2UDLJDXWFZP3YOPBWUNXPG4UDRGMOM3WA6FBETUVJ4EKOCZ66742WPV77ZWAMALZ6PGVO3CT4SDSAHEUT5IA7UA7ASACTPZZNK3S2XJZCGDYOEX64L2NIQY6ZP57WWV5NRR6OTQKAEPAAQAKFQAHGE2QHVCKASQQBNCIASQECQYNOACVIFSCEIAXICC3FSZJZ62XYVX4YL24LCOOO6N2OH7HESUXJMBL3MR7UIWQKOUQF2IQ4FAHICR3IAOKGOFFHKCTWYSNNMVHIYDVCDVIXEJX5RQ4KJ2T3N43RXJ26TDMVW7LY3BAYIM5CERCGADCRVAOAFAKSJAFIHOXBB5ZSPHP46K7T7KHFMVFTCBUCAHYKC7QFCARSEAM5KQAXCZEEEJEE7RJBD5T34BOOVNQULTWEZHFTCFLCFVEXX2W56XW6ZEZI3ZWICXSZLKZFCLWM7T4VRQI42QOKIXVWO5PDTVCUNODYEGCDYSH7PWTHJYH423S4DHOXR7DQ7B6BYTHMNNV5GE7H742LGFJZ6O7LR2ODUIJBT7VFPZMH775BWPH3XEFVJH6WMTAPP3WXH2ZLP44FPEJOJPQTWCPDQY3UF63ZXRQ7N4H3E7YNQQQRG2F6VNV7L6X6OK2J7NCOGVUYYESCSKOWYA2PGC7ELRU4MIW7GDSRKZPNR6H56VAYO27XCELWDIRBUU3VWAK7TWOZYUJCRGUXMIGRVEYTRFVY2QE4HNXE2EM3YBHJIMCCFICCQ5VNWWXJLECDXXFNGPXX7CHPRYJUQIICZFNZWF5IYK6IWUNJKI3AESVQBOQRYA7FYLS3BUH2NQE4AAGGBBBYY2EFNRUKGU5XLR2VUFRHWIUISGU6CKHUTFGHLIOII2BWUD6GQMOIUKRBAIFBFFVCAZRQAIU3FFT6TAWSJ5TVX6LWJKACRFNH5SIZOCH45L5PAN4LJKRTATEYSTRG45DF2T5FDK35VP72QPYXF3HGZ6AXP6N7XULQEUEJXKUZRZ3TLHWTZOQIWP5NO7PUXWWTK6NC54NGJ2ZCOS5WH46MNGGSCVVBIMLMYQKHSUHK5WXSCUUPQNOJ5FZHAK65A3OWYRDIXEYTOMTSPZVKAVKFVQSBNH3PXBPXZZPWVDPUT74UNW65G7P3V4VD52DNX76VDILB3Z6YW2HCNVJFKPIB22HGQYQ6ECC3S2QRNQJAGXP6RWNLL57MKFS2YGEMRKURSMSBIEII3CMSTJ4JDHU7N63GRQXTOHF33557GJSZPMCF3647DTUJLJLZ3CUQ4XN7FV4MYKTLD67DVQOIQ2MIYFCRCDGQQZMONXF5OZ2WJCV6D334X4P4CQCQC7K5ZXX3OOVENE2MYYSHEGQLENTG7NZGOL77IRX5UWZJJEIRCUYLKIL5DP457HMLQBWBE3FWGN2MALAAFABPAAE2EONGWO5TXPDF3PD4XC3TRMMO67G7LJYVCVA4G44AEOUKGXVJ3W3LLWUBKRCEIWSRDQXUDTSPVZXH7NWY6XMZ7QEYDFG7HQFAA7AD4AXAAOQCL4MNFO57HO6DNAJF5JLAEDYIVQSUKFKRAKTBGRSJQEMYFHPJ3Y5D7G23O7454Z5IX4OAGG4OHQAIUAOO56757WLDZRJQFIJQCYTHQKICARDRDOW4KDBTFAKBZAOAVACBYOXC75C4APY7MPTTFXQ2XZGKAN4HTLYYOBALKE5ERRLYYQQQFEICSQOMIACCUQAAMA2RAKZFFXWUHCYODELBEHACRMIOAEBAYZMBOABTKAUIDWEBUCCWSWAI6REABFHWR6EWIIFUAQL4S22OKKVSGIDWVNUZBNCXBUFDOGUMABBEC6JGHQQD6CRPJCXYIB7CZF65I3M5O52OSTVDBNXDRJLMXTKE4QIVG6ISCOGGFRAMQYWPR7UM2ONS65W63Y5TV5GL467TLPZCLKDAG2Q2PPQPA4NRFZ426OE2A4WBQOKEMAXUQPY4V67HI66PTZX57CZGMCUCIS7ZY2RKIGMH3HH2QR37ZTPIAOBRYAWLO7CDIAN7QYAA7IBGAAUPDDQX6SBKRMEA6PEALYOJF4NMSXNGC3EGWLKMBBQB623Z6Z532AVTQMKAQHIE6NXIVCRIVIJI6ZAJJU6BRBF7YL6QREQL7JCADUWTLFXF2CKDQ5AEA24PTKLGKLJNDQCIAXN5PBZTG242LKSJ4DLDA2XQHPCRTMRHTNKEJWKW4J7MY5UX7RHKH2IDP7AOG4DXTD2EPVDSYAAAAAASKFJZCK4QTAQI======",
			],
			"extremeEmptyData" => ["", "",],
		];
	}

	/**
	 * Test the encoding of plain data to Base32.
	 *
	 * This test receives valid string data and expects the codec to produce the correct encoded data. For a test of the
	 * codec's response to non-string data, see testSetPlain().
	 *
	 * @dataProvider dataForTestEncoding
	 *
	 * @param string $plainData
	 * @param string $expectedEncodedData
	 */
	public function testEncoding(string $plainData, string $expectedEncodedData)
	{
		$base32Codec = new Base32($plainData);
		$actual = $base32Codec->encoded();
		$this->assertSame($expectedEncodedData, $actual, "Base32::encoded() produced unexpected output: expected = {$expectedEncodedData}; actual = {$actual}");
		$actual = Base32::encode($plainData);
		$this->assertSame($expectedEncodedData, $actual, "static Base32::encode() produced unexpected output: expected = {$expectedEncodedData}; actual = {$actual}");
	}

	/**
	 * Data provider for testDecoding()
	 *
	 * @return array
	 */
	public function dataForTestDecoding(): array
	{
		return [
			"typicalAsciiData" => ["ORSXG5BNMRQXIYJNORXS2ZLOMNXWIZI=", "test-data-to-encode",],
			"typicalMixedData" => ["ORSXG5BN74WW22LYMVSC3ABNMRQXIYJNAAWXI3ZNR4WWK3TDN5SGKCQK", "test-\xff-mixed-\x80-data-\x00-to-\x8f-encode\n\n",],
			"typicalBinaryData" => ["777P37H37L4PO===", "\xff\xfe\xfd\xfc\xfb\xfa\xf8\xf7",],
			"typicalPNGImageData" => [
				"RFIE4RYNBINAUAAAAAGUSSCEKIAAAABAAAAAAIAIAYAAAADTPJ5PIAAAAACHGQSJKQEAQCAIPQEGJCAAAAAAS4CILFZQAAAAQMAAAAEDAFRO7O22AAAAAGLUIVMHIU3PMZ2HOYLSMUAHO53XFZUW423TMNQXAZJON5ZGPG7OHQNAAAAACF2EKWDUKRUXI3DFADBYS4LVNF2CATDPM5XR6D3RQAAAAAATORCVQ5CBOV2GQ33SABCGC4TSMVXCARLEMFWGKSVV67KQAAAAHJ2EKWDUIRSXGY3SNFYHI2LPNYAEG6LBNY5CAIZUGFRGEYZTBJGWCZ3FNZ2GCORAENRTCNBTMNRAUWLFNRWG65Z2EARWGYLDGE2DHPJIMBXAAAAAC52EKWDUINZGKYLUNFXW4ICUNFWWKACKOVWHSIBSGAYTPJO7NY7AAAAGE5EUIQKULCC6LF6LR5OEOFOGX7XVJ5PNLP6ZRHVHA7NWG3ADREJBXS4AEKIIYDFREUWLDSAGFFEEQIDWVQIX6BKCBB3LAZILL2AAILDMIWHDGCZQREKMSUIUMNPLNQZEGOJXS6F2PO5OXPVKB2FZTNS3MZTDYSFT4NEFPOSVFKO66557HKTUVFYAODW4NXJGLU4ZCD73ZVUMJWKAU4BAPWSULE4SDHKGHAKSNDGYKRN55OT54XFDVRTCOHY7EXFKZFK2CTVJJIAYTHSKJ7IIOKTESWSYPCSHVR6GF2UDLJDXWFZP3YOPBWUNXPG4UDRGMOM3WA6FBETUVJ4EKOCZ66742WPV77ZWAMALZ6PGVO3CT4SDSAHEUT5IA7UA7ASACTPZZNK3S2XJZCGDYOEX64L2NIQY6ZP57WWV5NRR6OTQKAEPAAQAKFQAHGE2QHVCKASQQBNCIASQECQYNOACVIFSCEIAXICC3FSZJZ62XYVX4YL24LCOOO6N2OH7HESUXJMBL3MR7UIWQKOUQF2IQ4FAHICR3IAOKGOFFHKCTWYSNNMVHIYDVCDVIXEJX5RQ4KJ2T3N43RXJ26TDMVW7LY3BAYIM5CERCGADCRVAOAFAKSJAFIHOXBB5ZSPHP46K7T7KHFMVFTCBUCAHYKC7QFCARSEAM5KQAXCZEEEJEE7RJBD5T34BOOVNQULTWEZHFTCFLCFVEXX2W56XW6ZEZI3ZWICXSZLKZFCLWM7T4VRQI42QOKIXVWO5PDTVCUNODYEGCDYSH7PWTHJYH423S4DHOXR7DQ7B6BYTHMNNV5GE7H742LGFJZ6O7LR2ODUIJBT7VFPZMH775BWPH3XEFVJH6WMTAPP3WXH2ZLP44FPEJOJPQTWCPDQY3UF63ZXRQ7N4H3E7YNQQQRG2F6VNV7L6X6OK2J7NCOGVUYYESCSKOWYA2PGC7ELRU4MIW7GDSRKZPNR6H56VAYO27XCELWDIRBUU3VWAK7TWOZYUJCRGUXMIGRVEYTRFVY2QE4HNXE2EM3YBHJIMCCFICCQ5VNWWXJLECDXXFNGPXX7CHPRYJUQIICZFNZWF5IYK6IWUNJKI3AESVQBOQRYA7FYLS3BUH2NQE4AAGGBBBYY2EFNRUKGU5XLR2VUFRHWIUISGU6CKHUTFGHLIOII2BWUD6GQMOIUKRBAIFBFFVCAZRQAIU3FFT6TAWSJ5TVX6LWJKACRFNH5SIZOCH45L5PAN4LJKRTATEYSTRG45DF2T5FDK35VP72QPYXF3HGZ6AXP6N7XULQEUEJXKUZRZ3TLHWTZOQIWP5NO7PUXWWTK6NC54NGJ2ZCOS5WH46MNGGSCVVBIMLMYQKHSUHK5WXSCUUPQNOJ5FZHAK65A3OWYRDIXEYTOMTSPZVKAVKFVQSBNH3PXBPXZZPWVDPUT74UNW65G7P3V4VD52DNX76VDILB3Z6YW2HCNVJFKPIB22HGQYQ6ECC3S2QRNQJAGXP6RWNLL57MKFS2YGEMRKURSMSBIEII3CMSTJ4JDHU7N63GRQXTOHF33557GJSZPMCF3647DTUJLJLZ3CUQ4XN7FV4MYKTLD67DVQOIQ2MIYFCRCDGQQZMONXF5OZ2WJCV6D334X4P4CQCQC7K5ZXX3OOVENE2MYYSHEGQLENTG7NZGOL77IRX5UWZJJEIRCUYLKIL5DP457HMLQBWBE3FWGN2MALAAFABPAAE2EONGWO5TXPDF3PD4XC3TRMMO67G7LJYVCVA4G44AEOUKGXVJ3W3LLWUBKRCEIWSRDQXUDTSPVZXH7NWY6XMZ7QEYDFG7HQFAA7AD4AXAAOQCL4MNFO57HO6DNAJF5JLAEDYIVQSUKFKRAKTBGRSJQEMYFHPJ3Y5D7G23O7454Z5IX4OAGG4OHQAIUAOO56757WLDZRJQFIJQCYTHQKICARDRDOW4KDBTFAKBZAOAVACBYOXC75C4APY7MPTTFXQ2XZGKAN4HTLYYOBALKE5ERRLYYQQQFEICSQOMIACCUQAAMA2RAKZFFXWUHCYODELBEHACRMIOAEBAYZMBOABTKAUIDWEBUCCWSWAI6REABFHWR6EWIIFUAQL4S22OKKVSGIDWVNUZBNCXBUFDOGUMABBEC6JGHQQD6CRPJCXYIB7CZF65I3M5O52OSTVDBNXDRJLMXTKE4QIVG6ISCOGGFRAMQYWPR7UM2ONS65W63Y5TV5GL467TLPZCLKDAG2Q2PPQPA4NRFZ426OE2A4WBQOKEMAXUQPY4V67HI66PTZX57CZGMCUCIS7ZY2RKIGMH3HH2QR37ZTPIAOBRYAWLO7CDIAN7QYAA7IBGAAUPDDQX6SBKRMEA6PEALYOJF4NMSXNGC3EGWLKMBBQB623Z6Z532AVTQMKAQHIE6NXIVCRIVIJI6ZAJJU6BRBF7YL6QREQL7JCADUWTLFXF2CKDQ5AEA24PTKLGKLJNDQCIAXN5PBZTG242LKSJ4DLDA2XQHPCRTMRHTNKEJWKW4J7MY5UX7RHKH2IDP7AOG4DXTD2EPVDSYAAAAAASKFJZCK4QTAQI======",
				"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x20\x00\x00\x00\x20\x08\x06\x00\x00\x00\x73\x7a\x7a\xf4\x00\x00\x00\x04\x73\x42\x49\x54\x08\x08\x08\x08\x7c\x08\x64\x88\x00\x00\x00\x09\x70\x48\x59\x73\x00\x00\x00\x83\x00\x00\x00\x83\x01\x62\xef\xbb\x5a\x00\x00\x00\x19\x74\x45\x58\x74\x53\x6f\x66\x74\x77\x61\x72\x65\x00\x77\x77\x77\x2e\x69\x6e\x6b\x73\x63\x61\x70\x65\x2e\x6f\x72\x67\x9b\xee\x3c\x1a\x00\x00\x00\x11\x74\x45\x58\x74\x54\x69\x74\x6c\x65\x00\xc3\x89\x71\x75\x69\x74\x20\x4c\x6f\x67\x6f\x1f\x0f\x71\x80\x00\x00\x00\x13\x74\x45\x58\x74\x41\x75\x74\x68\x6f\x72\x00\x44\x61\x72\x72\x65\x6e\x20\x45\x64\x61\x6c\x65\x4a\xb5\xf7\xd5\x00\x00\x00\x3a\x74\x45\x58\x74\x44\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x00\x43\x79\x61\x6e\x3a\x20\x23\x34\x31\x62\x62\x63\x33\x0a\x4d\x61\x67\x65\x6e\x74\x61\x3a\x20\x23\x63\x31\x34\x33\x63\x62\x0a\x59\x65\x6c\x6c\x6f\x77\x3a\x20\x23\x63\x61\x63\x31\x34\x33\xbd\x28\x60\x6e\x00\x00\x00\x17\x74\x45\x58\x74\x43\x72\x65\x61\x74\x69\x6f\x6e\x20\x54\x69\x6d\x65\x00\x4a\x75\x6c\x79\x20\x32\x30\x31\x37\xa5\xdf\x6e\x3e\x00\x00\x06\x27\x49\x44\x41\x54\x58\x85\xe5\x97\xcb\x8f\x5c\x47\x15\xc6\xbf\xef\x54\xf5\xed\x5b\xfd\x98\x9e\xa7\x07\xdb\x63\x6c\x03\x89\x12\x1b\xcb\x80\x22\x90\x8c\x0c\xb1\x25\x2c\xb1\xc8\x06\x29\x48\x48\x20\x76\xac\x11\x7f\x05\x42\x08\x76\xb0\x65\x0b\x5e\x80\x04\x2c\x6c\x45\x8e\x33\x0b\x30\x89\x14\xc9\x51\x14\x63\x5e\xb6\xc3\x24\x33\x93\x79\x78\xba\x7b\xba\xeb\xbe\xaa\x0e\x8b\x99\xb6\x5b\x66\x66\x3c\x48\xb3\xe3\x48\x57\xba\x55\x2a\x9d\xef\x77\xbf\x3a\xa7\x4a\x97\x00\x70\xed\xc6\xdd\x26\x5d\x39\x91\x0f\xfb\xcd\x68\xc4\xd9\x40\xa7\x02\x07\xda\x54\x59\x39\x21\x9d\x46\x38\x15\x26\x8c\xd8\x54\x5b\xde\xba\x7d\xe5\xca\x3a\xc6\x62\x71\xf1\xf2\x5c\xaa\xc9\x55\xa1\x4e\xa9\x4a\x01\x89\x9e\x4a\x4f\xd0\x87\x2a\x64\x95\xa5\x87\x8a\x47\xac\x7c\x62\xea\x83\x5a\x47\x7b\x17\x2f\xde\x1c\xf0\xda\x8d\xbb\xcd\xca\x0e\x26\x63\x99\xbb\x03\xc5\x09\x27\x4a\xa7\x84\x53\x85\x9f\x7b\xfc\xd5\x9f\x5f\xff\x36\x03\x00\xbc\xf9\xe6\xab\xb6\x29\xf2\x43\x90\x0e\x4a\x4f\xa8\x07\xe8\x0f\x82\x40\x14\xdf\x9c\xb5\x5b\x96\xae\x9c\x88\xc3\xc3\x89\x7f\x71\x7a\x6a\x21\x8f\x65\xfd\xfd\xad\x5e\xb6\x31\xf3\xa7\x05\x00\x8f\x00\x20\x05\x16\x00\x39\x89\xa8\x1e\xa2\x50\x25\x08\x05\xa2\x40\x25\x02\x0a\x18\x6b\x80\x2a\xa0\xb2\x11\x10\x0b\xa0\x42\xd9\x65\x94\xe7\xda\xbe\x2b\x7e\x61\x7a\xe2\xc4\xe7\x3b\xcd\xd3\x8f\xf3\x92\x54\xba\x58\x15\xed\x91\xfd\x11\x68\x29\xd4\x81\x74\x88\x70\xa0\x3a\x05\x1d\xa0\x0e\x51\x9c\x52\x9d\x42\x9d\xb1\x26\xb5\x95\x3a\x30\x3a\x88\x75\x45\xc8\x9b\xf6\x30\xe2\x93\xa9\xed\xbc\xdc\x6e\x9d\x7a\x63\x65\x6d\xf5\xe3\x61\x06\x10\xce\x88\x91\x11\x80\x31\x46\xa0\x70\x0a\x05\x49\x20\x2a\x0e\xeb\x84\x3d\xcc\x9e\x77\xf3\xca\xfc\xfe\xa3\x95\x95\x2c\xc4\x1a\x08\x07\xc2\x85\xf8\x14\x40\x8c\x88\x06\x75\x50\x05\xc5\x92\x10\x89\x21\x3f\x14\x84\x7d\x9e\xf8\x17\x3a\xad\x85\x17\x3b\x13\x27\x2c\xc4\x55\x88\xb5\x25\xef\xab\x77\xd7\xb7\xb2\x4c\xa3\x79\xb2\x05\x79\x65\x6a\xc9\x44\xbb\x33\xf3\xe5\x63\x04\x73\x50\x72\x91\x7a\xd9\xdd\x78\xe7\x51\x51\xae\x1e\x08\x61\x0f\x12\x3f\xdf\x69\x9d\x38\x3f\x35\xb9\x70\x67\x75\xe3\xf1\xc3\xe1\xf0\x71\x33\xb1\xad\xaf\x4c\x4f\x9f\xfc\xd2\xcc\x54\xe7\xce\xfa\xe3\xa7\x0e\x88\x48\x67\xfa\x95\xf9\x61\xff\xfe\x86\xcf\x3e\xee\x42\xd5\x27\xf5\x99\x30\x3d\xfb\xb5\xcf\xac\xad\xfc\xe1\x5e\x44\xb9\x2f\x84\xec\x27\x8e\x18\xdd\x0b\xed\xe6\xf1\x87\xdb\xc3\xec\x9f\xc3\x61\x08\x44\xda\x2f\xaa\xda\xfd\x7e\xbf\x9c\xad\x27\xed\x13\x8d\x5a\x63\x04\x90\xa4\xa7\x5b\x00\xd3\xcc\x2f\x91\x71\xa7\x18\x8b\x7c\xc3\x94\x55\x97\xb6\x3e\x3f\x7d\x50\x61\xda\xfd\xc4\x45\xd8\x68\x88\x69\x4d\xd6\xc0\x57\xe7\x67\x67\x14\x48\xa2\x6a\x5d\x88\x34\x6a\x4c\x4e\x25\xae\x35\x02\x70\xed\xb9\x34\x46\x6f\x01\x3a\x50\xc1\x08\xa8\x10\xa1\xda\xb6\xd6\xba\x56\x41\x0e\xf7\x2b\x4c\xfb\xdf\xe2\x3b\xe3\x84\xd2\x08\x40\xb2\x56\xe6\xc5\xea\x30\xaf\x22\xd4\x6a\x54\x8d\x80\x92\xac\x02\xe8\x47\x00\xf9\x70\xb9\x6c\x34\x3e\x9b\x02\x70\x00\x31\x82\x10\xe3\x1a\x21\x5b\x1a\x28\xd4\xed\xd7\x1d\x56\x85\x89\xec\x8a\x22\x46\xa7\x84\xa3\xd2\x65\x31\xd6\x87\x21\x1a\x0d\xa8\x3f\x1a\x0c\x72\x28\xa8\x84\x08\x28\x4a\x5a\x88\x19\x8c\x00\x8a\x6c\xa5\x9f\xa6\x0b\x49\x3d\x9d\x6f\xe5\xd9\x2a\x00\xa2\x56\x9f\xb2\x46\x5c\x23\xf3\xab\xeb\xc0\xde\x2d\x2a\x8c\xc1\x32\x62\x53\x89\xb9\xd1\x97\x53\xe9\x46\xad\xf6\xaf\xfe\xa0\xfc\x5c\xbb\x39\xb3\xe0\x5d\xfe\x6f\xef\x45\xc0\x94\x22\x6e\xaa\x66\x39\xdc\xd6\x7b\x4f\x2e\x82\x2c\xfe\xb5\xdf\x7d\x2f\x6b\x4d\x5e\x68\xbb\xc6\x99\x3a\xc8\x9d\x2e\xd8\xfc\xf3\x1a\x63\x48\x55\xa8\x50\xc5\xb3\x10\x51\xe5\x43\xab\xb6\xbc\x85\x4a\x3e\x0d\x72\x7a\x5c\x9c\x0a\xf7\x41\xb7\x5b\x11\x1a\x2e\x4c\x4d\xcc\x9c\x9f\x9a\xa8\x15\x51\x6b\x09\x05\xa7\xdb\xee\x17\xdf\x39\x7d\xaa\x37\xd2\x7f\xe5\x1b\x6f\x74\xdf\x7e\xeb\xca\x8f\xba\x1b\x6f\xff\x54\x68\x58\x77\x9f\x62\xda\x38\x9b\x54\x95\x4f\x40\x75\xa3\x9a\x18\x87\x88\x21\x6e\x5a\x84\x5b\x04\x80\xd7\x7f\xa3\x66\xad\x7d\xfb\x14\x59\x6b\x06\x23\x22\xaa\x46\x4c\x90\x50\x44\x23\x62\x64\xa6\x9e\x24\x67\xa7\xdb\xed\x9a\x30\xbc\xdc\x72\xef\x7d\xef\xcc\x99\x65\xec\x11\x77\xee\x7c\x73\xa2\x56\x95\xe7\x62\xa4\x39\x76\xfc\xb5\xe3\x30\xa9\xac\x7e\xf8\xeb\x07\x22\x1a\x62\x30\x51\x44\x43\x34\x21\x96\x39\xb7\x2f\x5d\x9d\x59\x22\xaf\x87\xbd\xf2\xfc\x7f\x05\x01\x40\x5f\x57\x73\x7b\xed\xce\xa9\x1a\x4d\x33\x18\x91\xc8\x68\x2c\x8d\x99\xbe\xdc\x99\xcb\xff\xd1\x1b\xf6\x96\xca\x52\x44\x44\x54\xc2\xd4\x85\xf4\x6f\xe7\x7e\x76\x2e\x01\xb0\x49\xb2\xd8\xcd\xd3\x00\xb0\x00\xa0\x0b\xc0\x02\x68\x8e\x69\xac\xee\xce\xef\x19\x76\xf1\xf2\xe2\xdc\xe2\xc6\x3b\xdf\x37\xd6\x9c\x54\x55\x07\x0d\xce\x00\x8e\xa2\x8d\x7a\xa7\x76\xda\xd7\x6a\x05\x51\x11\x11\x69\x44\x70\xbd\x07\x39\x3e\xb9\xb9\xfe\xdb\x63\xd7\x66\x7f\x02\x60\x65\x37\xcf\x02\x80\x1f\x00\xf8\x0b\x80\x0e\x80\x97\xc6\x34\xae\xef\xce\xef\x0d\xa0\x49\x7a\x95\x80\x83\xc2\x2b\x09\x51\x45\x54\x40\xa9\x84\xd1\x92\x60\x46\x60\xa7\x7a\x77\x8e\x8f\xe6\xd6\xdd\xfe\x77\x99\xea\x2f\xc7\x00\xc6\xe3\x8f\x00\x22\x80\x73\xbb\xef\xf7\xf6\x58\xf3\x14\xc0\xa8\x4c\x05\x89\x9e\x0a\x40\x81\x11\xc4\x6e\xb7\x14\x30\xcc\xa0\x50\x72\x07\x02\xa0\x10\x70\xeb\x8b\xfd\x17\x00\xfc\x7d\x8f\x9c\xcb\x78\x6a\xf9\x32\x80\xde\x1e\x6b\xc6\x1c\x10\x2d\x44\xe9\x23\x15\xe3\x10\x84\x0a\x44\x0a\x50\x73\x10\x01\x0a\x90\x00\x18\x0d\x44\x0a\xc9\x4b\x7b\x50\xe2\xc3\x86\x45\x84\x87\x00\xa2\xc4\x38\x04\x08\x31\x96\x05\xc0\x0c\xd4\x0a\x20\x76\x20\x68\x21\x5a\x56\x02\x3d\x12\x00\x25\x3d\xa3\xe2\x59\x08\x2d\x01\x05\xf2\x5a\xd3\x94\xaa\xc8\xc8\x1d\xaa\xda\x64\x2d\x15\xc3\x42\x8d\xc6\xa3\x00\x10\x90\x5e\x49\x8f\x08\x0f\xc2\x8b\xd2\x2b\xe1\x01\xf8\xb2\x5f\x75\x1b\x67\x5d\xdd\x3a\x53\xa8\xc2\xdb\x8e\x29\x5b\x2f\x35\x13\x90\x45\x4d\xe4\x48\x4e\x31\x8b\x10\x32\x18\xb3\xe3\xfa\x33\x4e\x6c\xbd\xdb\x7b\x78\xec\xeb\xd3\x2f\x9e\xfc\xd6\xfc\x89\x6a\x18\x0d\xa8\x69\xef\x83\xc1\xc6\xc4\xb9\xe6\xbc\xe2\x68\x1c\xb0\x60\xe5\x11\x80\xbd\x20\xfc\x72\xbe\xf9\xd1\xef\x3e\x79\xbf\x7e\x2c\x99\x82\xa0\x91\x2f\xe7\x1a\x8a\x90\x66\x1f\x67\x3e\xa1\x1d\xff\x33\x7a\x00\xe0\xc7\x00\xb2\xdd\xf1\x0d\x00\x6f\xe1\x80\x03\xe8\x09\x80\x0a\x3c\x63\x85\xfd\x20\xaa\x2c\x20\x3c\xf2\x01\x78\x72\x4b\xc6\xb2\x57\x69\x85\xb2\x1a\xcb\x53\x02\x18\x07\xda\xde\x7d\x9e\xef\x40\xac\xe0\xc5\x02\x07\x41\x3c\xdb\xa2\xa2\x8a\x2a\x84\xa3\xd9\x02\x53\x4f\x06\x21\x2f\xf0\xbf\x42\x24\x82\xfe\x91\x00\x74\xb4\xd6\x5b\x97\x42\x50\xe1\xd0\x10\x1a\xe3\xe6\xa5\x99\x4b\x4b\x47\x01\x20\x17\x6f\x5e\x1c\xcc\xda\xe6\x96\xa9\x27\x83\x58\xc1\xab\xc0\xef\x14\x66\xc8\x9e\x6d\x51\x13\x65\x5b\x89\xfb\x31\xda\x5f\xf1\x3a\x8f\xa4\x0d\xff\x03\x8d\xc1\xde\x63\xd1\x1f\x51\xcb\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82",
			],
			"extremeEmptyData" => ["", "",],
		];
	}

	/**
	 * Test the decoding of Base32 data to plain.
	 *
	 * This test receives valid base32-encoded data and the codec is expected to produce the correct decoded data. For
	 * a test of the codec's ability to identify invalid encoded data, see testSetEncoded().
	 *
	 * @dataProvider dataForTestDecoding
	 *
	 * @param string $encodedData
	 * @param string|null $expectedPlainData
	 * @param class-string|null $exceptionClass
	 */
	public function testDecoding(string $encodedData, string | null $expectedPlainData, string | null $exceptionClass = null)
	{
		$base32Codec = new Base32();

		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$base32Codec->setEncoded($encodedData);
		$actual = $base32Codec->raw();
		$this->assertSame($expectedPlainData, $actual, "Base32::plain() produced unexpected output: expected = {$expectedPlainData}; actual = {$actual}");
		$actual = Base32::decode($encodedData);
		$this->assertSame($expectedPlainData, $actual, "static Base32::decode() produced unexpected output: expected = {$expectedPlainData}; actual = {$actual}");
	}
}
