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

namespace Equit\Totp\Tests;

use BadMethodCallException;
use Equit\Totp\Codecs\Base32;
use Equit\Totp\Contracts\Renderer;
use Equit\Totp\Exceptions\UrlGenerator\InvalidUserException;
use Equit\Totp\Exceptions\UrlGenerator\UnsupportedReferenceTimeException;
use Equit\Totp\Exceptions\UrlGenerator\UnsupportedRendererException;
use Equit\Totp\Factory;
use Equit\Totp\Tests\Framework\Exceptions\InvalidOtpUrlException;
use Equit\Totp\Tests\Framework\TestCase;
use Equit\Totp\UrlGenerator;
use Generator;
use InvalidArgumentException;
use TypeError;

/**
 * Test for the UrlGenerator class.
 */
class UrlGeneratorTest extends TestCase
{
    /**
     * Seed data for random issuers.
     */
    protected const Issuers = [
        "Equit", "BadPun", "NomadIT", "BugSnag", "Linode", "Amazon AWS", "IBM", "Microsoft", "Azure", "Amazon",
        "Apple Inc", "Linux Foundation", "RAI", "The British Library", "Sainsbury", "J. Sainsbury", "Tesco", "Waitrose", "Asda", "Aldi",
        "Cheadle Royal", "EASA", "EASST", "Royal Anthropological Institute", "Namecheap", "GoDaddy!", "Fortinet", "Sentry", "MailGun", "MailChimp",
        "Laravel", "Symfony", "Packagist", "GitHub", "GitLab", "Jira", "BitBucket", "Confluence", "Subversion", "Mercurial",
    ];

    /**
     * Seed data for random users.
     */
    protected const Users = [
        "darren", "Susan", "clive", "mo.iqbal", "peggy-sue", "Art.Garfunkel", "david", "superuser", "administrator", "COLIN",
        "MARK", "abney", "Abbey", "abi", "sami", "Usman", "imran", "urma", "Ootha", "forbes",
        "ruariadh", "conor", "chuck", "Chet", "mowgli", "abu", "Herman", "FRANCOISE", "cortana", "siri",
        "alexa", "mortimer", "zbigniew", "Alasdair", "Michael", "filip", "Sven", "jacqui", "peter", "petra",
    ];

    /**
     * Helper to generate a random issuer string (or null).
     *
     * @param float $nullProbability The probability that the issuer is null. Must be between 0 and 1. Default is 0.1
     * (10% chance of null).
     *
     * @return string|null
     */
    protected static function randomIssuer(float $nullProbability = 0.1): ?string
    {
        return ((10 * $nullProbability) > mt_rand(0, 99) ? null : self::Issuers[mt_rand(0, count(self::Issuers) - 1)]);
    }

    /**
     * Helper to generate a random user string.
     *
     * @return string
     */
    protected static function randomUser(): string
    {
        return self::Users[mt_rand(0, count(self::Users) - 1)];
    }

    /**
     * Test data for testHasIssuer().
     *
     * @return array[]
     */
    public function dataForTestHasIssuer(): array
    {
        return [
            "typical" => ["Equit", true,],
            "typicalNull" => [null, false,],
            "extremeEmpty" => ["", true,],
        ];
    }

    /**
     * @dataProvider dataForTestHasIssuer
     *
     * @param string|null $issuer The issuer to test with.
     * @param bool $expected What hasIssuer() is expected to return.
     *
     * @return void
     */
    public function testHasIssuer(string | null $issuer, bool $expected): void
    {
        $generator = new UrlGenerator();
        $generator->setIssuer($issuer);
        $this->assertEquals($expected,$generator->hasIssuer(), "UrlGenerator did not correctly report that it " . ($expected ? "has" : "does not have") . " an issuer.");
    }

    /**
     * Test data for testHasIssuer().
     *
     * @return Generator
     */
    public function dataForTestIssuer(): Generator
    {
        yield from [
            "typical" => ["Equit",],
            "typicalNull" => [null,],
            "extremeEmpty" => ["",],
        ];

        // 100 random issuers - 10% will be null
        for ($idx = 0; $idx < 100; ++$idx) {
            yield [self::randomIssuer(),];
        }
    }

    /**
     * @dataProvider dataForTestIssuer
     *
     * @param string|null $issuer The issuer to test with.
     *
     * @return void
     */
    public function testIssuer(string | null $issuer): void
    {
        $generator = new UrlGenerator();
        $generator->setIssuer($issuer);
        $this->assertEquals($issuer, $generator->issuer(), "UrlGenerator did not correctly report the issuer.");
    }

    /**
     * Test data for testHasIssuer().
     *
     * @return Generator
     */
    public function dataForTestSetIssuer(): Generator
    {
        yield from [
            "typical" => ["Equit",],
            "typicalNull" => [null,],
            "extremeEmpty" => ["",],
            "invalidInt" => [1, TypeError::class],
            "invalidFloat" => [0.3, TypeError::class],
            "invalidStringable" => [self::createStringable("Equit"), TypeError::class],
            "invalidArray" => [["Equit",], TypeError::class,],
            "invalidTrue" => [["true",], TypeError::class,],
            "invalidFalse" => [["false",], TypeError::class,],
        ];

        // 100 random issuers - 10% will be null
        for ($idx = 0; $idx < 100; ++$idx) {
            yield [self::randomIssuer(),];
        }
    }

    /**
     * @dataProvider dataForTestSetIssuer
     *
     * @param string|null $issuer The issuer to test with.
     */
    public function testSetIssuer(mixed $issuer, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $generator = new UrlGenerator();
        $generator->setIssuer($issuer);
        $this->assertEquals($issuer, $generator->issuer(), "UrlGenerator did not correctly set the issuer.");
    }

    /**
     * Test data for testHasIssuer().
     *
     * @return Generator
     */
    public function dataForTestUser(): Generator
    {
        yield from [
            "typical" => ["darren",],
        ];

        for ($idx = 0; $idx < count(self::Users); ++$idx) {
            yield [self::Users[$idx],];
        }
    }

    /**
     * @dataProvider dataForTestUser
     *
     * @param string $user The user to test with.
     */
    public function testUser(string $user): void
    {
        $generator = new UrlGenerator();
        $generator->setUser($user);
        $this->assertEquals($user, $generator->user(), "UrlGenerator did not correctly report the user.");
    }

    /**
     * Test data for testHasIssuer().
     *
     * @return Generator
     */
    public function dataForTestSetUser(): Generator
    {
        yield from [
            "typical" => ["darren",],
            "invalidNull" => [null, TypeError::class,],
            "invalidEmpty" => ["", InvalidUserException::class,],
            "invalidInt" => [1, TypeError::class],
            "invalidFloat" => [0.3, TypeError::class,],
            "invalidStringable" => [self::createStringable("darren"), TypeError::class,],
            "invalidArray" => [["Equit",], TypeError::class,],
            "invalidTrue" => [["true",], TypeError::class,],
            "invalidFalse" => [["false",], TypeError::class,],
        ];

        for ($idx = 0; $idx < count(self::Users); ++$idx) {
            yield [self::Users[$idx],];
        }
    }

    /**
     * @dataProvider dataForTestSetUser
     *
     * @param mixed $user The user to test with.
     * @param string|null $exceptionClass The class of exception expected to be thrown, if any.
     */
    public function testSetUser(mixed $user, ?string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $generator = new UrlGenerator();
        $generator->setUser($user);
        $this->assertEquals($user, $generator->user(), "UrlGenerator did not correctly set the user.");
    }

    /**
     * Test data for testUrlFor();.
     *
     * @return Generator The test data.
     */
    public function dataForTestUrlFor(): Generator
    {
        yield from [
            "typicalIssuerAndUser" => [
                [
                    "issuer" => "Equit",
                    "user" => "darren",
                ],
                [
                    "secret" => "password-password",
                ],
                "otpauth://totp/Equit:darren/?secret=OBQXG43XN5ZGILLQMFZXG53POJSA====&issuer=Equit",
            ],
            "typicalIssuerAndUserBinarySecret" => [
                [
                    "issuer" => "MailGun",
                    "user" => "darrenedale",
                ],
                [
                    "secret" => "\x10\x72\x47\x33\x70\xd1\x5a\xd7\xad\xee\x38\xb3\x48\x9f\x6b\x23\x3f\x40\x55\x5a",
                ],
                "otpauth://totp/MailGun:darrenedale/?secret=CBZEOM3Q2FNNPLPOHCZURH3LEM7UAVK2&issuer=MailGun",
            ],
            "typicalIssuerAndUrlEncodedUser" => [
                [
                    "issuer" => "BugSnag",
                    "user" => "darren edale",
                ],
                [
                    "secret" => "\xca\x1e\x10\xfa\x3d\x56\x65\xb7\x21\x3c\x36\xb6\x7d\x35\xa5\xa9\xa0\x08\x61\x53",
                ],
                "otpauth://totp/BugSnag:darren+edale/?secret=ZIPBB6R5KZS3OIJ4G23H2NNFVGQAQYKT&issuer=BugSnag",
            ],
            "typicalUrlEncodedIssuerAndUser" => [
                [
                    "issuer" => "Left/Rite",
                    "user" => "darren edale",
                ],
                [
                    "secret" => "\x99\x7e\x5e\xb4\x9e\x2e\x13\x5d\x59\xd3\xbf\x22\xa3\x45\xa0\x37\x7c\x0e\x58\xb9\x60\x5a\x09\xcb\xd9\xee\x4d\xc1\x22\xbd\x6d\xfc",
                ],
                "otpauth://totp/Left%2FRite:darren%20edale/?secret=TF7F5NE6FYJV2WOTX4RKGRNAG56A4WFZMBNATS6Z5ZG4CIV5NX6A====&issuer=Left%2FRite",
            ],
            "typicalDifferentSpaceEncodings" => [
                [
                    "issuer" => "Open Roads",
                    "user" => "darren edale",
                ],
                [
                    "secret" => "\xb4\x73\x19\xa7\x82\xa0\x95\x91\x96\x61\xd1\x94\x1b\x49\xae\xa5\xc4\x48\x1b\xbb\x38\x5f\x73\xc7\x27\xd1\xae\x78\x2b\xe6\xc9\x82\x2e\x56\xa6\x6a\xc0\xe8\xe6\xde\x36\xaf\x0c\x0c\x5f\x91\xfb\x21\x79\xcb\xfd\x0e\xda\xb3\x31\x8b\x08\xfb\xe5\x33\x3f\x24\xeb\xe0",
                ],
                "otpauth://totp/Open%20Roads:darren+edale/?secret=WRZRTJ4CUCKZDFTB2GKBWSNOUXCEQG53HBPXHRZH2GXHQK7GZGBC4VVGNLAORZW6G2XQYDC7SH5SC6OL7UHNVMZRRMEPXZJTH4SOXYA=&issuer=Open+Roads",
            ],
            "typicalIssuerAndUserParamsInDifferentOrder" => [
                [
                    "issuer" => "Dedaleus",
                    "user" => "darren.edale",
                ],
                [
                    "secret" => "password-password",
                ],
                "otpauth://totp/Dedaleus:darren.edale/?issuer=Dedaleus&secret=OBQXG43XN5ZGILLQMFZXG53POJSA====",
            ],
            "typicalUserOnly" => [
                [
                    "user" => "makepeace",
                ],
                [
                    "secret" => "password-password",
                ],
                "otpauth://totp/makepeace/?secret=OBQXG43XN5ZGILLQMFZXG53POJSA====",
            ],
            "typicalDefaltGeneratorWithNonDefaultDigits" => [
                [
                    "user" => "slartibartfast",
                ],
                [
                    "secret" => "password-password",
                    "digits" => 8,
                ],
                "otpauth://totp/slartibartfast/?secret=OBQXG43XN5ZGILLQMFZXG53POJSA====&digits=8",
            ],
            "typicalWithDigitsDefaultDigits" => [
                [
                    "user" => "slartibartfast",
                    "withDigits" => true,
                ],
                [
                    "secret" => "password-password",
                ],
                "otpauth://totp/slartibartfast/?secret=OBQXG43XN5ZGILLQMFZXG53POJSA====&digits=6",
            ],
            "typicalWithDigitsNonDefaultDigits" => [
                [
                    "user" => "slartibartfast",
                    "withDigits" => true,
                ],
                [
                    "secret" => "password-password",
                    "digits" => 8,
                ],
                "otpauth://totp/slartibartfast/?secret=OBQXG43XN5ZGILLQMFZXG53POJSA====&digits=8",
            ],
            "typicalDefaultGeneratorWithNonDefaultAlgorithm" => [
                [
                    "user" => "arthur.dent",
                ],
                [
                    "secret" => "password-password",
                    "hashAlgorithm" => Factory::Sha512Algorithm,
                ],
                "otpauth://totp/arthur.dent/?secret=OBQXG43XN5ZGILLQMFZXG53POJSA====&algorithm=SHA512",
            ],
            "typicalWithAlgorithmDefaultAlgorithm" => [
                [
                    "user" => "arthur.dent",
                    "withAlgorithm" => true,
                ],
                [
                    "secret" => "password-password",
                ],
                "otpauth://totp/arthur.dent/?secret=OBQXG43XN5ZGILLQMFZXG53POJSA====&algorithm=SHA1",
            ],
            "typicalWithAlgorithmNonDefaultAlgorithm" => [
                [
                    "user" => "arthur.dent",
                    "withAlgorithm" => true,
                ],
                [
                    "secret" => "password-password",
                    "hashAlgorithm" => Factory::Sha512Algorithm,
                ],
                "otpauth://totp/arthur.dent/?secret=OBQXG43XN5ZGILLQMFZXG53POJSA====&algorithm=SHA512",
            ],
            "typicalWithPeriodDefaultPeriod" => [
                [
                    "user" => "ford-prefect",
                    "withPeriod" => true,
                ],
                [
                    "secret" => "password-password",
                ],
                "otpauth://totp/ford-prefect/?secret=OBQXG43XN5ZGILLQMFZXG53POJSA====&period=30",
            ],
            "typicalWithPeriodNonDefaultPeriod" => [
                [
                    "user" => "ford-prefect",
                    "withPeriod" => true,
                ],
                [
                    "secret" => "password-password",
                    "time-step" => 20,
                ],
                "otpauth://totp/ford-prefect/?secret=OBQXG43XN5ZGILLQMFZXG53POJSA====&period=20",
            ],
            "typicalDefaultGeneratorWithNonDefaultPeriod" => [
                [
                    "user" => "ford-prefect",
                ],
                [
                    "secret" => "password-password",
                    "time-step" => 20,
                ],
                "otpauth://totp/ford-prefect/?secret=OBQXG43XN5ZGILLQMFZXG53POJSA====&period=20",
            ],
            "invalidEmptyUser" =>[
                [
                    "issuer" => "Equit",
                    "user" => "",
                ],
                [
                    "secret" => "password-password",
                ],
                "",
                InvalidUserException::class,
            ],
            "invalidMissingUser" =>[
                [
                    "issuer" => "Equit",
                ],
                [
                    "secret" => "password-password",
                ],
                "",
                InvalidUserException::class,
            ],
            "invalidNonDefaultTimestamp" =>[
                [
                    "issuer" => "Equit",
                    "user" => "darren",
                ],
                [
                    "secret" => "password-password",
                    "referenceTime" => 60,
                ],
                "",
                UnsupportedReferenceTimeException::class,
            ],
            "invalidIncompatibleRenderer" =>[
                [
                    "issuer" => "Equit",
                    "user" => "darren",
                    "withDigits" => true,
                ],
                [
                    "secret" => "password-password",
                    "renderer" => new class implements Renderer
                    {
                        public function render(string $hmac): string
                        {
                            return "spong";
                        }
                    }
                ],
                "",
                UnsupportedRendererException::class,
            ],
        ];

        // 100 random valid setups
        for ($idx = 0; $idx < 100; ++$idx) {
            $user         = self::randomUser();
            $issuer       = self::randomIssuer();
            $secret       = self::randomValidSecret();
            $base32Secret = Base32::encode($secret);

            $yield = [
                [
                    "issuer" => $issuer,
                    "user" => $user,
                ],
                [
                    "secret" => $secret,
                ],
            ];

            $user = urlencode($user);

            if (isset($issuer)) {
                $issuer = urlencode($issuer);
                $yield[] = "otpauth://totp/{$issuer}:{$user}/?secret={$base32Secret}&issuer={$issuer}";
            } else {
                $yield[] = "otpauth://totp/{$user}/?secret={$base32Secret}";
            }

            yield $yield;
        }
    }

    /**
     * @dataProvider dataForTestUrlFor
     *
     * @param array $urlConfig Configuration for the UrlGenerator to test.
     * @param array $totpConfig Configuration for the Totp to use to test the UrlGenerator.
     * @param string $expectedUrl The URL the generator is expected to produce.
     * @param string|null $exceptionClass The exception that is expected to be thrown, if any.
     *
     * @throws InvalidArgumentException if the renderer in the TOTP config is not valid.
     */
    public function testUrlFor(array $urlConfig, array $totpConfig, string $expectedUrl,  string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $generator = UrlGenerator::from($urlConfig["issuer"] ?? null);

        if (isset($urlConfig["user"])) {
            $generator->setUser($urlConfig["user"]);
        }

        if (isset($totpConfig["renderer"])) {
            $totp = new Factory(secret: $totpConfig["secret"], timeStep: $totpConfig["time-step"] ?? TimeStep::DefaultTimeStep, referenceTime: $totpConfig["referenceTime"] ?? 0, hashAlgorithm: $totpConfig["hashAlgorithm"] ?? Factory::DefaultAlgorithm);

            if (is_string($totpConfig["renderer"])) {
                $totp->withRenderer(new $totpConfig["renderer"]());
            } else if (is_callable($totpConfig["renderer"])) {
                $totp->withRenderer($totpConfig["renderer"]());
            } else if ($totpConfig["renderer"] instanceof Renderer) {
                $totp->withRenderer($totpConfig["renderer"]);
            } else {
                throw new InvalidArgumentException("The renderer provided in the TOTP config is not valid.");
            }
        } else {
            $totp = Factory::integer(digits: $totpConfig["digits"] ?? 6, secret: $totpConfig["secret"], timeStep: $totpConfig["time-step"] ?? TimeStep::DefaultTimeStep, referenceTime: $totpConfig["referenceTime"] ?? 0, hashAlgorithm: $totpConfig["hashAlgorithm"] ?? Factory::DefaultAlgorithm);
        }

        if ($urlConfig["withDigits"] ?? false) {
            $generator->setIncludeDigits(true);
        }

        if ($urlConfig["withPeriod"] ?? false) {
            $generator->setIncludePeriod(true);
        }

        if ($urlConfig["withAlgorithm"] ?? false) {
            $generator->setIncludeAlgorithm(true);
        }
        try {
            $this->assertOtpUrlIsEquivalentTo($expectedUrl, $generator->urlFor($totp));
        } catch (InvalidOtpUrlException $err) {
            $this->fail("The reference OTP URL '{$expectedUrl}' is not valid.");
        }
    }

    /**
     * Test for the protocol() method.
     */
    public function testProtocol(): void
    {
        $generator = new UrlGenerator();
        $this->assertEquals("otpauth", $generator->protocol());
    }

    /**
     * Test for the authenticationType() method.
     */
    public function testAuthenticationType(): void
    {
        $generator = new UrlGenerator();
        $this->assertEquals("totp", $generator->authenticationType());
    }

    /**
     * Test for the includesPeriod() method.
     */
    public function testIncludesPeriod(): void
    {
        $generator = new UrlGenerator();
        $this->assertNull($generator->includesPeriod(), "Default state of includesPeriod property is not as expected.");
        $generator->setIncludePeriod(true);
        $this->assertTrue($generator->includesPeriod(), "includesPeriod property was not true after turning it on.");
        $generator->setIncludePeriod(false);
        $this->assertFalse($generator->includesPeriod(), "includesPeriod property was not false after turning it off.");
        $generator->setIncludePeriod(null);
        $this->assertNull($generator->includesPeriod(), "includesPeriod property was not null after reverting it to the default behaviour.");
    }

    /**
     * Test for the includesPeriod() method.
     */
    public function testIncludesDigits(): void
    {
        $generator = new UrlGenerator();
        $this->assertNull($generator->includesDigits(), "Default state of includesDigits property is not as expected.");
        $generator->setIncludeDigits(true);
        $this->assertTrue($generator->includesDigits(), "includesDigits property was not true after turning it on.");
        $generator->setIncludeDigits(false);
        $this->assertFalse($generator->includesDigits(), "includesDigits property was not false after turning it off.");
        $generator->setIncludeDigits(null);
        $this->assertNull($generator->includesDigits(), "includesDigits property was not null after reverting it to the default behaviour.");
    }

    /**
     * Test for the includesPeriod() method.
     */
    public function testIncludesAlgorithm(): void
    {
        $generator = new UrlGenerator();
        $this->assertNull($generator->includesAlgorithm(), "Default state of includesAlgorithm property is not as expected.");
        $generator->setIncludeAlgorithm(true);
        $this->assertTrue($generator->includesAlgorithm(), "includesAlgorithm property was not true after turning it on.");
        $generator->setIncludeAlgorithm(false);
        $this->assertFalse($generator->includesAlgorithm(), "includesAlgorithm property was not false after turning it off.");
        $generator->setIncludeAlgorithm(null);
        $this->assertNull($generator->includesAlgorithm(), "includesAlgorithm property was not null after reverting it to the default behaviour.");
    }

    /**
     * Data provider for methods that switch UrlGenerator features on/off.
     *
     * The following switch methods use this test data:
     * - setIncludesPeriod()
     * - setIncludesDigits()
     * - setIncludesAlgorithm()
     *
     * @return array
     */
    public function dataForTestOptionSwitchMethods(): array
    {
        return [
            "typicalTrue" => [true,],
            "typicalFalse" => [false,],
            "typicalNull" => [null, ],
            "invalidInt1" => [1, TypeError::class,],
            "invalidInt0" => [0, TypeError::class,],
            "invalidStringTrue" => ["true", TypeError::class,],
            "invalidStringFalse" => ["false", TypeError::class,],
            "invalidString1" => ["1", TypeError::class,],
            "invalidString0" => ["0", TypeError::class,],
            "invalidStringableTrue" => [self::createStringable("true"), TypeError::class,],
            "invalidStringableFalse" => [self::createStringable("false"), TypeError::class,],
            "invalidStringable1" => [self::createStringable("1"), TypeError::class,],
            "invalidStringable0" => [self::createStringable("0"), TypeError::class,],
            "invalidArrayTrue" => [[true,], TypeError::class,],
            "invalidArrayFalse" => [[false,], TypeError::class,],
        ];
    }

    /**
     * Test for the setIncludePeriod() method.
     *
     * @dataProvider dataForTestOptionSwitchMethods
     *
     * @param mixed $include The value to pass to the setIncludePeriod() method, and the expected return value from
     * includesPeriod().
     * @param class-string|null $exceptionClass The class of the exception that is expected to tbe thrown, if any.
     */
    public function testSetIncludesPeriod(mixed $include, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $generator = new UrlGenerator();
        $generator->setIncludePeriod($include);
        $this->assertEquals($include, $generator->includesPeriod(), "includesPeriod() did not report the correct state.");
    }

    /**
     * Test for the setIncludeDigits() method.
     *
     * @dataProvider dataForTestOptionSwitchMethods
     *
     * @param mixed $include The value to pass to the setIncludeDigits() method, and the expected return value from
     * includesDigits().
     * @param class-string|null $exceptionClass The class of the exception that is expected to tbe thrown, if any.
     */
    public function testSetIncludesDigits(mixed $include, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $generator = new UrlGenerator();
        $generator->setIncludeDigits($include);
        $this->assertEquals($include, $generator->includesDigits(), "includesPeriod() did not report the correct state.");
    }

    /**
     * Test for the setIncludeAlgorithm() method.
     *
     * @dataProvider dataForTestOptionSwitchMethods
     *
     * @param mixed $include The value to pass to the setIncludeAlgorithm() method, and the expected return value from
     * includesAlgorithm().
     * @param class-string|null $exceptionClass The class of the exception that is expected to tbe thrown, if any.
     */
    public function testSetIncludesAlgorithm(mixed $include, string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $generator = new UrlGenerator();
        $generator->setIncludeAlgorithm($include);
        $this->assertEquals($include, $generator->includesAlgorithm(), "includesPeriod() did not report the correct state.");
    }

    /**
     * Test data for testStaticBadMethodCall().
     *
     * @return \Generator
     */
    public function dataForFluentBadMethodCallTests(): Generator
    {
        yield from [
            // these are all likely confusions of actual static methods provided
            ["fromIssuer", [self::randomIssuer(0.0)],],
            ["forUser", [self::randomUser()],],
            ["includeDigits",],
            ["includeAlgorithm",],
            ["includePeriod",],
        ];

        // test with 100 randomly-generated method names
        $methodNameCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_";

        for ($idx = 0; $idx < 100; ++$idx) {
            $method = "";

            for ($times = 0; $times < 2; ++$times) {
                $charCount = mt_rand(5, 10);

                for ($charIdx = 0; $charIdx < $charCount; ++$charIdx) {
                    $method .= $methodNameCharacters[mt_rand(0, strlen($methodNameCharacters) - 1)];
                }

                // this ensures it can't match an existing static/fluent method
                $method .= "_";
            }

            yield [$method,];
        }
    }

    /**
     * @dataProvider dataForFluentBadMethodCallTests
     *
     * Test the static/fluent interface throws the BadMethodCall exception with non-existent methods.
     *
     * @param string $methodName The invalid method name.
     * @param array $args The optional args for the call.
     */
    public function testStaticBadMethodCall(string $methodName, array $args = []): void
    {
        $this->expectException(BadMethodCallException::class);
        UrlGenerator::{$methodName}(...$args);
    }

    /**
     * @dataProvider dataForFluentBadMethodCallTests
     *
     * Test the static/fluent interface throws the BadMethodCall exception with non-existent methods.
     *
     * @param string $methodName The invalid method name.
     * @param array $args The optional args for the call.
     */
    public function testDynamicBadMethodCall(string $methodName, array $args = []): void
    {
        $this->expectException(BadMethodCallException::class);
        UrlGenerator::from("Equit")->{$methodName}(...$args);
    }

    /**
     * Test for() used as the initialising method in a fluent build of an UrlGenerator.
     *
     * @dataProvider dataForTestSetUser
     *
     * @param mixed $user The user to test with.
     * @param string|null $exceptionClass The class of exception expected to be thrown, if any.
     */
    public function testStaticFor(mixed $user, ?string $exceptionClass = null): void
    {
        if ($exceptionClass) {
            $this->expectException($exceptionClass);
        }

        $generator = UrlGenerator::for($user);
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::for() did not return an UrlGenerator.");
        $this->assertEquals($user, $generator->user(), "The created generator did not report the expected user.");
    }

    /**
     * Test for() used as a chained method in a fluent build of an UrlGenerator.
     *
     * @dataProvider dataForTestSetUser
     *
     * @param mixed $user The user to test with.
     * @param string|null $exceptionClass The class of exception expected to be thrown, if any.
     */
    public function testDynamicFor(mixed $user, ?string $exceptionClass = null): void
    {
        if ($exceptionClass) {
            $this->expectException($exceptionClass);
        }

        $generator = UrlGenerator::from("Equit")->for($user);
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::for() did not return an UrlGenerator.");
        $this->assertEquals($user, $generator->user(), "The created generator did not report the expected user.");
    }

    /**
     * Test from() used as the initialising method in a fluent build of an UrlGenerator.
     *
     * @dataProvider dataForTestIssuer
     *
     * @param mixed $issuer The issuer to test with.
     * @param string|null $exceptionClass The class of exception expected to be thrown, if any.
     */
    public function testStaticFrom(mixed $issuer, ?string $exceptionClass = null): void
    {
        if ($exceptionClass) {
            $this->expectException($exceptionClass);
        }

        $generator = UrlGenerator::from($issuer);
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::from() did not return an UrlGenerator.");
        $this->assertSame($issuer, $generator->issuer(), "The created generator did not report the expected issuer.");
    }

    /**
     * Test from() used as a chained method in a fluent build of an UrlGenerator.
     *
     * @dataProvider dataForTestIssuer
     *
     * @param mixed $issuer The issuer to test with.
     * @param string|null $exceptionClass The class of exception expected to be thrown, if any.
     */
    public function testDynamicFrom(mixed $issuer, ?string $exceptionClass = null): void
    {
        if ($exceptionClass) {
            $this->expectException($exceptionClass);
        }

        $generator = UrlGenerator::for("darren")->from($issuer);
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::from() did not return an UrlGenerator.");
        $this->assertSame($issuer, $generator->issuer(), "The created generator did not report the expected issuer.");
    }

    /**
     * Test withPeriod() used as the initialising method in a fluent build of an UrlGenerator.
     */
    public function testStaticWithPeriod(): void
    {
        $generator = UrlGenerator::withPeriod();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withPeriod() did not return an UrlGenerator.");
        $this->assertTrue($generator->includesPeriod(), "The created generator did not report the expected 'includes period' state.");
    }

    /**
     * Test withPeriod() used as a chained method in a fluent build of an UrlGenerator.
     */
    public function testDynamicWithPeriod(): void
    {
        $generator = UrlGenerator::from("Equit")->withPeriod();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withPeriod() did not return an UrlGenerator.");
        $this->assertTrue($generator->includesPeriod(), "The created generator did not report the expected 'includes period' state.");
    }

    /**
     * Test withPeriod() used as the initialising method in a fluent build of an UrlGenerator.
     */
    public function testStaticWithPeriodIfCustomised(): void
    {
        $generator = UrlGenerator::withPeriodIfCustomised();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withPeriodIfCustomised() did not return an UrlGenerator.");
        $this->assertNull($generator->includesPeriod(), "The created generator did not report the expected 'includes period' state.");
    }

    /**
     * Test withPeriod() used as a chained method in a fluent build of an UrlGenerator.
     */
    public function testDynamicWithPeriodIfCustomised(): void
    {
        $generator = UrlGenerator::from("Equit")->withPeriodIfCustomised();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withPeriodIfCustomised() did not return an UrlGenerator.");
        $this->assertNull($generator->includesPeriod(), "The created generator did not report the expected 'includes period' state.");
    }

    /**
     * Test withoutPeriod() used as the initialising method in a fluent build of an UrlGenerator.
     */
    public function testStaticWithoutPeriod(): void
    {
        $generator = UrlGenerator::withoutPeriod();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withoutPeriod() did not return an UrlGenerator.");
        $this->assertFalse($generator->includesPeriod(), "The created generator did not report the expected 'includes period' state.");
    }

    /**
     * Test withoutPeriod() used as a chained method in a fluent build of an UrlGenerator.
     */
    public function testDynamicWithoutPeriod(): void
    {
        $generator = UrlGenerator::from("Equit")->withoutPeriod();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withoutPeriod() did not return an UrlGenerator.");
        $this->assertFalse($generator->includesPeriod(), "The created generator did not report the expected 'includes period' state.");
    }

    /**
     * Test withAlgorithm() used as the initialising method in a fluent build of an UrlGenerator.
     */
    public function testStaticWithAlgorithm(): void
    {
        $generator = UrlGenerator::withAlgorithm();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withAlgorithm() did not return an UrlGenerator.");
        $this->assertTrue($generator->includesAlgorithm(), "The created generator did not report the expected 'includes algorithm' state.");
    }

    /**
     * Test withAlgorithm() used as a chained method in a fluent build of an UrlGenerator.
     */
    public function testDynamicWithAlgorithm(): void
    {
        $generator = UrlGenerator::from("Equit")->withAlgorithm();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withAlgorithm() did not return an UrlGenerator.");
        $this->assertTrue($generator->includesAlgorithm(), "The created generator did not report the expected 'includes algorithm' state.");
    }

    /**
     * Test withAlgorithm() used as the initialising method in a fluent build of an UrlGenerator.
     */
    public function testStaticWithAlgorithmIfCustomised(): void
    {
        $generator = UrlGenerator::withAlgorithmIfCustomised();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withAlgorithmIfCustomised() did not return an UrlGenerator.");
        $this->assertNull($generator->includesAlgorithm(), "The created generator did not report the expected 'includes algorithm' state.");
    }

    /**
     * Test withAlgorithm() used as a chained method in a fluent build of an UrlGenerator.
     */
    public function testDynamicWithAlgorithmIfCustomised(): void
    {
        $generator = UrlGenerator::from("Equit")->withAlgorithmIfCustomised();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withAlgorithmIfCustomised() did not return an UrlGenerator.");
        $this->assertNull($generator->includesAlgorithm(), "The created generator did not report the expected 'includes algorithm' state.");
    }

    /**
     * Test withoutAlgorithm() used as the initialising method in a fluent build of an UrlGenerator.
     */
    public function testStaticWithoutAlgorithm(): void
    {
        $generator = UrlGenerator::withoutAlgorithm();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withoutAlgorithm() did not return an UrlGenerator.");
        $this->assertFalse($generator->includesAlgorithm(), "The created generator did not report the expected 'includes algorithm' state.");
    }

    /**
     * Test withoutAlgorithm() used as a chained method in a fluent build of an UrlGenerator.
     */
    public function testDynamicWithoutAlgorithm(): void
    {
        $generator = UrlGenerator::from("Equit")->withoutAlgorithm();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withoutAlgorithm() did not return an UrlGenerator.");
        $this->assertFalse($generator->includesAlgorithm(), "The created generator did not report the expected 'includes algorithm' state.");
    }

    /**
     * Test withDigits() used as the initialising method in a fluent build of an UrlGenerator.
     */
    public function testStaticWithDigits(): void
    {
        $generator = UrlGenerator::withDigits();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withDigits() did not return an UrlGenerator.");
        $this->assertTrue($generator->includesDigits(), "The created generator did not report the expected 'includes digits' state.");
    }

    /**
     * Test withDigits() used as a chained method in a fluent build of an UrlGenerator.
     */
    public function testDynamicWithDigits(): void
    {
        $generator = UrlGenerator::from("Equit")->withDigits();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withDigits() did not return an UrlGenerator.");
        $this->assertTrue($generator->includesDigits(), "The created generator did not report the expected 'includes digits' state.");
    }

    /**
     * Test withDigitsIfCustomised() used as the initialising method in a fluent build of an UrlGenerator.
     */
    public function testStaticWithDigitsIfCustomised(): void
    {
        $generator = UrlGenerator::withDigitsIfCustomised();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withDigits() did not return an UrlGenerator.");
        $this->assertNull($generator->includesDigits(), "The created generator did not report the expected 'includes digits' state.");
    }

    /**
     * Test withDigitsIfCustomised() used as a chained method in a fluent build of an UrlGenerator.
     */
    public function testDynamicWithDigitsIfCustomised(): void
    {
        $generator = UrlGenerator::from("Equit")->withDigitsIfCustomised();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withDigitsIfCustomised() did not return an UrlGenerator.");
        $this->assertNull($generator->includesDigits(), "The created generator did not report the expected 'includes digits' state.");
    }

    /**
     * Test withoutDigits() used as the initialising method in a fluent build of an UrlGenerator.
     */
    public function testStaticWithoutDigits(): void
    {
        $generator = UrlGenerator::withoutDigits();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withoutDigits() did not return an UrlGenerator.");
        $this->assertFalse($generator->includesDigits(), "The created generator did not report the expected 'includes digits' state.");
    }

    /**
     * Test withoutDigits() used as a chained method in a fluent build of an UrlGenerator.
     */
    public function testDynamicWithoutDigits(): void
    {
        $generator = UrlGenerator::from("Equit")->withoutDigits();
        $this->assertInstanceOf(UrlGenerator::class, $generator, "UrlGenerator::withoutDigits() did not return an UrlGenerator.");
        $this->assertFalse($generator->includesDigits(), "The created generator did not report the expected 'includes digits' state.");
    }
}
