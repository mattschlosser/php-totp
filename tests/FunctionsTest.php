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

use Generator;
use TypeError;
use function Equit\Totp\scrubString;

/**
 * Tests for standalone functions included in the library.
 */
class FunctionsTest extends Framework\TestCase
{
    /**
     * Test data for scrubString()
     *
     * @return \Generator
     */
    public function dataForTestScrubString(): Generator
    {
        yield from [
            "typical" => ["foobarfizzbuzz",],
            "typicalWhitespace" => ["        ",],
            "typicalNulls" => ["\0\0\0\0\0\0\0\0",],
            "extremeEmpty" => ["",],
            "extremeVeryLong" => [str_repeat("foobarfizzbuzz", 10000),],
            "invalidNull" => [null, TypeError::class,],
            "invalidInt" => [12345, TypeError::class,],
            "invalidFloat" => [12345.6789, TypeError::class,],
            "invalidTrue" => [true, TypeError::class,],
            "invalidFalse" => [false, TypeError::class,],
            "invalidStringable" => [self::createStringable("foobarfizzbuzz"), TypeError::class,],
            "invalidArray" => [["foobarfizzbuzz",], TypeError::class,],
            "invalidObject" => [new class
            {
            }, TypeError::class,],
        ];

        // 1000 random binary strings
        for ($idx = 0; $idx < 1000; ++$idx) {
            yield sprintf("%s%02d", "randomString", $idx) => [self::randomBinaryString(),];
        }
    }


    /**
     * @dataProvider dataForTestScrubString
     *
     * @param mixed $str The string to test with.
     * @param string|null $expectedException The class name of the Throwable that is expected, if any.
     */
    public function testScrubString(mixed $str, ?string $expectedException = null): void
    {
        if (isset($expectedException)) {
            $this->expectException($expectedException);
        }

        $before = $str;
        scrubString($str);
        $this->assertIsString($str, "Shredding the string changed its type.");
        $this->assertAllCharactersHaveChanged($before, $str, "Not all the characters in the string were changed by Totp::shred().");
    }
}