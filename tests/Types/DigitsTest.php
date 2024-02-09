<?php

declare(strict_types=1);

namespace Equit\Totp\Tests\Types;

use Equit\Totp\Exceptions\InvalidDigitsException;
use Equit\Totp\Tests\Framework\TestCase;
use Equit\Totp\Types\Digits;

class DigitsTest extends TestCase
{
    private Digits $digits;

    public function setUp(): void
    {
        $this->digits = new Digits(8);
    }

    public function tearDown(): void
    {
        unset($this->digits);
    }

    public static function dataForTestConstructor1(): iterable
    {
        for ($digits = 6; $digits < 15; ++$digits) {
            yield "{$digits} digits" => [$digits];
        }
    }

    /**
     * Ensure constructor accepts valid digit counts.
     *
     * @dataProvider dataForTestConstructor1
     */
    public function testConstructor1(int $digits): void
    {
        $instance = new Digits($digits);
        self::assertSame($digits, $instance->digits());
    }

    public static function dataForTestConstructor2(): iterable
    {
        for ($digits = 0; $digits < 6; ++$digits) {
            yield "{$digits} digits" => [$digits];
        }
    }

    /**
     * Ensure constructor throws with invalid digit counts.
     *
     * @dataProvider dataForTestConstructor2
     */
    public function testConstructor2(int $digits): void
    {
        self::expecteException(InvalidDigitsException::class);
        self::expectExceptionMessage("Expected digits >= 6, found {$digits}");
        new Digits($digits);
    }

    /** Ensure we can read the number of digits. */
    public function testDigits1(): void
    {
        self::assertSame(8, $this->digits->digits());
    }

    /** Ensure the number of digits is stringified as expected. */
    public function testToString1(): void
    {
        self::assertSame("8", $this->digits->__toString());
    }
}
