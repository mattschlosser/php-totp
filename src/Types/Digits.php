<?php

declare(strict_types=1);

namespace Equit\Totp\Types;

use Equit\Totp\Exceptions\InvalidDigitsException;
use Stringable;

final class Digits implements Stringable
{
    /** The minimum number of digits, as per RFC 6238. */
    public const MinimumDigits = 6;

    /** @var int The number of digits. */
    private int $digits;

    /**
     * Initialise a new Digits instance with a digit count.
     *
     * @param int $digits The number of digits.
     *
     * @throws InvalidDigitsException if the number of digits is not valid.
     */
    public function __construct(int $digits)
    {
        if (self::MinimumDigits > $digits) {
            throw new InvalidDigitsException($digits, "Expected digits >= " . self::MinimumDigits . ", found {$digits}");
        }

        $this->digits = $digits;
    }

    /** @return int The number of digits. */
    public function digits(): int
    {
        return $this->digits;
    }

    /** @return string The stringified number of digits. */
    public function __toString(): string
    {
        return (string) $this->digits;
    }
}
