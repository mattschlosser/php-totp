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

namespace Equit\Totp\Renderers;

use Equit\Totp\Contracts\IntegerRenderer;
use Equit\Totp\Renderers\Traits\RendersStandardIntegerPasswords;
use Equit\Totp\Types\Digits;

/**
 * Render a TOTP with an arbitrary number of decimal digits.
 *
 * This renders the truncation of the computed HMAC as a number of decimal digits, as specified by the HOTP
 * specification (see RFC 4226, https://datatracker.ietf.org/doc/html/rfc4226). The number of digits must be 6 or more
 * and should ordinarily be 9 or lower.
 *
 * Instances of this class model immutability.
 */
class Integer implements IntegerRenderer
{
    use RendersStandardIntegerPasswords;

    /** The default number of digits. */
    public const DefaultDigits = 6;

    /** @var Digits The number of digits. */
    protected Digits $digitCount;

    /**
     * Initialise a new renderer for a given number of digits.
     *
     * @param Digits|null $digits The digit count for rendered passwords. Defaults to 6.
     */
    public function __construct(?Digits $digits = null)
    {
        $this->digitCount = $digits ?? new Digits(self::DefaultDigits);
    }

    /** @return Digits The number of digits in rendered passwords. */
    public function digits(): Digits
    {
        return $this->digits();
    }

    /**
     * Set the number of digits in the rendered passwords.
     *
     * The TOTP specification mandates that the rendering contains at least 6 decimal digits. There is little point in
     * specifying more than 9 digits since you're likely to just be adding extra 0 pad characters on the left of the
     * 9-digit rendering.
     *
     * The renderer is cloned, the digits are set on the clone, and the clone is returned.
     *
     * @param Digits $digits The number of digits.
     * @return $this
     */
    public function withDigits(Digits $digits): self
    {
        $clone = clone $this;
        $clone->digitCount = $digits;
        return $clone;
    }
}
