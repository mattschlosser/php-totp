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

namespace Equit\Totp\Renderers\Traits;

/**
 * Trait for renderers that produce padded integer one-time passwords.
 *
 * The final byte of the HMAC is used to calculate an offset. The four bytes starting at that offset are then
 * interpreted as a 32-bit unsigned integer, and the rightmost N digits of the decimal representation of that number are
 * used as the password. The password is left-padded with 0s if necessary to achieve the required number of digits.
 *
 * Renderer subclasses can import this trait and provide a digitCount property with the number of digits and the trait
 * will take care of the rest. The number of digits must be > 0.
 */
trait RendersStandardIntegerPasswords
{
    use ExtractsStandard31BitInteger;

    /** The renderer name. */
    public function name(): string
    {
        return "{$this->digits()}-digits";
    }

    /**
     * @return int The number of digits in the rendered password.
     */
    public function digits(): int
    {
        return $this->digitCount;
    }

    /**
     * Render the integer password from a given HMAC.
     *
     * The HMAC must be 152 bits (19 bytes) or more in length. HMACs provided by Totp instances always meet this
     * requirement.
     *
     * @param string $hmac The HMAC to process.
     *
     * @return string The digits of the generated password.
     */
    public function render(string $hmac): string
    {
        assert(5 < $this->digits(), "Invalid digit count in Renderer subclass " . get_class($this));
        $password = self::extractIntegerFromHmac($hmac) % (10 ** $this->digits());
        return str_pad("{$password}", $this->digits(), "0", STR_PAD_LEFT);
    }
}
