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
 * Render a TOTP of six decimal digits.
 *
 * The standard procedure, described in RFC 6238, is used to extract a 31-bit integer from the HOTP HMAC, the lease-
 * significant 6 digits of which are used as the password. The password is padded to the left with 0s if it has fewer
 * than 6 digits.
 */
class SixDigits implements IntegerRenderer
{
    use RendersStandardIntegerPasswords;

    /** @return Digits 6 */
    public function digits(): Digits
    {
        static $digits = null;

        if (null === $digits) {
            $digits = new Digits(6);
        }

        return $digits;
    }
}
