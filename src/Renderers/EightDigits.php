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

namespace Equit\Totp\Renderers;

/**
 * Render a TOTP of eight decimal digits.
 *
 * The standard procedure, described in RFC 6238, is used to extract a 31-bit integer from the HOTP HMAC, the lease-
 * significant 8 digits of which are used as the password. The password is padded to the left with 0s if it has fewer
 * than 8 digits.
 */
class EightDigits implements IntegerRenderer
{
    use RendersStandardIntegerPasswords;

    protected int $digitCount = 8;
}
