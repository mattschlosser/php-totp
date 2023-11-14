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

namespace Equit\Totp\Contracts;

use Equit\Totp\TotpSecret;

interface TotpFactory
{
    /**
     * @return string The hash algorithm that is being used when computing the OTP.
     */
    public function hashAlgorithm(): string;

    /**
     * @return int The time step, in seconds, used when computing the OTP.
     */
    public function timeStep(): int;

    /**
     * @return int The reference unix timestamp (T0 in RFC6238-speak).
     */
    public function referenceTimestamp(): int;

    /** The name/identifier of the rendering scheme used to produce the actual passcodes (e.g. 6-digit, steam,...) */
    public function renderer(): string;

    /** Get a new Totp to calculate passcodes for a given secret. */
    public function totp(string|TotpSecret $secret): Totp;
}
