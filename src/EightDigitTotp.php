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

namespace Equit\Totp;

use DateTime;

/**
 * Convenience subclass of IntegerTotp for 8-digit passwords.
 */
class EightDigitTotp extends IntegerTotp
{
    public function __construct(string $secret, int $interval = self::DefaultInterval, DateTime | int $baseline = self::DefaultBaselineTime)
    {
        parent::__construct(8, $secret, $interval, $baseline);
    }
}