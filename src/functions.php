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

namespace Equit\Totp;

/**
 * Replace the content of a string with random data.
 *
 * @param string $str The string to scrub.
 */
function scrubString(string &$str): void
{
    for ($idx = strlen($str) - 1; $idx >= 0; --$idx) {
        // ensure we don't accidentally overwrite the string's memory with the same bytes
        do {
            $char = chr(rand(0, 255));
        } while ($char === $str[$idx]);

        $str[$idx] = $char;
    }
}
