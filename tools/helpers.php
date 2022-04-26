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

namespace Equit\Totp\Tools;

/**
 * Convert a binary string to a PHP source string literal.
 *
 * The returned value is the content of the string, not including the surrounding "".
 *
 * @param string $binary The binary string to convert.
 *
 * @return string The PHP source string literal.
 */
function toPhpHexString(string $binary): string
{
    return "\\x" . implode("\\x", str_split(bin2hex($binary), 2));
}
