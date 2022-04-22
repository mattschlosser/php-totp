<?php

declare(strict_types=1);

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
