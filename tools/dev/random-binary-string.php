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

/**
 * Generate a random string of bytes of a specified length and output it as a PHP string literal.
 *
 * The string literal is output without surrounding "".
 */

namespace Equit\Totp\Tools\Dev\RandomBinaryString;

require_once(__DIR__ . "/../bootstrap.php");

use function Equit\Totp\Tools\toPhpHexString;

/**
 * Show the help/usage message.
 */
function usage(): void
{
    global $argv;
    $bin = basename($argv[0]);

    echo <<<EOT
{$bin} - Generate a random binary string.

Usage: {$argv[0]} [--help | bytes]

--help
    Show this help message and exit.
    
bytes
    The number of bytes in the random binary string. Default is 20.
    
EOT;
}

if (isset($argv[1]) && "--help" === $argv[1]) {
    usage();
    exit(1);
}

echo toPhpHexString(random_bytes($argv[1] ?? 20)) . "\n";
