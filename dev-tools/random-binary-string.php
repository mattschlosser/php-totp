<?php

/**
 * Generate a random string of bytes of a specified length and output it as a PHP string literal.
 *
 * The string literal is output without surrounding "".
 */

require_once("bootstrap.php");

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
