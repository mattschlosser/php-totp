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

/**
 * Use the oathtool utility (https://www.nongnu.org/oath-toolkit/oathtool.1.html) to generate PHP test data for the
 * RFC 6238 test data (see page 15 of the RFC).
 *
 * The test data in the RFC all use the same secret, reference time (0) and time step (30).
 *
 * The oathtool command is expected to be in your path. If it is not, this script will fail.
 */

namespace Equit\Totp\Tools\Dev\RfcTestData;

require_once(__DIR__ . "/../bootstrap.php");

use DateTime;
use DateTimeZone;
use Equit\Totp\Codecs\Base32;
use Equit\Totp\Codecs\Base64;

/**
 * Show the usage/help message.
 */
function usage(): void
{
    global $argv;
    $bin = basename($argv[0]);

    echo <<<EOT
{$bin} - Generate test data for php-totp's unit tests based on the test data in RFC 6238.

Usage: {$argv[0]} [--help]

The oathtool command must be in your path. If it's not, this script will fail.

--help
    Show this help message and exit.

EOT;
}

if (isset($argv[1]) && "--help" === $argv[1]) {
    usage();
    exit(1);
}

$secret       = "12345678901234567890";
$base32secret = Base32::encode($secret);
$base64secret = Base64::encode($secret);

echo "[\n";

foreach (["sha1", "sha256", "sha512"] as $algorithm) {
    foreach ([59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000,] as $timestamp) {
        $time = new DateTime("@{$timestamp}", new DateTimeZone("UTC"));
        $otp  = trim(`oathtool -b -d 8 --now="{$time->format("Y-m-d H:i:s")} UTC" --totp="{$algorithm}" "{$base32secret}"`);
        $otp7 = substr($otp, 1);
        $otp6 = substr($otp, 2);

        // NOTE the secret is ASCII-safe, so we can output it without escaping any binary
        echo <<<EOT
    "rfcTestData-{$algorithm}-{$timestamp}" => [
      "algorithm" => "${algorithm}",
      "referenceTimestamp" => 0,
      "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
      "time-step" => 30,
      "timestamp" => {$timestamp},
      "time" => new DateTime("{$time->format("Y-m-d H:i:s")}", new DateTimeZone("UTC")),
      "secret" => [
        "raw" => "{$secret}",
        "base32" => "{$base32secret}",
        "base64" => "{$base64secret}",
      ],
      "passwords" => [
        "8" => "{$otp}",
        "7" => "{$otp7}",
        "6" => "{$otp6}",
      ],
    ],

EOT;
    }
}

echo "];\n";
