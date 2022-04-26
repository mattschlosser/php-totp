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
 * Create a Totp with random data and output all its details.
 */

namespace Equit\Totp\Tools\Dev\RandomBinaryString;

require_once(__DIR__ . "/../bootstrap.php");

use DateTime;
use Equit\Totp\Totp;
use ReflectionMethod;
use function Equit\Totp\Tools\toPhpHexString;

/**
 * Show the usage/help message.
 */
function usage(): void
{
    global $argv;
    $bin = basename($argv[0]);

    echo <<<EOT
{$bin} - Output verbose details of a random TOTP.

Usage: {$argv[0]} [--help]

--help
    Show this help message and exit.

EOT;
}

if (isset($argv[1]) && "--help" === $argv[1]) {
    usage();
    exit(1);
}

$totp = Totp::integer(
    digits: 6,
    secret: Totp::randomSecret(),
    timeStep: 10 * mt_rand(1, 6),                                  // random time-step, 10, 20, 30 40, 50 or 60 seconds
    referenceTime: mt_rand(0, time() - (60 * 60 * 24 * 365 * 20))  // reference time is a random time up to 20 years ago
);

// "current" time is some point in time between the reference time and actual current time
$currentTime = mt_rand($totp->referenceTimestamp(), time());

// use reflection to retrieve 64-bit BE counter bytes
$counterBytesAt = new ReflectionMethod($totp, "counterBytesAt");
$counterBytesAt->setAccessible(true);
$counterBytesAt = $counterBytesAt->getClosure($totp);

echo "Secret         : " . toPhpHexString($totp->secret()) . "\n";
echo "Secret (B32)   : {$totp->base32Secret()}\n";
echo "Secret (B64)   : {$totp->base64Secret()}\n";
echo "Reference Time : {$totp->referenceTimestamp()} {$totp->referenceTime()->format("Y-m-d H:i:s T")}\n";
echo "Time step      : {$totp->timeStep()}\n";
echo "Current Time   : {$currentTime} " . (new DateTime("@{$currentTime}"))->format("Y-m-d H:i:s T") . "\n\n";

// OTP details at current time
echo "Counter        : " . $totp->counterAt($currentTime) . " - " . toPhpHexString($counterBytesAt($currentTime)) . "\n";
echo "HMAC           : " . toPhpHexString($totp->hmacAt($currentTime)) . "\n";
echo "OTP (6)        : {$totp->passwordAt($currentTime)}\n";
$totp->renderer()->setDigits(7);
echo "OTP (7)        : {$totp->passwordAt($currentTime)}\n";
$totp->renderer()->setDigits(8);
echo "OTP (8)        : {$totp->passwordAt($currentTime)}\n\n";

// OTP details at -1 time step
$currentTime -= $totp->timeStep();
echo "Counter - 1     : " . $totp->counterAt($currentTime) . " - " . toPhpHexString($counterBytesAt($currentTime)) . "\n";
echo "HMAC - 1        : " . toPhpHexString($totp->hmacAt($currentTime)) . "\n";
$totp->renderer()->setDigits(6);
echo "OTP - 1 (6)     : {$totp->passwordAt($currentTime)}\n";
$totp->renderer()->setDigits(7);
echo "OTP - 1 (7)     : {$totp->passwordAt($currentTime)}\n";
$totp->renderer()->setDigits(8);
echo "OTP - 1 (8)     : {$totp->passwordAt($currentTime)}\n\n";

// OTP details at +1 time step
$currentTime += (2 * $totp->timeStep());
echo "Counter + 1     : " . $totp->counterAt($currentTime) . " - " . toPhpHexString($counterBytesAt($currentTime)) . "\n";
echo "HMAC + 1        : " . toPhpHexString($totp->hmacAt($currentTime)) . "\n";
$totp->renderer()->setDigits(6);
echo "OTP + 1 (6)     : {$totp->passwordAt($currentTime)}\n";
$totp->renderer()->setDigits(7);
echo "OTP + 1 (7)     : {$totp->passwordAt($currentTime)}\n";
$totp->renderer()->setDigits(8);
echo "OTP + 1 (8)     : {$totp->passwordAt($currentTime)}\n";
