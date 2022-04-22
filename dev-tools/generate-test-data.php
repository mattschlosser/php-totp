<?php

/**
 * @file generate-test-data.php
 *
 * Use oathtool (https://www.nongnu.org/oath-toolkit/oathtool.1.html) to generate test data for php-totp unit tests.
 * This most likely requires a unix-like platform
 */
require_once(__DIR__ . "/../vendor/autoload.php");

use Equit\Totp\Base32;
use Equit\Totp\Base64;

/**
 * Show the usage/help message.
 */
function usage(): void
{
    global $argv;
    $bin = basename($argv[0]);

    echo <<<EOT
{$bin} - Generate some test data for php-totp.

Usage: {$argv[0]} [--help | OPTIONS]

The oathtool command must be in your path. If it's not, this script will fail.

--help
    Show this help message and exit.
    
OPTIONS
  --secret SECRET
      Set the secret to use when generating test TOTP data. SECRET is the secret to use. Specify -32 (the default) or
      -64 - see below - to use Base32 or Base64 encoded binary secrets. If this is not specified, a random  secret will
      be generated for each TOTP output.
      
  -32
      Indicates that supplied secret is Base32 encoded.
      
  -64
      Indicates that supplied secret is Base64 encoded.

  --digits DIGITS
      Set the number of digits to use for generated passwords. DIGITS is the number of digits. It must be between 6 and
      10 inclusive. If this is not specified, a random number of digits will be generated for each TOTP output. 
      
  --reference-time TIME
      Set the reference time for generated TOTPs. TIME is the time to use, specified either as a Unix timestamp or a
      date in a format that PHP's DateTime class can parse. It must be before the current time if specified with the 
      --current-time option.
      
      If this is not specified a random time between the Unix epoch and 20 years before the current system time will be
      chosen for each TOTP output.
      
  --current-time TIME
      Set the current time for generated TOTPs. TIME is the time to use, specified either as a Unix timestamp or a date 
      in a format that PHP's DateTime class can parse. If this is specified, --reference-time must also be specified,
      and the current time must be after the reference time.
      
      If this is not specified a random time between the Unix epoch and 20 years before the current system time will be
       chosen for each TOTP output.
      
  --interval INTERVAL
      Set the interval to use when generating test TOTP data. INTERVAL is the number of seconds. It must be at least 1.
      If this is not specified, a random interval between 1 and 3660 (1 day) will be generated for each TOTP output. 
      
  --algorithm ALGORITHM
      Set the hash algorithm to use when generating test TOTP data. ALGORITHM is the algorithm to use. It must be one
      of SHA1, SHA256 and SHA512. If this is not specified, a random algorithm will be chosen for each TOTP output. 

  --times N
      Output test data for N TOTPs.

EOT;
}

/**
 * Choose one of a number of options, optionally with a weighting attached to each option.
 *
 * @param array $options The options to choose from.
 * @param array|null $weights The optional weights for each option.
 *
 * @return mixed One of the options.
 */
function chooseOne(array $options, array $weights = null): mixed
{
    if (!isset($weights)) {
        return $options[mt_rand(0, count($options) - 1)];
    }

    $item             = mt_rand(0, array_sum($weights) - 1);
    $cumulativeWeight = 0;

    for ($idx = 0; $idx < count($weights); ++$idx) {
        $cumulativeWeight += $weights[$idx];

        if ($cumulativeWeight > $item) {
            break;
        }
    }

    return $options[$idx];
}

/**
 * @return array The valid TOTP algorithms.
 */
function validAlgorithms(): array
{
    return ["SHA1", "SHA256", "SHA512",];
}

/**
 * Choose a random algorithm from those supported by TOTP.
 *
 * This will be one of sha1, sah256 and sha512.
 *
 * @return string The algorithm.
 */
function randomAlgorithm(): string
{
    return chooseOne(validAlgorithms());
}

/**
 * Generate a random timestamp to act as the reference time for the TOTP.
 *
 * The generated timestamp will be some time between the unix epoch and the current system time.
 *
 * @return int The timestamp.
 */
function randomReferenceTimestamp(): int
{
    return mt_rand(0, time() - 20 * 365 * 24 * 60 * 60);
}

/**
 * Generate a random timestamp to act as the time at which to generate the password for the TOTP.
 *
 * The timestamp will be some point between the provided reference time for the TOTP and the end of the largest year
 * provided, of 9999 if no largest year is provided.
 *
 * $maxYear must be after the year of the reference timestamp and must not be greater than 9999.
 *
 * @param int $referenceTimestamp The reference timestamp for the TOTP.
 * @param int|null $maxYear The latest year for which a random time may be generated.
 *
 * @return int
 */
function randomNow(int $referenceTimestamp, int $maxYear = null): int
{
    if (isset($maxYear)) {
        $maxTimestamp = (DateTime::createFromFormat("Y-m-d H:i:s", "{$maxYear}-12-31 23:59:59", new DateTimeZone("UTC")))->getTimestamp();
    } else {
        // 9999-12-31 23:59:59
        $maxTimestamp = 253402300799;
    }

    return mt_rand($referenceTimestamp, $maxTimestamp);
}

/**
 * Generate a random interval for a TOTP.
 *
 * The generated interval will be a multiple of 10 seconds between 10 and 3660 (one hour), inclusive.
 *
 * @return int The interval.
 */
function randomInterval(): int
{
    return 10 * mt_rand(1, 360);
}

/**
 * Generate a random number of digits for the password generated by an OTP.
 *
 * The number of digits will be 6, 7 or 8.
 *
 * @return int The number of digits.
 */
function randomDigits(): int
{
    return chooseOne([6, 7, 8,]);
}

/**
 * Convert a binary string to a PHP string literal for use in PHP source code.
 *
 * @param string $str The string to convert.
 *
 * @return string The PHP source string literal for the proviced binary string.
 */
function phpHexStringLiteral(string $str): string
{
    return "\\x" . implode("\\x", str_split(bin2hex($str), 2));
}

$opts = [
    "secret-type" => "base32",
    "times" => 1,
];

for ($idx = 1; $idx < $argc; ++$idx) {
    switch ($argv[$idx]) {
        case "--help":
            usage();
            exit(1);

        case "--secret":
            $opts["secret"] = $argv[++$idx] ?? die("--secret requires the secret to be specified as the next argument. See ${argv[0]} --help for details.");
            break;

        case "--reference-time":
            ++$idx;

            if (!isset($argv[$idx])) {
                die("--reference-time requires the time to be specified as the next argument. See ${argv[0]} --help for details.");
            }

            if (filter_var($argv[$idx], FILTER_VALIDATE_INT, ["options" => ["min_range" => 0,],])) {
                $opts["referenceTimestamp"] = intval($argv[$idx]);
            } else {
                try {
                    $opts["referenceTimestamp"] = (new DateTime($argv[$idx]))->getTimestamp();
                }
                catch (Exception $e) {
                    die("The provided time for --reference-time was not valid. See ${argv[0]} --help for details.");
                }
            }
            break;

        case "--current-time":
            ++$idx;

            if (!isset($argv[$idx])) {
                die("--current-time requires the time to be specified as the next argument. See ${argv[0]} --help for details.");
            }

            if (filter_var($argv[$idx], FILTER_VALIDATE_INT, ["options" => ["min_range" => 0,],])) {
                $opts["now"] = intval($argv[$idx]);
            } else {
                try {
                    $opts["now"] = (new DateTime($argv[$idx]))->getTimestamp();
                }
                catch (Exception $e) {
                    die("The provided time for --current-time was not valid. See ${argv[0]} --help for details.");
                }
            }
            break;

        case "--times":
            ++$idx;

            if (!isset($argv[$idx])) {
                die("--times requires the number of test data items to be specified as the next argument. See ${argv[0]} --help for details.");
            }

            if (!filter_var($argv[$idx], FILTER_VALIDATE_INT, ["options" => ["min_range" => 1,],])) {
                die("The number of test data items must be a positive integer. See ${argv[0]} --help for details.");
            }

            $opts["times"] = intval($argv[$idx]);
            break;

        case "--digits":
            ++$idx;

            if (!isset($argv[$idx])) {
                die("--digits requires the number of digits to be specified as the next argument. See ${argv[0]} --help for details.");
            }

            if (!filter_var($argv[$idx], FILTER_VALIDATE_INT, ["options" => ["min_range" => 6, "max_range" => 10,],])) {
                die("The number of digits items must be between 6 and 10 inclusive. See ${argv[0]} --help for details.");
            }

            $opts["digits"] = intval($argv[$idx]);
            break;

        case "--algorithm":
            ++$idx;

            if (!isset($argv[$idx])) {
                die("--algorithm requires the algorithm to be specified as the next argument. See ${argv[0]} --help for details.");
            }

            if (!in_array($argv[$idx], validAlgorithms())) {
                die("The algorithm must be one of [" . implode(", ", validAlgorithms()) . "]. See ${argv[0]} --help for details.");
            }

            $opts["algorithm"] = $argv[$idx];
            break;

        case "--interval":
            ++$idx;

            if (!isset($argv[$idx])) {
                die("--interval requires the interval to be specified as the next argument. See ${argv[0]} --help for details.");
            }

            if (!filter_var($argv[$idx], FILTER_VALIDATE_INT, ["options" => ["min_range" => 1,],])) {
                die("The interval must be at least 1 second. See ${argv[0]} --help for details.");
            }

            $opts["interval"] = intval($argv[$idx]);
            break;

        case "-32":
            $opts["secret-type"] = "base32";
            break;

        case "-64":
            $opts["secret-type"] = "base64";
            break;

        default:
            die ("Unrecognised argument {$argv[$idx]}. See ${argv[0]} --help for details.");
    }
}

if (isset($opts["now"])) {
    if (!isset($opts["referenceTimestamp"])) {
        die("--reference-time must be specified if --current-time is specified. See ${argv[0]} --help for details.");
    }

    if ($opts["now"] < $opts["referenceTimestamp"]) {
        die("--current-time must be on or after if --reference-time. See ${argv[0]} --help for details.");
    }
}

if (isset($opts["secret"])) {
    $opts["secret"] = match ($opts["secret-type"]) {
        "base32" => $opts["secret"],
        "base64" => Base32::encode(Base64::decode($opts["secret"])),
        "hex" => Base32::encode(hex2bin($opts["secret"])),
    };
}

echo "[\n";

$timesDigits = strlen("{$opts["times"]}");

for ($idx = 0; $idx < $opts["times"]; ++$idx) {
    $secret             = $opts["secret"] ?? Base32::encode(random_bytes(20));
    $algorithm          = $opts["algorithm"] ?? randomAlgorithm();
    $referenceTimestamp = $opts["referenceTimestamp"] ?? randomReferenceTimestamp();
    $interval           = $opts["interval"] ?? randomInterval();
    $digits             = $opts["digits"] ?? randomDigits();
    $nowTimestamp       = $opts["now"] ?? randomNow($referenceTimestamp, 2299);
    $referenceTime      = new DateTime("@{$referenceTimestamp}", new DateTimeZone("UTC"));
    $nowTime            = new DateTime("@{$nowTimestamp}", new DateTimeZone("UTC"));
    $oathToolOutput     = explode("\n", trim(`oathtool -b -v --totp={$algorithm} -d {$digits} --now "{$nowTime->format("Y-m-d H:i:s")} UTC" -s {$interval}s -S "{$referenceTime->format("Y-m-d H:i:s")} UTC" "{$secret}"`));
    $password           = array_pop($oathToolOutput);

    foreach ($oathToolOutput as $line) {
        if (preg_match("/Counter: 0x([a-zA-Z0-9]+) \(([0-9]+)\)/", $line, $matches)) {
            $counterValue = intval($matches[2]);
            $counterBytes = hex2bin(str_pad($matches[1], 16, "0", STR_PAD_LEFT));
        }
    }

    echo "   \"randomDataset" . sprintf("%0{$timesDigits}d", $idx + 1) . "\" => [\n";
    echo "      \"algorithm\" => \"" . strtolower($algorithm) . "\"\n";
    echo "      \"secret\" => [\n";
    echo "         \"raw\" => \"" . phpHexStringLiteral(Base32::decode($secret)) . "\"\n";
    echo "         \"base32\" => \"{$secret}\"\n";
    echo "         \"base64\" => \"" . Base64::encode(Base32::decode($secret)) . "\"\n";
    echo "      ],\n";
    echo "      \"referenceTime\" => [\n";
    echo "         // {$referenceTime->format("Y-m-d H:i:s")} UTC\n";
    echo "         \"timestamp\" => {$referenceTimestamp},\n";
    echo "         \"datetime\" => new DateTime(\"@{$referenceTimestamp}\", new DateTimeZone(\"UTC\")),\n";
    echo "      ],\n";
    echo "      \"interval\" => {$interval},\n";
    echo "      \"currentTime\" => [\n";
    echo "         // {$nowTime->format("Y-m-d H:i:s")} UTC\n";
    echo "         \"timestamp\" => {$nowTimestamp},\n";
    echo "         \"datetime\" => new DateTime(\"@{$nowTimestamp}\", new DateTimeZone(\"UTC\")),\n";
    echo "      ],\n";
    echo "      \"digits\" => {$digits},\n";
    echo "      \"counter\" => [\n";
    echo "         \"bytes\" => \"" . phpHexStringLiteral($counterBytes) . "\",\n";
    echo "         \"value\" => {$counterValue},\n";
    echo "      ],\n";
    echo "      \"password\" => \"{$password}\",\n";
    echo "   ],\n";
}

echo "]\n";
