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

namespace Equit\Totp\Tools\Totp;

require_once(__DIR__ . "/bootstrap.php");

use DateTime;
use DateTimeZone;
use Equit\Totp\Codecs\Base32;
use Equit\Totp\Codecs\Base64;
use Equit\Totp\Exceptions\InvalidBase32DataException;
use Equit\Totp\Exceptions\InvalidBase64DataException;
use Equit\Totp\Exceptions\InvalidSecretException;
use Equit\Totp\Exceptions\SecureRandomDataUnavailableException;
use Equit\Totp\Factory;
use Equit\Totp\Renderers\EightDigits;
use Equit\Totp\Renderers\SixDigits;
use Equit\Totp\Renderers\Steam;
use Exception;
use Throwable;
use function Equit\Totp\Tools\toPhpHexString;

/**
 * Process exit code when the script has run successfully.
 */
const ExitOk = 0;

/**
 * Process exit code when the script has only shown the usage message.
 */
const ErrUsageOnly = 1;

/**
 * Process exit code when the user has used --reference-time or -r but not given a time.
 */
const ErrMissingReferenceTime = 2;

/**
 * Process exit code when the user has used --reference-time or -r and has provided an invalid time string.
 */
const ErrInvalidReferenceTime = 3;

/**
 * Process exit code when the user has used --totp-time or -t but not given a time.
 */
const ErrMissingTotpTime = 4;

/**
 * Process exit code when the user has used --totp-time or -t and has provided an invalid time string.
 */
const ErrInvalidTotpTime = 5;

/**
 * Process exit code when the user has used --totp-time or -t and has provided an invalid time string.
 */
const ErrTotpTimeTooEarly = 6;

/**
 * Process exit code when the user has used --period or -p but not given a period.
 */
const ErrMissingPeriod = 7;

/**
 * Process exit code when the user has used --period or -p and has given an invalid period.
 */
const ErrInvalidPeriod = 8;

/**
 * Process exit code when the user has used --secret, -s, --secret-64 or --raw-secret but not given a secret.
 */
const ErrMissingSecret = 9;

/**
 * Process exit code when the user has used --secret, -s, --secret-64 or --raw-secret but not provided a valid secret.
 */
const ErrInvalidSecret = 10;

/**
 * Process exit code when the user has not supplied a secret and a sufficiently secure random one can't be generated.
 */
const ErrCannotGenerateRandomSecret = 11;

/**
 * Data structure encapsulating the program options.
 */
class Options
{
    public int $referenceTime = Factory::DefaultReferenceTime; // The TOTP reference time (T0)
    public int $timeStep = TimeStep::DefaultTimeStep;           // The TOTP time step
    public ?int $totpTime = null;                           // The time at which to calculate the TOTP
    public ?string $secret = null;                          // The raw TOTP secret
    public string $algorithm = Factory::DefaultAlgorithm;      // The TOTP hash algorithm
    public string $renderer = SixDigits::class;             // The class of the TOTP renderer
    public bool $explain = false;                           // Flag indicating whether to explain all steps

    /**
     * Parse command line arguments into an Options object.
     *
     * @param array $args The arguments.
     *
     * @return Options The options.
     * @throws \Exception If an argument can't be read.
     */
    public static function readFrom(array $args): Options
    {
        $options = new static();

        for ($idx = 0; $idx < count($args); ++$idx) {
            $arg = $args[$idx];

            switch ($arg) {
                case "--help":
                    throw new Exception("--help must be the only argument, if provided.", ErrUsageOnly);

                case "--reference-time":
                case "-r":
                    ++$idx;

                    if (!isset($args[$idx])) {
                        throw new Exception("{$arg} requires the reference time as an argument.", ErrMissingReferenceTime);
                    }

                    try {
                        $options->referenceTime = static::parseTimestamp($args[$idx]);
                    }
                    catch (Throwable $err) {
                        throw new Exception("The argument '{$args[$idx]}' provided for {$arg} is not a valid time.", ErrInvalidReferenceTime, $err);
                    }
                    break;

                case "--totp-time":
                case "-t":
                    ++$idx;

                    if (!isset($args[$idx])) {
                        throw new Exception("{$arg} requires the 'current' TOTP time as an argument.", ErrMissingTotpTime);
                    }

                    try {
                        $options->totpTime = static::parseTimestamp($args[$idx]);
                    }
                    catch (Throwable $err) {
                        throw new Exception("The argument '{$args[$idx]}' provided for {$arg} is not a valid time.", ErrInvalidTotpTime, $err);
                    }
                    break;

                case "--time-step":
                case "--period":
                case "--interval":
                case "-p":
                    ++$idx;

                    if (!isset($args[$idx])) {
                        throw new Exception("{$arg} requires the period specified in seconds as an argument.", ErrMissingPeriod);
                    }

                    $options->timeStep = filter_var($args[$idx], FILTER_VALIDATE_INT, ["options" => ["min_range" => 1,]]);

                    if (false === $options->timeStep) {
                        throw new Exception("{$arg} requires the period in whole seconds > 0.", ErrInvalidPeriod);
                    }
                    break;

                case "--secret":
                case "-s":
                    ++$idx;

                    if (!isset($args[$idx])) {
                        throw new Exception("{$arg} requires the secret as an argument.", ErrMissingSecret);
                    }

                    try {
                        $options->secret = Base32::decode($args[$idx]);
                    }
                    catch (InvalidBase32DataException $err) {
                        throw new Exception("The secret given to {$arg} is not valid Base32 encoded data.", ErrInvalidSecret, $err);
                    }
                    break;

                case "--secret-64":
                    ++$idx;

                    if (!isset($args[$idx])) {
                        throw new Exception("{$arg} requires the secret as an argument.", ErrMissingSecret);
                    }

                    try {
                        $options->secret = Base64::decode($args[$idx]);
                    }
                    catch (InvalidBase64DataException $err) {
                        throw new Exception("The secret given to {$arg} is not valid Base64 encoded data.", ErrMissingSecret, $err);
                    }
                    break;

                case "--raw-secret":
                    ++$idx;

                    if (!isset($args[$idx])) {
                        throw new Exception("{$arg} requires the secret as an argument.", $arg, ErrMissingSecret);
                    }

                    $options->secret = $args[$idx];
                    break;

                case "--sha1":
                case "--SHA1":
                    $options->algorithm = Factory::Sha1Algorithm;
                    break;

                case "--sha256":
                case "--SHA256":
                    $options->algorithm = Factory::Sha256Algorithm;
                    break;

                case "--sha512":
                case "--SHA512":
                    $options->algorithm = Factory::Sha512Algorithm;
                    break;

                case "--steam":
                    $options->renderer = Steam::class;
                    break;

                case "--six-digits":
                case "-6":
                    $options->renderer = SixDigits::class;
                    break;

                case "--eight-digits":
                case "-8":
                    $options->renderer = EightDigits::class;
                    break;

                case "--explain":
                case "-e":
                    $options->explain = true;
                    break;
            }
        }

        // fill in the blanks for those options that the user has not supplied, and for which we use late population
        if (!isset($options->secret)) {
            try {
                $options->secret = Factory::randomSecret();
            }
            catch (SecureRandomDataUnavailableException $err) {
                throw new Exception("It has not been possible to generate cryptographically-secure random secrets - you must provide a secret using the command-line options.", ErrCannotGenerateRandomSecret, $err);
            }
        }

        if (!isset($options->totpTime)) {
            $options->totpTime = time();
        }

        return $options;
    }

    /**
     * Parse a user-supplied date-time string into a Unix timestamp.
     *
     * @param string $timeString The user-supplied time string.
     *
     * @return int|null The timestamp, or null if the user's input can't be parsed.
     * @throws \Exception
     */
    private static function parseTimestamp(string $timeString): ?int
    {
        $time = filter_var($timeString, FILTER_VALIDATE_INT);

        if (false !== $time) {
            return $time;
        }

        return (new DateTime($timeString, new DateTimeZone("UTC")))->getTimestamp();
    }

    /**
     * @throws \Exception if the options are not valid.
     */
    public function validate(): void
    {
        if ($this->totpTime < $this->referenceTime) {
            throw new Exception("One-time passwords are not available before the TOTP reference time.", ErrTotpTimeTooEarly);
        }
    }
}

/**
 * Encapsulation of the command to run.
 */
class Command
{
    /**
     * @var string The command-line script executed.
     */
    private string $m_bin;

    /**
     * @var array The command-line arguments for the script.
     */
    private array $m_args;

    /**
     * Initialise a new command with the given command-line.
     *
     * The arguments should include the script name - usually, $argv is what you want to pass.
     *
     * @param array $args The arguments from the command-line.
     */
    public function __construct(array $args)
    {
        $this->m_bin  = array_shift($args);
        $this->m_args = $args;
    }

    /**
     * Fetch one or all of the command-line arguments.
     *
     * @param int|null $idx The index of the argument requested. Omit to receive all the arguments.
     *
     * @return array|string The requested argument, or all of them.
     */
    public function arguments(?int $idx = null): array|string
    {
        if (isset($idx)) {
            return $this->m_args[$idx];
        }

        return $this->m_args;
    }

    /**
     * Fetch the count of the command-line arguments that were passed to the script.
     *
     * @return int The number of command-line arguments.
     */
    public function argumentCount(): int
    {
        return count($this->arguments());
    }

    /**
     * Run the command.
     *
     * @return int The process exit code.
     */
    public function exec(): int
    {
        if (1 === $this->argumentCount() && "--help" === $this->arguments(0)) {
            $this->usage();
            return ErrUsageOnly;
        }

        try {
            $options = Options::readFrom($this->arguments());
            $options->validate();
            return $this->outputTotp($options);
        }
        catch (Throwable $err) {
            fputs(STDERR, $err->getMessage() . "\n");
            return $err->getCode();
        }
    }


    /**
     * Show the usage/help message.
     */
    private function usage(): void
    {
        $bin = basename($this->m_bin);

        echo <<<EOT
{$bin} - Generate a Time-based One-Time Password.

Usage: {$this->m_bin} [--help | OPTIONS]

--help
    Show this help message and exit.
    
OPTIONS
  --secret SECRET
  -s SECRET
      Set the secret to use when generating the TOTP data. SECRET is the secret to use, encoded using base32. It must
      be at least 128 bits (16 bytes) long when decoded.
      
      If no secret is provided, a random secret will be used.
      
      See also --secret-64 and --raw-secret for other ways of providing the secret.
      
  --secret-64 SECRET
      Set the secret to use when generating the TOTP data. SECRET is the secret to use, encoded using base64. It must
      be at least 128 bits (16 bytes) long when decoded.
      
      If no secret is provided, a random secret will be used.
      
      See also --secret and --raw-secret for other ways of providing the secret.
      
  --raw-secret SECRET
      Set the secret to use when generating the TOTP data. SECRET is the secret to use, as raw bytes. It must be at
      least 128 bits (16 bytes) long.
      
      This option is often not what you want since secrets should usually contain non-ASCII data, which you can't supply
      easily on the command-line --secret or --secret-64 is often a better choice.
      
      If no secret is provided, a random secret will be used.
      
      See also --secret and --secret-64 for other ways of providing the secret.

  --reference-time TIME
      Set the reference time for the generated password. TIME is the time to use, specified either as a Unix timestamp
      or a date in a format that PHP's DateTime class can parse. It must be before the current time if specified with
      the --totp-time option.
      
      If this is not specified the Unix epoch is used (00:00:00 01/01/1970 UTC).
      
  --totp-time TIME
      Set the current time for the generated password. TIME is the time to use, specified either as a Unix timestamp or
      a date in a format that PHP's DateTime class can parse. If this is specified, it must be after the reference time.
      
      If this is not specified the current system time is used.
      
  --time-step TIME-STEP
  --period TIME-STEP
  --interval TIME-STEP
  -p TIME-STEP
      Set the time step to use when generating the password. TIME-STEP is the number of seconds. It must be at least 1.
      If this is not specified, the default time step of 30 seconds will be used. 
      
  --sha1
  --SHA1
      Use the SHA1 hash algorithm when generating the password.
      
  --sha256
  --SHA256
      Use the SHA256 hash algorithm when generating the password.
      
  --sha512
  --SHA512
      Use the SHA512 hash algorithm when generating the password.

  --steam
      Use the Steam renderer to produce the final password. This produces a five-character code in line with those used
      by the Steam authenticator.

  --six-digits
  -6
      Produce a 6-digit password according to the standard TOTP algorithm.

  --eight-digits
  -8
      Produce an 8-digit password according to the standard TOTP algorithm.

  --explain
  -e
      Output the data used at each step of the process of producing the password. This is a debug feature.

EOT;
    }

    /**
     * Output the TOTP for a given configuration.
     *
     * @param Options $options The configuration options.
     *
     * @return int ExitOk on success, some other value on failure.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor should not throw with Unix timestamp.
     */
    private function outputTotp(Options $options): int
    {
        try {
            /** @noinspection PhpUnhandledExceptionInspection we know the interval and hash algorithm are both valid, and a
             * secret is supplied so none of the following exceptions can be thrown:
             * - InvalidIntervalException
             * - InvalidHashAlgorithmException
             * - SecureRandomDataUnavailableException
             */
            $totp = new Factory(secret: $options->secret, renderer: new $options->renderer, timeStep: $options->timeStep, referenceTime: $options->referenceTime, hashAlgorithm: $options->algorithm);
        }
        catch (InvalidSecretException $err) {
            fputs(STDERR, "The provided secret is not valid: {$err->getMessage()}\n");
            return ErrInvalidSecret;
        }

        if ($options->explain) {
            echo "Secret         : '" . toPhpHexString($options->secret) . "'\n";
            echo "Secret (base32): '" . Base32::encode($options->secret) . "'\n";
            echo "Secret (base64): '" . base64::encode($options->secret) . "'\n";
            echo "Reference Time : {$totp->referenceTimestamp()} - {$totp->referenceDateTime()->format("Y-m-d H:i:s")} UTC\n";
            echo "Time step      : {$totp->timeStep()} seconds\n";
            /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with Unix timestamp. */
            echo "TOTP time      : {$options->totpTime} - " . (new DateTime("@{$options->totpTime}", new DateTimeZone("UTC")))->format("Y-m-d H:i:s") . "\n";
            /** @noinspection PhpUnhandledExceptionInspection We validate above that the time is not before the reference time. */
            echo "Counter        : {$totp->counterAt($options->totpTime)}\n";
            /** @noinspection PhpUnhandledExceptionInspection We validate above that the time is not before the reference time. */
            echo "Counter bytes  : '" . toPhpHexString(pack("J", $totp->counterAt($options->totpTime))) . "'\n";
            /** @noinspection PhpUnhandledExceptionInspection We validate above that the time is not before the reference time. */
            echo "HMAC           : '" . toPhpHexString($totp->hmacAt($options->totpTime)) . "'\n";
            echo "Password       : ";
        }

        /** @noinspection PhpUnhandledExceptionInspection We validate above that the time is not before the reference time. */
        echo "{$totp->passwordAt($options->totpTime)}\n";
        return ExitOk;
    }
}

exit((new Command($argv))->exec());
