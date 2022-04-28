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

use DateTime;
use DateTimeZone;
use Equit\Totp\Exceptions\SecureRandomDataUnavailableException;
use Equit\Totp\Exceptions\InvalidHashAlgorithmException;
use Equit\Totp\Exceptions\InvalidTimeStepException;
use Equit\Totp\Exceptions\InvalidSecretException;
use Equit\Totp\Exceptions\InvalidTimeException;
use Equit\Totp\Exceptions\InvalidVerificationWindowException;
use Equit\Totp\Renderers\EightDigits;
use Equit\Totp\Renderers\Integer;
use Equit\Totp\Renderers\Renderer;
use Equit\Totp\Renderers\SixDigits;
use Exception;

/**
 * Class for generating Time-based One-Time Passwords.
 *
 * RFC 6238 does not say anything on the subject of whether T0 (the reference timestamp) can be a negative value, only
 * that the timestamp integer type used must enable the authentication time to extend beyond 2038 (i.e not a 32-bit
 * integer). Since it mentions nothing regarding the signedness of T0, this implementation does not forbid reference
 * times before the Unix epoch (i.e. -ve timestamps).
 */
class Totp
{
    /**
     * Import the trait that securely erases all string properties on destruction.
     */
    use SecurelyErasesProperties;

    /**
     * Use this to specify that the SHA1 algorithm should be used to generate HMACs.
     */
    public const Sha1Algorithm = "sha1";

    /**
     * Use this to specify that the SHA256 algorithm should be used to generate HMACs.
     */
    public const Sha256Algorithm = "sha256";

    /**
     * Use this to specify that the SHA512 algorithm should be used to generate HMACs.
     */
    public const Sha512Algorithm = "sha512";

    /**
     * The default algorithm to use to generate HMACs.
     *
     * This is equal to Sha1Algorithm.
     */
    public const DefaultAlgorithm = self::Sha1Algorithm;

    /**
     * The default update time step for passwords.
     */
    public const DefaultTimeStep = 30;

    /**
     * The default reference time for passwords.
     */
    public const DefaultReferenceTime = 0;

    /**
     * Error code for InvalidVerificationWindowException when the window is < 0.
     */
    public const ErrNegativeWindow = 1;

    /**
     * Error code for InvalidVerificationWindowException when the window would cause verification of passwords from
     * before the reference time.
     */
    public const ErrWindowViolatesReferenceTime = 2;

    /**
     * @var string The hashing algorithm to use when generating HMACs.
     */
    private string $m_hashAlgorithm = self::DefaultAlgorithm;

    /**
     * @var string The secret for password generation.
     */
    private string $m_secret;

    /**
     * @var int The time step, in seconds, at which the password changes.
     */
    private int $m_timeStep;

    /**
     * @var int The reference time from new password generation time steps are measured.
     */
    private int $m_referenceTime;

    /**
     * @var Renderer The renderer that will perform the truncation that turns the computed HMAC into a user-readable
     * one-time password.
     */
    private Renderer $m_renderer;

    /**
     * Initialise a new TOTP.
     *
     * If the reference time is specified as an int, it is interpreted as the number of seconds since the Unix epoch.
     * The default hashing algorithm is SHA1.
     *
     * @param TotpSecret|string|null $secret The TOTP secret. If given as a string, it's assumed to be raw binary.
     * @param Renderer|null $renderer The renderer that produces one-time passwords from HMACs.
     * @param int $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param string $hashAlgorithm The hash algorithm to use when generating OTPs. Must be one of the algorithm class
     * constants. Defaults to Sha1Algorithm.
     *
     * @throws InvalidTimeStepException if the time step is not a positive integer.
     * @throws InvalidSecretException if the provided secret is less than 128 bits in length.
     * @throws InvalidHashAlgorithmException if the provided hash algorithm is not one of the supported algorithms. See
     * the class constants.
     * @throws SecureRandomDataUnavailableException if a randomly-generated secret is required but a
     * source of cryptographically-secure random data is not available.
     */
    public function __construct(TotpSecret|string $secret = null, Renderer $renderer = null, int $timeStep = self::DefaultTimeStep, int|DateTime $referenceTime = self::DefaultReferenceTime, string $hashAlgorithm = self::DefaultAlgorithm)
    {
        $this->setSecret($secret ?? static::randomSecret());
        $this->setRenderer($renderer ?? static::defaultRenderer());
        $this->setTimeStep($timeStep);
        $this->setHashAlgorithm($hashAlgorithm);
        $this->m_referenceTime = ($referenceTime instanceof DateTime ? $referenceTime->getTimestamp() : $referenceTime);
    }

    /**
     * Overwrite a string with random bytes.
     *
     * This is intended to be used to shred secrets contained in strings so that the secret is only available in memory
     * in its unencrypted form for as long as is necessary. The Totp destructor uses this method to shred its internal
     * store of the unencrypted secret.
     *
     * @param string $str A reference to the string to shred.
     */
    public static final function shred(string &$str): void
    {
        for ($idx = strlen($str) - 1; $idx >= 0; --$idx) {
            // this loop ensures we don't accidentally overwrite the secret's memory with the same bytes - the chances
            // are infinitesimal anyway for valid secrets - at most 1 in 256^16 - but this guarantees it
            do {
                $char = chr(rand(0, 255));
            } while ($char === $str[$idx]);

            $str[$idx] = $char;
        }
    }

    /**
     * Helper to generate a random secret.
     *
     * The constructor uses this if no secret is provided. The secret is guaranteed to be valid for a TOTP. Currently
     * it is always 64 bytes (512 bits) in length so that it is sufficiently strong for all the supported algorithms.
     *
     * @return string The random secret.
     * @throws SecureRandomDataUnavailableException if a known source of cryptographically secure random data is
     * not available.
     */
    public static function randomSecret(): string
    {
        try {
            return random_bytes(64);
        }
        catch (Exception $e) {
            if (function_exists("openssl_random_pseudo_bytes")) {
                $secret = openssl_random_pseudo_bytes(64, $isStrong);

                if (false !== $secret && $isStrong) {
                    return $secret;
                }
            }

            throw new SecureRandomDataUnavailableException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Instantiate a TOTP generator with a six-digit integer password renderer.
     *
     * This is a convenience factory function for a commonly-used type of TOTP.
     *
     * @param TotpSecret|string|null $secret The TOTP secret. If given as a string, it's assumed to be raw binary.
     * @param int $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param string $hashAlgorithm The hash algorithm to use when generating OTPs. Must be one of the algorithm class
     * constants. Defaults to Sha1Algorithm.
     *
     * @return Totp
     * @throws \Equit\Totp\Exceptions\InvalidHashAlgorithmException If the supplied hashing algorithm is not one
     * supported by TOTP.
     * @throws \Equit\Totp\Exceptions\InvalidTimeStepException if the time step is < 1.
     * @throws \Equit\Totp\Exceptions\InvalidSecretException if the provided secret is less than 128 bits in length.
     * @throws \Equit\Totp\Exceptions\SecureRandomDataUnavailableException
     * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
     *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
     */
    public static function sixDigits(TotpSecret|string $secret = null, int $timeStep = self::DefaultTimeStep, int|DateTime $referenceTime = self::DefaultReferenceTime, string $hashAlgorithm = self::DefaultAlgorithm): Totp
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        return new Totp(secret: $secret, renderer: new SixDigits(), timeStep: $timeStep, referenceTime: $referenceTime, hashAlgorithm: $hashAlgorithm);
    }

    /**
     * Instantiate a TOTP generator with an eight-digit integer password renderer.
     *
     * This is a convenience factory function for a commonly-used type of TOTP.
     *
     * @param TotpSecret|string|null $secret The TOTP secret. If given as a string, it's assumed to be raw binary.
     * @param int $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param string $hashAlgorithm The hash algorithm to use when generating OTPs. Must be one of the algorithm class
     * constants. Defaults to Sha1Algorithm.
     *
     * @return Totp
     * @throws \Equit\Totp\Exceptions\InvalidHashAlgorithmException If the supplied hashing algorithm is not one
     * supported by TOTP.
     * @throws \Equit\Totp\Exceptions\InvalidTimeStepException if the time step is < 1.
     * @throws \Equit\Totp\Exceptions\InvalidSecretException if the provided secret is less than 128 bits in length.
     * @throws \Equit\Totp\Exceptions\SecureRandomDataUnavailableException
     * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
     *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
     */
    public static function eightDigits(TotpSecret|string $secret = null, int $timeStep = self::DefaultTimeStep, int|DateTime $referenceTime = self::DefaultReferenceTime, string $hashAlgorithm = self::DefaultAlgorithm): Totp
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        return new Totp(secret: $secret, renderer: new EightDigits(), timeStep: $timeStep, referenceTime: $referenceTime, hashAlgorithm: $hashAlgorithm);
    }

    /**
     * Instantiate a TOTP generator with an integer password renderer of a given number of digits.
     *
     * This is a convenience factory function for commonly-used types of TOTP.
     *
     * @param int $digits The number of digits in generated one-time passwords.
     * @param TotpSecret|string|null $secret The TOTP secret. If given as a string, it's assumed to be raw binary.
     * @param int $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param string $hashAlgorithm The hash algorithm to use when generating OTPs. Must be one of the algorithm class
     * constants. Defaults to Sha1Algorithm.
     *
     * @return Totp
     * @throws \Equit\Totp\Exceptions\InvalidHashAlgorithmException If the supplied hashing algorithm is not one
     * supported by TOTP.
     * @throws \Equit\Totp\Exceptions\InvalidDigitsException if the number of digits is < 1.
     * @throws \Equit\Totp\Exceptions\InvalidTimeStepException if the time step is < 1.
     * @throws \Equit\Totp\Exceptions\InvalidSecretException if the provided secret is less than 128 bits in length.
     * @throws \Equit\Totp\Exceptions\SecureRandomDataUnavailableException
     * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
     *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
     */
    public static function integer(int $digits, TotpSecret|string $secret = null, int $timeStep = self::DefaultTimeStep, int|DateTime $referenceTime = self::DefaultReferenceTime, string $hashAlgorithm = self::DefaultAlgorithm): Totp
    {
        return new Totp(secret: $secret, renderer: new Integer($digits), timeStep: $timeStep, referenceTime: $referenceTime, hashAlgorithm: $hashAlgorithm);
    }

    /**
     * Helper to create the default renderer when none is provided to the constructor.
     *
     * @return Renderer The default renderer.
     */
    protected static function defaultRenderer(): Renderer
    {
        return new SixDigits();
    }

    /**
     * Fetch the hashing algorithm to use to generate HMACs.
     *
     * @return string The hashing algorithm.
     */
    public function hashAlgorithm(): string
    {
        return $this->m_hashAlgorithm;
    }

    /**
     * Set the hash algorithm to use when generating HMACs.
     *
     * The hash algorithm must be one of SHA1, SHA256 or SHA512. Use the class constants for these to avoid errors.
     *
     * @param string $hashAlgorithm The hash algorithm.
     *
     * @throws InvalidHashAlgorithmException if the hash algorithm provided is not valid.
     */
    public function setHashAlgorithm(string $hashAlgorithm): void
    {
        $this->m_hashAlgorithm = match ($hashAlgorithm) {
            self::Sha1Algorithm, self::Sha256Algorithm, self::Sha512Algorithm => $hashAlgorithm,
            default => throw new InvalidHashAlgorithmException($hashAlgorithm, "The hash algorithm must be one of " . self::Sha1Algorithm . ", " . self::Sha256Algorithm . " or " . self::Sha512Algorithm . "."),
        };
    }

    /**
     * Fetch the raw secret.
     *
     * The raw secret is a byte sequence, not technically a string. It is likely to contain non-printable bytes.
     *
     * @return string The raw secret.
     */
    public function secret(): string
    {
        return $this->m_secret;
    }

    /**
     * @return string The secret, base32 encoded so that it's printable.
     */
    public function base32Secret(): string
    {
        return Base32::encode($this->secret());
    }

    /**
     * @return string The secret, base64 encoded so that it's printable.
     */
    public function base64Secret(): string
    {
        return Base64::encode($this->secret());
    }

    /**
     * Set the secret for generated passwords.
     *
     * The secret must be at least 128 bits (16 bytes) in length, ideally 160 bits (SHA1), 256 bits (SHA256) or 512 bits
     * (SHA512). There is minimal value in setting a secret with more than the ideal bits.
     *
     * @param TotpSecret|string $secret The secret. If given as a string, the string is assumed to be the raw secret.
     *
     * @throws InvalidSecretException if the secret is less than 128 bits in length.
     */
    public function setSecret(TotpSecret|string $secret): void
    {
        if ($secret instanceof TotpSecret) {
            $this->m_secret = $secret->raw();
            return;
        }

        if (16 > strlen($secret)) {
            throw new InvalidSecretException($secret, "TOTP secrets must be at least 128 bits (16 octets) in size.");
        }

        $this->m_secret = $secret;
    }

    /**
     * Fetch the renderer being used to generate one-time passwords from HMACs.
     *
     * @return \Equit\Totp\Renderers\Renderer The renderer.
     */
    public function renderer(): Renderer
    {
        return $this->m_renderer;
    }

    /**
     * Set the renderer to use to generate one-time passwords from HMACs.
     *
     * @param \Equit\Totp\Renderers\Renderer $renderer The renderer.
     */
    public function setRenderer(Renderer $renderer): void
    {
        $this->m_renderer = $renderer;
    }

    /**
     * Fetch the size of the time step at which the one-time password changes, in seconds.
     *
     * @return int The time step.
     */
    public function timeStep(): int
    {
        return $this->m_timeStep;
    }

    /**
     * @param int $timeStep
     *
     * @throws InvalidTimeStepException
     */
    public function setTimeStep(int $timeStep): void
    {
        if (1 > $timeStep) {
            throw new InvalidTimeStepException($timeStep, "The time step for a TOTP must be >= 1 second.");
        }

        $this->m_timeStep = $timeStep;
    }

    /**
     * Fetch the reference time from which time steps are measured.
     *
     * The reference time is returned as the number of seconds since the Unix epoch.
     *
     * @return int The reference time number of seconds.
     */
    public function referenceTimestamp(): int
    {
        return $this->m_referenceTime;
    }

    /**
     * The reference time from which time steps are measured as a DateTime object.
     *
     * @return \DateTime The reference time.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor doesn't throw with Unix timestamp.
     */
    public function referenceTime(): DateTime
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor doesn't throw with Unix timestamp. */
        return new DateTime("@{$this->m_referenceTime}", new DateTimeZone("UTC"));
    }

    /**
     * Set the reference time from which time steps are generated.
     *
     * The reference time can be set either as an integer number of seconds since the Unix epoch or as a PHP DateTime
     * object. If using a DateTime object, make sure you know what time it represents in UTC since it is the number of
     * seconds since 1970-01-01 00:00:00 UTC that will be used as the reference time. (In effect, the DateTime you
     * provide is converted to UTC before the number of seconds is calculated.)
     *
     * @param int|\DateTime $referenceTime The
     *
     * @return void
     */
    public function setReferenceTime(int|DateTime $referenceTime): void
    {
        if ($referenceTime instanceof DateTime) {
            $referenceTime = $referenceTime->getTimestamp();
        }

        $this->m_referenceTime = $referenceTime;
    }

    /**
     * Fetch the counter at a given time.
     *
     * This method retrieves the number of time steps that have passed between the reference time and the time provided.
     * This is returned as an integer in the native byte order of the underlying platform. It may be 32-bit or 64-bit.
     * It is important to note that this is not necessarily the set of bytes that will be used for the counter when the
     * HMAC is generated for the TOTP, since the specification mandates that a 64-bit integer in big-endian byte order
     * is required for that purpose. The counterBytesAt() and counterBytes() methods provide the actual data that is
     * used when generating the HMAC.
     *
     * @param \DateTime|int $time The time at which the counter is sought.
     *
     * @return int The number of time steps between the reference time and the provided time.
     * @throws InvalidTimeException if the requested time is before the reference time.
     */
    public final function counterAt(DateTime|int $time): int
    {
        if ($time instanceof DateTime) {
            $time = $time->getTimestamp();
        }

        if ($time < $this->referenceTimestamp()) {
            throw new InvalidTimeException(($time instanceof DateTime ? $time->getTimestamp() : $time), "The time at which the counter was requested is before the reference time.");
        }

        return (int)floor(($time - $this->referenceTimestamp()) / $this->timeStep());
    }

    /**
     * Fetch the HOTP counter for the current system time.
     *
     * This method retrieves the number of time steps that have passed between the reference time and the current time.
     * This is returned as an integer in the native byte order of the underlying platform. It may be 32-bit or 64-bit.
     * It is important to note that this is not necessarily the set of bytes that will be used for the counter when the
     * HMAC is generated for the TOTP, since the specification mandates that a 64-bit integer in big-endian byte order
     * is required for that purpose. Specifically, the value will not be the correct bit pattern for generating the
     * HOTP if either of the following is true:
     * - the size of a PHP int on the platform is not 64 bits
     * - the byte order of a PHP int on the platform is not big-endian
     *
     * The counterBytesAt() and counterBytes() methods provide the actual data that is used when generating the HMAC.
     *
     * This method is provided as a convenience to use, for example when determining whether a submitted OTP has already
     * been used to authenticate.
     *
     * @return int The number of time steps between the reference time and the current time.
     * @throws InvalidTimeException if the current system time is before the reference time.
     */
    public final function counter(): int
    {
        return $this->counterAt(self::currentTime());
    }

    /**
     * Fetch the HOTP counter bytes at a specified time.
     *
     * @param \DateTime|int $time The time at which the counter is sought.
     *
     * @return string The 64 bits of the counter, in BIG ENDIAN format.
     * @throws InvalidTimeException if the requested time is before the reference time.
     */
    protected final function counterBytesAt(DateTime|int $time): string
    {
        return pack("J", $this->counterAt($time));
    }

    /**
     * Fetch the HOTP counter bytes for the current system time.
     *
     * @return string The 64 bits of the counter, in BIG ENDIAN format.
     * @throws InvalidTimeException if the current time is before the reference time.
     */
    protected final function counterBytes(): string
    {
        return $this->counterBytesAt(self::currentTime());
    }

    /**
     * Fetch the raw TOTP HMAC at a given time.
     *
     * This is the raw byte sequence generated using the secret, reference time and time step.
     *
     * @param \DateTime|int $time The time at which the hmac is sought.
     *
     * @return string The current HMAC for the given point in tim.
     * @throws InvalidTimeException if the requested time is before the reference time.
     */
    public final function hmacAt(DateTime|int $time): string
    {
        return hash_hmac($this->hashAlgorithm(), $this->counterBytesAt($time), $this->secret(), true);
    }

    /**
     * Fetch the raw TOTP HMAC for the current system time.
     *
     * This is the raw byte sequence generated using the secret, reference time and time step.
     *
     * @return string The HMAC at the current system time.
     * @throws InvalidTimeException if the current time is before the reference time.
     */
    public final function hmac(): string
    {
        return $this->hmacAt(self::currentTime());
    }

    /**
     * Fetch the one-time password at a given point in time.
     *
     * @param \DateTime|int $time The time at which the password is sought.
     *
     * @return string The one-time password for the given point in time, formatted for display.
     * @throws InvalidTimeException if the requested time is before the reference time.
     */
    public final function passwordAt(DateTime|int $time): string
    {
        return $this->renderer()->render($this->hmacAt($time));
    }

    /**
     * Fetch the one-time password for the current system time.
     *
     * @return string The current TOTP password.
     * @throws InvalidTimeException if the current time is before the reference time.
     */
    public final function password(): string
    {
        return $this->passwordAt(self::currentTime());
    }

    /**
     * Verify that a user-supplied input matches the one-time password at a given point in time.
     *
     * Use the window to accept passwords up to N time steps old. N must be >= 0. If N is 0, only the password at the
     * specified time will be accepted; if it is 1, the password at the specified time and the password for the
     * immediately preceding time step will be considered acceptable; and so on. It is not possible to accept passwords
     * from prior to the reference time - if this is attempted (i.e. the window is too large) an
     * InvalidVerificationWindowException will be thrown.
     *
     * You are strongly encouraged NOT to use windows larger than 1 in your application.
     *
     * Note that this method does not verify that the password has not been used for a previous authentication - it is
     * the consuming application's responsibility to ensure that one-time passwords are not re-used.
     *
     * @param string $password The user-supplied password.
     * @param \DateTime|int $time The time at which to verify the user-supplied password matches the TOTP.
     * @param int $window The window of acceptable passwords, measured in time steps before the specified time.
     *
     * @return bool
     * @throws InvalidVerificationWindowException if the window is < 0 or extends before the reference time.
     * @throws InvalidTimeException if the requested time is before the reference time.
     */
    public final function verifyAt(string $password, DateTime|int $time, int $window = 0): bool
    {
        if (0 > $window) {
            throw new InvalidVerificationWindowException($window, "The verification window must be >= 0.", self::ErrNegativeWindow);
        }

        if ($time instanceof DateTime) {
            $time = $time->getTimestamp();
        }

        if ($time < $this->referenceTimestamp()) {
            throw new InvalidTimeException($time, "The time at which to verify the password is before the TOTP's reference time.");
        }

        $threshold = $time - ($window * $this->timeStep());

        if ($threshold < $this->referenceTimestamp()) {
            throw new InvalidVerificationWindowException($window, "The verification window would extend before the reference time for the TOTP.", self::ErrWindowViolatesReferenceTime);
        }

        while ($time >= $threshold) {
            if ($password === $this->passwordAt($time)) {
                return true;
            }

            $time -= $this->timeStep();
        }

        return false;
    }

    /**
     * Verify that some user input matches the current one-time password.
     *
     * Use the window to accept passwords up to N time steps old. N must be >= 0. If N is 0, only the password at the
     * current system time will be accepted; if it is 1, the password at the current system time and the password for
     * the immediately preceding time step will be considered acceptable; and so on. It is not possible to accept
     * passwords from prior to the reference time - if this is attempted (i.e. the window is too large) an
     * InvalidVerificationWindowException will be thrown.
     *
     * You are strongly encouraged NOT to use windows larger than 1 in your application.
     *
     * Note that this method does not verify that the password has not been used for a previous authentication - it is
     * the consuming application's responsibility to ensure that one-time passwords are not re-used.
     *
     * @param string $password The user-supplied password.
     * @param int $window The window of acceptable passwords, measured in time steps.
     *
     * @return bool true if the password is verified, false if not.
     * @throws InvalidVerificationWindowException if the window is < 0.
     * @throws InvalidTimeException if the current system time is before the reference time.
     */
    public final function verify(string $password, int $window = 0): bool
    {
        return $this->verifyAt($password, self::currentTime(), $window);
    }

    /**
     * Helper to get the current time.
     *
     * @return \DateTime The current time.
     * @noinspection PhpDocMissingThrowsInspection the DateTime constructor does not throw with "now".
     */
    protected static final function currentTime(): DateTime
    {
        /** @noinspection PhpUnhandledExceptionInspection the DateTime constructor does not throw with "now". */
        return new DateTime("now", new DateTimeZone("UTC"));
    }
}
