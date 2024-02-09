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

namespace Equit\Totp;

use DateTime;
use DateTimeZone;
use Equit\Totp\Codecs\Base32;
use Equit\Totp\Codecs\Base64;
use Equit\Totp\Contracts\Renderer;
use Equit\Totp\Contracts\Totp as TotpContract;
use Equit\Totp\Exceptions\InvalidTimeException;
use Equit\Totp\Exceptions\InvalidVerificationWindowException;
use Equit\Totp\Traits\SecurelyErasesProperties;
use Equit\Totp\Types\HashAlgorithm;
use Equit\Totp\Types\Secret;
use Equit\Totp\Types\TimeStep;

/**
 * Generates and verifies time-based one-time passcodes.
 *
 * RFC 6238 does not say anything on the subject of whether T0 (the reference timestamp) can be a negative value, only
 * that the timestamp integer type used must enable the authentication time to extend beyond 2038 (i.e not a 32-bit
 * integer). Since it mentions nothing regarding the signedness of T0, this implementation does not forbid reference
 * times before the Unix epoch (i.e. -ve timestamps).
 */
class Totp implements TotpContract
{
    /** Ensure all string properties are securely erased on destruction. */
    use SecurelyErasesProperties;

    /** Error code for InvalidVerificationWindowException when the window is < 0. */
    public const ErrNegativeWindow = 1;

    /**
     * Error code for InvalidVerificationWindowException when the window would cause verification of passwords from
     * before the reference time.
     */
    public const ErrWindowViolatesReferenceTime = 2;

    /**
     * @var HashAlgorithm The hashing algorithm to use when generating HMACs.
     */
    private HashAlgorithm $hashAlgorithm;

    /**
     * @var string The secret for password generation.
     */
    private string $secret;

    /**
     * @var TimeStep The time step, in seconds, at which the password changes.
     */
    private TimeStep $timeStep;

    /**
     * @var int The reference time from new password generation time steps are measured.
     */
    private int $referenceTime;

    /**
     * @var Renderer The renderer that will perform the truncation that turns the computed HMAC into a user-readable
     * one-time password.
     */
    private Renderer $renderer;

    /**
     * Initialise a new TOTP.
     *
     * If the reference time is specified as an int, it is interpreted as the number of seconds since the Unix epoch.
     * The default hashing algorithm is SHA1.
     *
     * @param Secret $secret The TOTP secret.
     * @param Renderer $renderer The renderer that produces one-time passwords from HMACs.
     * @param TimeStep $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param HashAlgorithm $hashAlgorithm The hash algorithm to use when generating OTPs. Must be one of the algorithm class
     * constants. Defaults to Sha1Algorithm.
     */
    public function __construct(Secret $secret, Renderer $renderer, TimeStep $timeStep, int|DateTime $referenceTime, HashAlgorithm $hashAlgorithm)
    {
        $this->secret = $secret->raw();
        $this->renderer = clone $renderer;
        $this->timeStep = $timeStep;
        $this->hashAlgorithm = $hashAlgorithm;
        $this->referenceTime = ($referenceTime instanceof DateTime ? $referenceTime->getTimestamp() : $referenceTime);
    }

    /**
     * Fetch the hashing algorithm to use to generate HMACs.
     *
     * @return HashAlgorithm The hashing algorithm.
     */
    public function hashAlgorithm(): HashAlgorithm
    {
        return $this->hashAlgorithm;
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
        return $this->secret;
    }

    /**
     * @api
     * @return string The secret, base32 encoded so that it's printable.
     */
    public function base32Secret(): string
    {
        return Base32::encode($this->secret());
    }

    /**
     * @api
     * @return string The secret, base64 encoded so that it's printable.
     */
    public function base64Secret(): string
    {
        return Base64::encode($this->secret());
    }

    /**
     * Fetch the renderer being used to generate one-time passwords from HMACs.
     *
     * @return string The name of the passcode renderer.
     */
    public function renderer(): string
    {
        return $this->renderer->name();
    }


    /**
     * Fetch the size of the time step at which the one-time password changes, in seconds.
     *
     * @return TimeStep The time step.
     */
    public function timeStep(): TimeStep
    {
        return $this->timeStep;
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
        return $this->referenceTime;
    }

    /**
     * The reference time from which time steps are measured as a DateTime object.
     *
     * @api
     * @return DateTime The reference time.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor doesn't throw with Unix timestamp.
     */
    public function referenceTime(): DateTime
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor doesn't throw with Unix timestamp. */
        return new DateTime("@{$this->referenceTime}", new DateTimeZone("UTC"));
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
     * @param DateTime|int $time The time at which the counter is sought.
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

        return (int) floor(($time - $this->referenceTimestamp()) / $this->timeStep()->seconds());
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
     * @api
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
     * @api
     * @param DateTime|int $time The time at which the counter is sought.
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
     * @api
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
     * @api
     * @param DateTime|int $time The time at which the hmac is sought.
     *
     * @return string The current HMAC for the given point in tim.
     * @throws InvalidTimeException if the requested time is before the reference time.
     */
    public final function hmacAt(DateTime|int $time): string
    {
        return hash_hmac((string) $this->hashAlgorithm(), $this->counterBytesAt($time), $this->secret(), true);
    }

    /**
     * Fetch the raw TOTP HMAC for the current system time.
     *
     * This is the raw byte sequence generated using the secret, reference time and time step.
     *
     * @api
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
     * @api
     * @param DateTime|int $time The time at which the password is sought.
     *
     * @return string The one-time password for the given point in time, formatted for display.
     * @throws InvalidTimeException if the requested time is before the reference time.
     */
    public final function passwordAt(DateTime|int $time): string
    {
        return $this->renderer->render($this->hmacAt($time));
    }

    /**
     * Fetch the one-time password for the current system time.
     *
     * @api
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
     * @api
     * @param string $password The user-supplied password.
     * @param DateTime|int $time The time at which to verify the user-supplied password matches the TOTP.
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

        $threshold = $time - ($window * $this->timeStep()->seconds());

        if ($threshold < $this->referenceTimestamp()) {
            throw new InvalidVerificationWindowException($window, "The verification window would extend before the reference time for the TOTP.", self::ErrWindowViolatesReferenceTime);
        }

        while ($time >= $threshold) {
            if ($password === $this->passwordAt($time)) {
                return true;
            }

            $time -= $this->timeStep()->seconds();
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
     * @api
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
     * @return DateTime The current time.
     * @noinspection PhpDocMissingThrowsInspection the DateTime constructor does not throw with "now".
     */
    protected static final function currentTime(): DateTime
    {
        /** @noinspection PhpUnhandledExceptionInspection the DateTime constructor does not throw with "now". */
        return new DateTime("now", new DateTimeZone("UTC"));
    }
}
