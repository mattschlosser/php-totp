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

namespace Equit\Totp;

use Equit\Totp\Exceptions\SecureRandomDataUnavailableException;
use Equit\Totp\Exceptions\InvalidDigitsException;
use Equit\Totp\Exceptions\InvalidHashAlgorithmException;
use Equit\Totp\Exceptions\InvalidSecretException;
use Equit\Totp\Exceptions\InvalidIntervalException;
use Equit\Totp\Exceptions\InvalidTimeException;
use Equit\Totp\Exceptions\InvalidVerificationWindowException;
use DateTime;
use DateTimeZone;
use Equit\Totp\Renderers\EightDigits;
use Equit\Totp\Renderers\Integer;
use Equit\Totp\Renderers\SixDigits;
use Exception;

/**
 * Class for generating Time-based One-Time Passwords.
 */
class Totp
{
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
	protected const DefaultAlgorithm = self::Sha1Algorithm;

   /**
     * The default update interval for codes.
     */
    public const DefaultInterval = 30;

    /**
     * The default reference time for codes.
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
     * @var string The secret for the code.
     */
    private string $m_secret;

    /**
     * @var int The interval, in seconds, at which the code changes.
     */
    private int $m_interval;

    /**
     * @var int The reference time against which codes are generated.
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
	 * @param TotpSecret|string|null $secret The secret for the code. If given as a string, it's assumed to be raw.
	 * @param Renderer|null $renderer The renderer that produces one-time passwords from HMACs.
	 * @param int $interval The update interval for the code. Defaults to 30 seconds.
	 * @param int|DateTime $referenceTime The reference time from which the code is generated.
	 * Defaults to 0.
	 *
	 * @throws InvalidIntervalException if the interval is not a positive integer.
	 * @throws InvalidSecretException if the provided secret is less than 128 bits in length.
	 * @throws InvalidHashAlgorithmException if the provided hash algorithm is not one of the supported algorithms. See
	 * the class constants.
	 * @throws SecureRandomDataUnavailableException if a randomly-generated secret is required but a
	 * source of cryptographically-secure random data is not available.
	 */
    public function __construct(TotpSecret | string $secret = null, Renderer $renderer = null, int $interval = self::DefaultInterval, int | DateTime $referenceTime = self::DefaultReferenceTime, string $hashAlgorithm = self::DefaultAlgorithm)
    {
        $this->setSecret($secret ?? self::randomSecret());
		$this->setRenderer($renderer ?? static::defaultRenderer());
        $this->setInterval($interval);
		$this->setHashAlgorithm($hashAlgorithm);
        $this->m_referenceTime = $referenceTime;
    }

	/**
	 * Helper to generate a random secret.
	 *
	 * The constructor uses this if no secret is provided. The secret is 64 bytes (512 bits) in length so that it is
	 * sufficiently strong for all the supported algorithms.
	 *
	 * @return string The random secret.
	 * @throws SecureRandomDataUnavailableException if random_bytes() is unable to generate
	 * cryptographically secure random data.
	 */
	public static function randomSecret(): string
	{
		try {
			return random_bytes(64);
		} catch (Exception $e) {
			throw new SecureRandomDataUnavailableException($e->getMessage(), $e->getCode(), $e);
		}
	}

	/**
	 * Instantiate a TOTP generator with a six-digit integer password renderer.
	 *
	 * This is a convenience factory function for a commonly-used type of TOTP.
	 *
	 * @param string $secret The secret for the code. This must be the binary representation of the secret.
	 * @param int $interval The update interval for the code. Defaults to 30 seconds.
	 * @param int|DateTime $referenceTime The reference time from which the code is generated.
	 * Defaults to 0.
	 *
	 * @return Totp
	 * @throws \Equit\Totp\Exceptions\InvalidIntervalException if the interval is < 1.
	 * @throws \Equit\Totp\Exceptions\InvalidSecretException if the provided secret is less than 128 bits in length.
	 * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
	 *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
	 */
	public static function sixDigitTotp(string $secret, int $interval = self::DefaultInterval, int | DateTime $referenceTime = self::DefaultReferenceTime): Totp
	{
		/** @noinspection PhpUnhandledExceptionInspection */
		return new Totp($secret, new SixDigits(), $interval, $referenceTime);
	}

	/**
	 * Instantiate a TOTP generator with an eight-digit integer password renderer.
	 *
	 * This is a convenience factory function for a commonly-used type of TOTP.
	 *
	 * @param string $secret The secret for the code. This must be the binary representation of the secret.
	 * @param int $interval The update interval for the code. Defaults to 30 seconds.
	 * @param int|\DateTime $referenceTime The reference time from which the code is generated.
	 * Defaults to 0.
	 *
	 * @return Totp
	 * @throws InvalidIntervalException if the interval is < 1.
	 * @throws InvalidSecretException if the provided secret is less than 128 bits in length.
	 * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
	 *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
	 */
	public static function eightDigitTotp(string $secret, int $interval = self::DefaultInterval, int | DateTime $referenceTime = self::DefaultReferenceTime): Totp
	{
		/** @noinspection PhpUnhandledExceptionInspection */
		return new Totp($secret, new EightDigits(), $interval, $referenceTime);
	}

	/**
	 * Instantiate a TOTP generator with an integer password renderer of a given number of digits.
	 *
	 * This is a convenience factory function for commonly-used types of TOTP.
	 *
	 * @param string $secret The secret for the code. This must be the binary representation of the secret.
	 * @param int $digits The number of digits in generated one-time passwords.
	 * @param int $interval The update interval for the code. Defaults to 30 seconds.
	 * @param int|\DateTime $referenceTime The reference time from which the code is generated.
	 * Defaults to 0.
	 *
	 * @return Totp
	 * @throws InvalidIntervalException if the interval is < 1.
	 * @throws InvalidSecretException if the provided secret is less than 128 bits in length.
	 * @throws InvalidDigitsException if the number of digits is < 1.
	 * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
	 *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
	 */
	public static function integerTotp(string $secret, int $digits, int $interval = self::DefaultInterval, int | DateTime $referenceTime = self::DefaultReferenceTime): Totp
	{
		/** @noinspection PhpUnhandledExceptionInspection */
		return new Totp($secret, new Integer($digits), $interval, $referenceTime);
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
	 * Set the algorithm to use when generating HMACs.
	 *
	 * The algorithm must be one of SHA1, SHA256 or SHA512. Use the class constants for these to avoid errors.
	 *
	 * @param string $algorithm The algorithm.
	 *
	 * @throws InvalidHashAlgorithmException if the algorithm provided is not valid.
	 */
	public function setHashAlgorithm(string $algorithm)
	{
		$this->m_hashAlgorithm = match ($algorithm) {
			self::Sha1Algorithm, self::Sha256Algorithm, self::Sha512Algorithm => $algorithm,
			default => throw new InvalidHashAlgorithmException($algorithm, "The hash algorithm must be one of " . self::Sha1Algorithm . ", " . self::Sha256Algorithm . " or " . self::Sha512Algorithm . "."),
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
	 * Set the secret for generated codes.
	 *
	 * The secret must be at least 128 bits (16 bytes) in length, ideally 160 bits. There is minimal value in setting a
	 * secret with more than 160 bits.
	 *
	 * @param TotpSecret|string $secret The secret. If given as a string, the string is assumed to be the raw secret.
	 *
	 * @throws InvalidSecretException if the secret is less than 128 bits in length.
	 */
    public function setSecret(TotpSecret | string $secret)
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
	 * @return \Equit\Totp\Renderer The renderer.
	 */
	public function renderer(): Renderer
	{
		return $this->m_renderer;
	}

	/**
	 * Set the renderer to use to generate one-time passwords from HMACs.
	 *
	 * @param \Equit\Totp\Renderer $renderer The renderer.
	 */
	public function setRenderer(Renderer $renderer)
	{
		$this->m_renderer = $renderer;
	}

    /**
     * Fetch the interval at which the TOTP code changes, in seconds.
     *
     * @return int The interval.
     */
    public function interval(): int
    {
        return $this->m_interval;
    }

    /**
     * @param int $interval
     *
     * @throws InvalidIntervalException
     */
    public function setInterval(int $interval)
    {
        if (1 > $interval) {
            throw new InvalidIntervalException($interval, "The interval for a TOTP must be >= 1 second.");
        }

        $this->m_interval = $interval;
    }

    /**
     * Fetch the reference time against which the TOTP codes will be generated.
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
     * The reference time against which codes are generated as a DateTime object.
     *
     * @return \DateTime The reference time.
     */
    public function referenceDateTime(): DateTime
    {
        return DateTime::createFromFormat("U", "{$this->m_referenceTime}", new DateTimeZone("UTC"));
    }

    /**
     * Set the reference time against which OTP codes are generated.
     *
     * The reference time can be set either as an integer number of seconds since the Unix epoch or as a PHP DateTime object.
     * If using a DateTime object, make sure you know what time it represents in UTC since it is the number of seconds
     * since 1970-01-01 00:00:00 UTC that will be used as the reference time. (In effect, the DateTime you provide is
     * converted to UTC before the number of seconds is calculated.)
     *
     * @param int|\DateTime $referenceTime The
     *
     * @return void
     */
    public function setReferenceTime(int | DateTime $referenceTime)
    {
        if ($referenceTime instanceof DateTime) {
            $referenceTime = $referenceTime->getTimestamp();
        }

        $this->m_referenceTime = $referenceTime;
    }

	/**
	 * Fetch the counter at a given time.
	 *
	 * This method retrieves the number of intervals that have passed between the reference time and the time provided.
	 * This is returned as an integer in the native byte order of the underlying platform. It may be 32-bit or 64-bit.
	 * It is important to note that this is not necessarily the set of bytes that will be used for the counter when the
	 * HMAC is generated for the TOTP, since the specification mandates that a 64-bit integer in big-endian byte order
	 * is required for that purpose. The counterBytesAt() and counterBytes() methods provide the actual data that is
	 * used when generating the HMAC.
	 *
	 * @param \DateTime|int $time The time at which the counter is sought.
	 *
	 * @return int The number of intervals between the base time and the provided time.
	 * @throws InvalidTimeException if the requested time is before the reference time.
	 */
	public final function counterAt(DateTime | int $time): int
	{
		if ($time instanceof DateTime) {
			$time = $time->getTimestamp();
		}

		if ($time < $this->referenceTimestamp()) {
			throw new InvalidTimeException(($time instanceof DateTime ? $time->getTimestamp() : $time), "The time at which the counter was requested is before the reference time.");
		}

		return (int) floor(($time - $this->referenceTimestamp()) / $this->interval());
	}

	/**
	 * Fetch the current counter.
	 *
	 * This method retrieves the number of intervals that have passed between the reference time and the current time.
	 * This is returned as an integer in the native byte order of the underlying platform. It may be 32-bit or 64-bit.
	 * It is important to note that this is not necessarily the set of bytes that will be used for the counter when the
	 * HMAC is generated for the TOTP, since the specification mandates that a 64-bit integer in big-endian byte order
	 * is required for that purpose. The counterBytesAt() and counterBytes() methods provide the actual data that is
	 * used when generating the HMAC.
	 *
	 * @return int The number of intervals between the base time and the current time.
	 * @throws InvalidTimeException if the current time is before the reference time.
	 */
	public final function counter(): int
	{
		return $this->counterAt(self::currentTime());
	}

    /**
     * Fetch the counter for the code at a given time.
     *
     * @param \DateTime|int $time The time at which the counter is sought.
     *
     * @return string The 64 bits of the counter, in BIG ENDIAN format.
	 * @throws InvalidTimeException if the requested time is before the reference time.
     */
    protected final function counterBytesAt(DateTime | int $time): string
    {
        return pack("J", $this->counterAt($time));
    }

    /**
     * Fetch the current counter for the code.
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
     * This is the raw byte sequence generated using the secret, reference time and interval.
     *
     * @param \DateTime|int $time The time at which the hmac is sought.
     *
     * @return string The current TOTP code.
	 * @throws InvalidTimeException if the requested time is before the reference time.
     */
    public final function hmacAt(DateTime | int $time): string
    {
		return hash_hmac($this->hashAlgorithm(), $this->counterBytesAt($time), $this->secret(), true);
    }

    /**
     * Fetch the raw current TOTP HMAC.
     *
     * This is the raw byte sequence generated using the secret, reference time and interval.
     *
     * @return string The current TOTP code.
	 * @throws InvalidTimeException if the current time is before the reference time.
     */
    public final function currentHmac(): string
    {
        return $this->hmacAt(self::currentTime());
    }

    /**
     * Fetch the TOTP password at a given point in time.
     *
     * Subclasses should reimplement this method to produce readable representations of the current raw code.
     * Commonly this is 6- or 8- decimal digits produced according to a defined algorithm that works with the raw
     * code.
     *
     * @param \DateTime|int $time The time at which the password is sought.
     *
     * @return string The current TOTP code, formatted for display.
	 * @throws InvalidTimeException if the requested time is before the reference time.
     */
    public final function passwordAt(DateTime | int $time): string
	{
		return $this->renderer()->render($this->hmacAt($time));
	}

    /**
     * Fetch the current TOTP password.
     *
     * The base implementation delegates to passwordAt().
     *
     * @return string The current TOTP password.
	 * @throws InvalidTimeException if the current time is before the reference time.
     */
    public final function currentPassword(): string
    {
        return $this->passwordAt(self::currentTime());
    }

	/**
	 * Verify that a user-supplied input matches the one-time password at a given point in time.
	 *
	 * Use the window to accept passwords up to N intervals old. It must be >= 0. If it is 0, only the password at the
	 * specified time will be accepted; if it is 1 both the password at the specified time and the one before it will be
	 * accepted, and so on. It is not possible to accept passwords from prior to the reference time - if this is
	 * attempted an InvalidVerificationWindowException will be thrown.
	 *
	 * You are strongly encouraged NOT to use windows larger than 1 in your application.
	 *
	 * Note that this method does not verify that the password has not been used for a previous authentication - it is
	 * the consuming application's responsibility to ensure that one-time passwords are not re-used.
	 *
	 * @param string $password The user-supplied password.
	 * @param \DateTime|int $time The time at which to verify the user-supplied password matches the TOTP.
	 * @param int $window The window of acceptable passwords, measured in intervals before the time.
	 *
	 * @return bool
	 * @throws InvalidVerificationWindowException if the window is < 0 or extends before the reference time.
	 * @throws InvalidTimeException if the requested time is before the reference time.
	 */
	public final function verifyAt(string $password, DateTime | int $time, int $window = 0): bool
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

		$threshold = $time - ($window * $this->interval());

		if ($threshold < $this->referenceTimestamp()) {
			throw new InvalidVerificationWindowException($window, "The verification window would extend before the reference time for the TOTP.", self::ErrWindowViolatesReferenceTime);
		}

		while ($time >= $threshold) {
			if ($password === $this->passwordAt($time)) {
				return true;
			}

			$time -= $this->interval();
		}

		return false;
	}

	/**
	 * Verify that some user input matches the current one-time password.
	 *
	 * Use the window to accept passwords up to N intervals old. It must be >= 0. If it is 0, only the current password
	 * will be accepted; if it is 1 both the current password and the next most recent password will be accepted, and
	 * so on. You are strongly encouraged not to use windows larger than 1 in your application. It is not possible to
	 * accept passwords from prior to the reference time - if this is attempted (by providing a time and window that
	 * refer to times prior to the reference time) the method will stop verifying the provided password at the first
	 * interval.
	 *
	 * You are strongly encouraged NOT to use windows larger than 1 in your application.
	 *
	 * Note that this method does not verify that the password has not been used for a previous authentication - it is
	 * the consuming application's responsibility to ensure that one-time passwords are not re-used.
	 *
	 * @param string $password The user-supplied password.
	 * @param int $window The window of acceptable passwords, measured in intervals.
	 *
	 * @return bool true if the password is verified, false if not.
	 * @throws InvalidVerificationWindowException if the window is < 0.
	 * @throws InvalidTimeException if the current time is before the reference time.
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
