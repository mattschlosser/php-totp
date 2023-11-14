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
use Equit\Totp\Contracts\Renderer;
use Equit\Totp\Contracts\TotpFactory as TotpFactoryContract;
use Equit\Totp\Exceptions\InvalidHashAlgorithmException;
use Equit\Totp\Exceptions\InvalidSecretException;
use Equit\Totp\Exceptions\InvalidTimeStepException;
use Equit\Totp\Exceptions\SecureRandomDataUnavailableException;
use Equit\Totp\Renderers\EightDigits;
use Equit\Totp\Renderers\Integer;
use Equit\Totp\Renderers\SixDigits;
use Equit\Totp\Traits\SecurelyErasesProperties;
use Exception;

/**
 * Class for generating Time-based One-Time Passwords.
 *
 * RFC 6238 does not say anything on the subject of whether T0 (the reference timestamp) can be a negative value, only
 * that the timestamp integer type used must enable the authentication time to extend beyond 2038 (i.e not a 32-bit
 * integer). Since it mentions nothing regarding the signedness of T0, this implementation does not forbid reference
 * times before the Unix epoch (i.e. -ve timestamps).
 */
class TotpFactory implements TotpFactoryContract
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
        $this->withRenderer($renderer ?? static::defaultRenderer());
        $this->withTimeStep($timeStep);
        $this->withHashAlgorithm($hashAlgorithm);
        $this->m_referenceTime = ($referenceTime instanceof DateTime ? $referenceTime->getTimestamp() : $referenceTime);
    }

    public function __clone(): void
    {
        $this->m_renderer = clone $this->m_renderer;
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
     * @return TotpFactory
     * @throws \Equit\Totp\Exceptions\InvalidHashAlgorithmException If the supplied hashing algorithm is not one
     * supported by TOTP.
     * @throws \Equit\Totp\Exceptions\InvalidTimeStepException if the time step is < 1.
     * @throws \Equit\Totp\Exceptions\InvalidSecretException if the provided secret is less than 128 bits in length.
     * @throws \Equit\Totp\Exceptions\SecureRandomDataUnavailableException
     * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
     *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
     */
    public static function sixDigits(TotpSecret|string $secret = null, int $timeStep = self::DefaultTimeStep, int|DateTime $referenceTime = self::DefaultReferenceTime, string $hashAlgorithm = self::DefaultAlgorithm): TotpFactory
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        return new TotpFactory(secret: $secret, renderer: new SixDigits(), timeStep: $timeStep, referenceTime: $referenceTime, hashAlgorithm: $hashAlgorithm);
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
     * @return TotpFactory
     * @throws \Equit\Totp\Exceptions\InvalidHashAlgorithmException If the supplied hashing algorithm is not one
     * supported by TOTP.
     * @throws \Equit\Totp\Exceptions\InvalidTimeStepException if the time step is < 1.
     * @throws \Equit\Totp\Exceptions\InvalidSecretException if the provided secret is less than 128 bits in length.
     * @throws \Equit\Totp\Exceptions\SecureRandomDataUnavailableException
     * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
     *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
     */
    public static function eightDigits(TotpSecret|string $secret = null, int $timeStep = self::DefaultTimeStep, int|DateTime $referenceTime = self::DefaultReferenceTime, string $hashAlgorithm = self::DefaultAlgorithm): TotpFactory
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        return new TotpFactory(secret: $secret, renderer: new EightDigits(), timeStep: $timeStep, referenceTime: $referenceTime, hashAlgorithm: $hashAlgorithm);
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
     * @return TotpFactory
     * @throws \Equit\Totp\Exceptions\InvalidHashAlgorithmException If the supplied hashing algorithm is not one
     * supported by TOTP.
     * @throws \Equit\Totp\Exceptions\InvalidDigitsException if the number of digits is < 1.
     * @throws \Equit\Totp\Exceptions\InvalidTimeStepException if the time step is < 1.
     * @throws \Equit\Totp\Exceptions\InvalidSecretException if the provided secret is less than 128 bits in length.
     * @throws \Equit\Totp\Exceptions\SecureRandomDataUnavailableException
     * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
     *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
     */
    public static function integer(int $digits, TotpSecret|string $secret = null, int $timeStep = self::DefaultTimeStep, int|DateTime $referenceTime = self::DefaultReferenceTime, string $hashAlgorithm = self::DefaultAlgorithm): TotpFactory
    {
        return new TotpFactory(secret: $secret, renderer: new Integer($digits), timeStep: $timeStep, referenceTime: $referenceTime, hashAlgorithm: $hashAlgorithm);
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
     * @return $this
     * @throws InvalidHashAlgorithmException if the hash algorithm provided is not valid.
     */
    public function withHashAlgorithm(string $hashAlgorithm): self
    {
        $clone = clone $this;
        $clone->m_hashAlgorithm = match ($hashAlgorithm) {
            self::Sha1Algorithm, self::Sha256Algorithm, self::Sha512Algorithm => $hashAlgorithm,
            default => throw new InvalidHashAlgorithmException($hashAlgorithm, "The hash algorithm must be one of " . self::Sha1Algorithm . ", " . self::Sha256Algorithm . " or " . self::Sha512Algorithm . "."),
        };
        return $clone;
    }

    /**
     * Fetch the renderer being used to generate one-time passwords from HMACs.
     *
     * @return string The renderer's name.
     */
    public function renderer(): string
    {
        return $this->m_renderer->name();
    }

    /**
     * Set the renderer to use to generate one-time passwords from HMACs.
     *
     * @param Renderer $renderer The renderer.
     * @return $this
     */
    public function withRenderer(Renderer $renderer): self
    {
        $clone = clone $this;
        $clone->m_renderer = $renderer;
        return $clone;
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
     * @return $this
     * @throws InvalidTimeStepException
     */
    public function withTimeStep(int $timeStep): self
    {
        if (1 > $timeStep) {
            throw new InvalidTimeStepException($timeStep, "The time step for a TOTP must be >= 1 second.");
        }

        $clone = clone $this;
        $clone->m_timeStep = $timeStep;
        return $clone;
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
     * @return $this
     */
    public function withReferenceTime(int|DateTime $referenceTime): self
    {
        if ($referenceTime instanceof DateTime) {
            $referenceTime = $referenceTime->getTimestamp();
        }

        $clone = clone $this;
        $clone->m_referenceTime = $referenceTime;
        return $clone;
    }

    /**
     * Produce a TOTP calculator for a given secret.
     *
     * @param TotpSecret|string $secret
     * @return Totp
     * @throws InvalidSecretException
     * @throws InvalidTimeStepException
     */
    public function totp(TotpSecret|string $secret): Totp
    {
        // NOTE the Totp constructor will clone the renderer.
        return new Totp($secret, $this->m_renderer, $this->timeStep(), $this->referenceTimestamp(), $this->hashAlgorithm());
    }
}
