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
use Equit\Totp\Exceptions\InvalidDigitsException;
use Equit\Totp\Exceptions\InvalidHashAlgorithmException;
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
     * @var string The hashing algorithm to use when generating HMACs.
     */
    private string $hashAlgorithm;

    /**
     * @var TotpSecret The secret for password generation.
     */
    private TotpSecret $secret;

    /**
     * @var int The time step, in seconds, at which the password changes.
     */
    private int $timeStep;

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
     * @param TotpSecret|null $secret The TOTP secret. If null, a cryptographically secure random secret is chosen.
     * @param Renderer|null $renderer The renderer that produces one-time passwords from HMACs.
     * @param TotpTimeStep|null $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param string $hashAlgorithm The hash algorithm to use when generating OTPs. Must be one of the algorithm class
     * constants. Defaults to Sha1Algorithm.
     *
     * @throws InvalidHashAlgorithmException if the provided hash algorithm is not one of the supported algorithms. See
     * the class constants.
     * @throws SecureRandomDataUnavailableException if a randomly-generated secret is required but a
     * source of cryptographically-secure random data is not available.
     */
    public function __construct(?TotpSecret $secret = null, ?Renderer $renderer = null, ?TotpTimeStep $timeStep = null, int|DateTime $referenceTime = self::DefaultReferenceTime, string $hashAlgorithm = self::DefaultAlgorithm)
    {
        self::checkHashAlgorithm($hashAlgorithm);
        $this->secret = $secret ?? static::randomSecret();
        $this->renderer = $renderer ?? static::defaultRenderer();
        $this->timeStep = $timeStep?->seconds() ?? self::DefaultTimeStep;
        $this->hashAlgorithm = $hashAlgorithm;
        $this->referenceTime = ($referenceTime instanceof DateTime ? $referenceTime->getTimestamp() : $referenceTime);
    }

    /** @throws InvalidHashAlgorithmException if the hash algorithm is not supported. */
    private static function checkHashAlgorithm(string $algorithm): void
    {
        switch ($algorithm) {
            case self::Sha1Algorithm:
            case self::Sha256Algorithm:
            case self::Sha512Algorithm:
                return;
        }

        throw new InvalidHashAlgorithmException($algorithm, "The hash algorithm must be one of " . self::Sha1Algorithm . ", " . self::Sha256Algorithm . " or " . self::Sha512Algorithm . ".");
    }

    public function __clone(): void
    {
        $this->renderer = clone $this->renderer;
    }

    /**
     * Helper to generate a random secret.
     *
     * The constructor uses this if no secret is provided. The secret is guaranteed to be valid for a TOTP. Currently
     * it is always 64 bytes (512 bits) in length so that it is sufficiently strong for all the supported algorithms.
     *
     * @return TotpSecret The random secret.
     * @throws SecureRandomDataUnavailableException if a known source of cryptographically secure random data is
     * not available.
     */
    public static final function randomSecret(): TotpSecret
    {
        try {
            return TotpSecret::fromRaw(random_bytes(64));
        }
        catch (Exception $e) {
            if (function_exists("openssl_random_pseudo_bytes")) {
                $secret = openssl_random_pseudo_bytes(64, $isStrong);


                if (is_string($secret) && $isStrong) {
                    // this is guaranteed not to throw
                    return TotpSecret::fromRaw($secret);
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
     * @param TotpSecret|null $secret The TOTP secret. If null, a cryptographically secure random secret will be chosen.
     * @param TotpTimeStep|null $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param string $hashAlgorithm The hash algorithm to use when generating OTPs. Must be one of the algorithm class
     * constants. Defaults to Sha1Algorithm.
     *
     * @return TotpFactory
     * @throws InvalidHashAlgorithmException If the supplied hashing algorithm is not one
     * supported by TOTP.
     * @throws SecureRandomDataUnavailableException
     * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
     *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
     */
    public static function sixDigits(?TotpSecret $secret = null, TotpTimeStep $timeStep = null, int|DateTime $referenceTime = self::DefaultReferenceTime, string $hashAlgorithm = self::DefaultAlgorithm): TotpFactory
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        return new TotpFactory(secret: $secret, renderer: new SixDigits(), timeStep: $timeStep, referenceTime: $referenceTime, hashAlgorithm: $hashAlgorithm);
    }

    /**
     * Instantiate a TOTP generator with an eight-digit integer password renderer.
     *
     * This is a convenience factory function for a commonly-used type of TOTP.
     *
     * @param TotpSecret|null $secret The TOTP secret. If null, a cryptographically secure random secret will be chosen.
     * @param TotpTimeStep|null $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param string $hashAlgorithm The hash algorithm to use when generating OTPs. Must be one of the algorithm class
     * constants. Defaults to Sha1Algorithm.
     *
     * @return TotpFactory
     * @throws InvalidHashAlgorithmException If the supplied hashing algorithm is not one
     * supported by TOTP.
     * @throws SecureRandomDataUnavailableException
     * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
     *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
     */
    public static function eightDigits(?TotpSecret $secret = null, TotpTimeStep $timeStep = null, int|DateTime $referenceTime = self::DefaultReferenceTime, string $hashAlgorithm = self::DefaultAlgorithm): TotpFactory
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
     * @param TotpSecret|null $secret The TOTP secret. If null, a cryptographically secure random secret will be chosen.
     * @param TotpTimeStep|null $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param string $hashAlgorithm The hash algorithm to use when generating OTPs. Must be one of the algorithm class
     * constants. Defaults to Sha1Algorithm.
     *
     * @return TotpFactory
     * @throws InvalidHashAlgorithmException If the supplied hashing algorithm is not one
     * supported by TOTP.
     * @throws InvalidDigitsException if the number of digits is < 1.
     * @throws SecureRandomDataUnavailableException
     * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
     *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
     */
    public static function integer(int $digits, ?TotpSecret $secret = null, ?TotpTimeStep $timeStep = null, int|DateTime $referenceTime = self::DefaultReferenceTime, string $hashAlgorithm = self::DefaultAlgorithm): TotpFactory
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
        return $this->hashAlgorithm;
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
        self::checkHashAlgorithm($hashAlgorithm);
        $clone = clone $this;
        $clone->hashAlgorithm = $hashAlgorithm;
        return $clone;
    }

    /**
     * Fetch the renderer being used to generate one-time passwords from HMACs.
     *
     * @return string The renderer's name.
     */
    public function renderer(): string
    {
        return $this->renderer->name();
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
        $clone->renderer = $renderer;
        return $clone;
    }

    /**
     * Fetch the size of the time step at which the one-time password changes, in seconds.
     *
     * @return int The time step.
     */
    public function timeStep(): int
    {
        return $this->timeStep;
    }

    /**
     * @param TotpTimeStep $timeStep
     * @return $this
     */
    public function withTimeStep(TotpTimeStep $timeStep): self
    {
        $clone = clone $this;
        $clone->timeStep = $timeStep->seconds();
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
        return $this->referenceTime;
    }

    /**
     * The reference time from which time steps are measured as a DateTime object.
     *
     * @return DateTime The reference time.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor doesn't throw with Unix timestamp.
     */
    public function referenceTime(): DateTime
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor doesn't throw with Unix timestamp. */
        return new DateTime("@{$this->referenceTime}", new DateTimeZone("UTC"));
    }

    /**
     * Set the reference time from which time steps are generated.
     *
     * The reference time can be set either as an integer number of seconds since the Unix epoch or as a PHP DateTime
     * object. If using a DateTime object, make sure you know what time it represents in UTC since it is the number of
     * seconds since 1970-01-01 00:00:00 UTC that will be used as the reference time. (In effect, the DateTime you
     * provide is converted to UTC before the number of seconds is calculated.)
     *
     * @param int|DateTime $referenceTime The
     * @return $this
     */
    public function withReferenceTime(int|DateTime $referenceTime): self
    {
        if ($referenceTime instanceof DateTime) {
            $referenceTime = $referenceTime->getTimestamp();
        }

        $clone = clone $this;
        $clone->referenceTime = $referenceTime;
        return $clone;
    }

    /**
     * Produce a TOTP calculator for a given secret.
     *
     * @param TotpSecret $secret
     * @return Totp
     * @throws InvalidTimeStepException
     */
    public function totp(TotpSecret $secret): Totp
    {
        // NOTE the Totp constructor will clone the renderer, and the time step is guaranteed to be valid
        return new Totp($secret, $this->renderer, new TotpTimeStep($this->timeStep()), $this->referenceTimestamp(), $this->hashAlgorithm());
    }
}
