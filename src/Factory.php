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
use Equit\Totp\Contracts\Renderer;
use Equit\Totp\Contracts\Factory as TotpFactoryContract;
use Equit\Totp\Exceptions\InvalidTimeStepException;
use Equit\Totp\Exceptions\SecureRandomDataUnavailableException;
use Equit\Totp\Renderers\EightDigits;
use Equit\Totp\Renderers\Integer;
use Equit\Totp\Renderers\SixDigits;
use Equit\Totp\Traits\SecurelyErasesProperties;
use Equit\Totp\Types\Digits;
use Equit\Totp\Types\HashAlgorithm;
use Equit\Totp\Types\TimeStep;
use Equit\Totp\Types\Secret;
use Exception;

/**
 * Factory for generating TOTP verifiers.
 *
 * Factories are configured with all the settings for consistently generating TOTP verifiers. To create an instance of
 * a verifier, call totp() with the secret for verifying passwords.
 */
class Factory implements TotpFactoryContract
{
    /** Ensure all string properties are securely erased on destruction. */
    use SecurelyErasesProperties;

    /** The default reference time for passwords. */
    public const DefaultReferenceTime = 0;

    /** @var HashAlgorithm The hashing algorithm to use when generating HMACs. */
    private HashAlgorithm $hashAlgorithm;

    /** @var TimeStep The time step, in seconds, at which the password changes. */
    private TimeStep $timeStep;

    /** @var int The reference time from new password generation time steps are measured. */
    private int $referenceTime;

    /**
     * @var Renderer The renderer that will perform the truncation that turns the computed HMAC into a user-readable
     * one-time password.
     */
    private Renderer $renderer;

    /**
     * Initialise a new TOTP verifier.
     *
     * If the reference time is specified as an int, it is interpreted as the number of seconds since the Unix epoch.
     * The default hashing algorithm is SHA1.
     *
     * @param Renderer|null $renderer The renderer that produces one-time passwords from HMACs.
     * @param TimeStep|null $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param HashAlgorithm|null $hashAlgorithm The hash algorithm to use when generating OTPs. Must be one of the algorithm class
     * constants. Defaults to Sha1Algorithm.
     */
    public function __construct(?Renderer $renderer = null, ?TimeStep $timeStep = null, int|DateTime $referenceTime = self::DefaultReferenceTime, ?HashAlgorithm $hashAlgorithm = null)
    {
        $this->renderer = $renderer ?? static::defaultRenderer();
        $this->timeStep = $timeStep ?? new TimeStep(TimeStep::DefaultTimeStep);
        $this->hashAlgorithm = $hashAlgorithm ?? new HashAlgorithm(HashAlgorithm::DefaultAlgorithm);
        $this->referenceTime = ($referenceTime instanceof DateTime ? $referenceTime->getTimestamp() : $referenceTime);
    }

    /** Clone the verifier's renderer. */
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
     * @return Secret The random secret.
     * @throws SecureRandomDataUnavailableException if a known source of cryptographically secure random data is
     * not available.
     */
    public static final function randomSecret(): Secret
    {
        try {
            return Secret::fromRaw(random_bytes(64));
        }
        catch (Exception $e) {
            if (function_exists("openssl_random_pseudo_bytes")) {
                $secret = openssl_random_pseudo_bytes(64, $isStrong);


                if (is_string($secret) && $isStrong) {
                    // this is guaranteed not to throw
                    return Secret::fromRaw($secret);
                }
            }

            throw new SecureRandomDataUnavailableException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Create a factory with a six-digit integer password renderer.
     *
     * @param TimeStep|null $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param HashAlgorithm|null $hashAlgorithm The hash algorithm to use when generating OTPs. Defaults to Sha1.
     *
     * @return Factory
     * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
     *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
     */
    public static function sixDigits(TimeStep $timeStep = null, int|DateTime $referenceTime = self::DefaultReferenceTime, ?HashAlgorithm $hashAlgorithm = null): Factory
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        return new Factory(renderer: new SixDigits(), timeStep: $timeStep, referenceTime: $referenceTime, hashAlgorithm: $hashAlgorithm);
    }

    /**
     * Instantiate a TOTP generator with an eight-digit integer password renderer.
     *
     * @param TimeStep|null $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param HashAlgorithm|null $hashAlgorithm The hash algorithm to use when generating OTPs. Defaults to Sha1.
     *
     * @return Factory
     * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
     *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
     */
    public static function eightDigits(TimeStep $timeStep = null, int|DateTime $referenceTime = self::DefaultReferenceTime, HashAlgorithm $hashAlgorithm = null): Factory
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        return new Factory(renderer: new EightDigits(), timeStep: $timeStep, referenceTime: $referenceTime, hashAlgorithm: $hashAlgorithm);
    }

    /**
     * Instantiate a TOTP generator with an integer password renderer of a given number of digits.
     *
     * This is a convenience factory function for commonly-used types of TOTP.
     *
     * @param Digits $digits The number of digits in generated one-time passwords.
     * @param TimeStep|null $timeStep The update time step for the passwords. Defaults to 30 seconds.
     * @param int|DateTime $referenceTime The reference time from which time steps are measured. Defaults to 0.
     * @param HashAlgorithm|null $hashAlgorithm The hash algorithm to use when generating OTPs. Must be one of the algorithm class
     * constants. Defaults to Sha1Algorithm.
     *
     * @return Factory
     * @noinspection PhpDocMissingThrowsInspection algorithm will be default so can't throw
     *  InvalidHashAlgorithmException; secret given so can't throw CryptographicallySecureRandomDataUnavailableException
     */
    public static function integer(Digits $digits, ?TimeStep $timeStep = null, int|DateTime $referenceTime = self::DefaultReferenceTime, ?HashAlgorithm $hashAlgorithm = null): Factory
    {
        return new Factory(renderer: new Integer($digits), timeStep: $timeStep, referenceTime: $referenceTime, hashAlgorithm: $hashAlgorithm);
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
     * @return HashAlgorithm The hashing algorithm.
     */
    public function hashAlgorithm(): HashAlgorithm
    {
        return $this->hashAlgorithm;
    }

    /**
     * Set the hash algorithm to use when generating HMACs.
     *
     * The hash algorithm must be one of SHA1, SHA256 or SHA512. Use the class constants for these to avoid errors.
     *
     * @param HashAlgorithm $hashAlgorithm The hash algorithm.
     * @return $this
     */
    public function withHashAlgorithm(HashAlgorithm $hashAlgorithm): self
    {
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
     * @return TimeStep The time step.
     */
    public function timeStep(): TimeStep
    {
        return $this->timeStep;
    }

    /**
     * @param TimeStep $timeStep
     * @return $this
     */
    public function withTimeStep(TimeStep $timeStep): self
    {
        $clone = clone $this;
        $clone->timeStep = $timeStep;
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
     * @param Secret $secret
     * @return Totp
     * @throws InvalidTimeStepException
     */
    public function totp(Secret $secret): Totp
    {
        // NOTE the Totp constructor will clone the renderer, and the time step is guaranteed to be valid
        return new Totp($secret, $this->renderer, $this->timeStep(), $this->referenceTimestamp(), $this->hashAlgorithm());
    }
}
