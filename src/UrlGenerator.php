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

use BadMethodCallException;
use Equit\Totp\Exceptions\UrlGenerator\UnsupportedRendererException;
use Equit\Totp\Exceptions\UrlGenerator\InvalidUserException;
use Equit\Totp\Exceptions\UrlGenerator\UnsupportedReferenceTimeException;
use Equit\Totp\Renderers\Integer;
use Equit\Totp\Renderers\IntegerRenderer;

/**
 * Generate provisioning URLs for services that have OTP 2FA.
 *
 * URLs are of the form:
 *
 *     otpauth://totp/[{issuer}:]{user}/?secret={secret}[&digits={digits}][&algorithm={algorithm}][&period={period}]
 *
 * The {issuer} (setIssuer(), issuer()) is optional; the {user} (setUser(), user()) is mandatory. By default the
 * generator will generate the URL parameters for digits, algorithm and period if those properties of the provided Totp
 * instance are non-default (e.g. if the algorithm is SHA1 the algorithm won't be part of the URL, but if it's SHA256 it
 * will). You can force or suppress individual parameters by passing `true` or `false` respectively to
 * setIncludeDigits(), setIncludeAlgorithm() and setIncludePeriod() as required. To revert to the default behaviour,
 * pass `null` to the same methods.
 *
 * ## Static/fluent interface
 *
 * Each of these methods can be called statically to create a UrlGenerator. You can also chain them to fluently
 * construct a UrlGenerator with the required feature set. For example:
 *
 *     $generator = UrlGenerator::for("darren")->from("Equit")->withDigits();
 *
 * and
 *
 *     $generator = UrlGenerator::from("Equit")->for("darren")->withDigits();
 *
 * are both valid, and will produce UrlGenerators with the same features.
 *
 * @method static self for(string $user) Initialise a generator for a given user.
 * @method static self from(string|null $issuer) Initialise a generator from a given issuer.
 * @method static self withPeriod() Initialise a generator that includes the period parameter in URLs it generates.
 * @method static self withPeriodIfCustomised() Initialise a generator that includes the period parameter in URLs it
 * generates only if the period is not the default period.
 * @method static self withoutPeriod() Initialise a generator that never includes the period parameter in URLs it
 * generates.
 * @method static self withDigits() Initialise a generator that includes the digits parameter in URLs it generates
 * @method static self withDigitsIfCustomised() Initialise a generator that includes the digits parameter in URLs
 * it generates only if the digit count is not the default digit count.
 * @method static self withoutDigits() Initialise a generator that never includes the period parameter in URLs it
 * generates
 * @method static self withAlgorithm() Initialise a generator that includes the algorithm parameter in URLs it
 * generates.
 * @method static self withAlgorithmIfCustomised() Initialise a generator that includes the algorithm parameter in URLs
 * it generates only if the algorithm is not the default algorithm.
 * @method static self withoutAlgorithm() Initialise a generator that never includes the algorithm parameter in URLs it
 * generates.
 */
class UrlGenerator
{
    /**
     * The protocol for URLs.
     *
     * This is the only protocol for OTP provisioning URLs at the time of writing.
     */
    public const Protocol = "otpauth";

    /**
     * The authentication type.
     *
     * At the time of writing the options are "totp" and "hotp". Since this is a TOTP library, we only do "totp" (for
     * now).
     */
    public const AuthenticationType = "totp";

    /**
     * @var string|null The issuer of the TOTP.
     */
    private ?string $m_issuer = null;

    /**
     * @var string The user being provisioned.
     */
    private string $m_user = "";

    /**
     * @var bool Whether the number of digits will be included in generated URLs. Will be null for default behaviour,
     * which is to include the digits if it's not the default digits (6).
     */
    private ?bool $m_includeDigits = null;

    /**
     * @var bool Whether the hash algorithm will be included in generated URLs. Will be null for default behaviour,
     * which is to include the algorithm if it's not the default algorithm (SHA1).
     */
    private ?bool $m_includeAlgorithm = null;

    /**
     * @var bool Whether the period will be included in generated URLs. Will be null for default behaviour, which is
     * to include the period if it's not the default period (30s).
     */
    private ?bool $m_includePeriod = null;

    /**
     * Determine whether an issuer has been set for the URL generator.
     *
     * @return bool true if an issuer has been set, false otherwise.
     */
    public function hasIssuer(): bool
    {
        return isset($this->m_issuer);
    }

    /**
     * Fetch the name of the issuer who is generating the provisioning URL.
     *
     * This can be null if no issuer is to appear in the generated provisioning URLs.
     *
     * @return string|null The issuer.
     */
    public function issuer(): ?string
    {
        return $this->m_issuer;
    }

    /**
     * Set the name of the issuer who is generating the provisioning URL.
     *
     * You can set this to null if you don't want a specific issuer to appear in the provisioning URL.
     *
     * The provided issuer will be URL encoded when the URL is generated, you don't need to (and shouldn't) do this
     * yourself.
     *
     * @param string|null $issuer The issuer.
     */
    public function setIssuer(string|null $issuer): void
    {
        $this->m_issuer = $issuer;
    }

    /**
     * Set the name of the user for whom the provisioning URL is being generated.
     *
     * You can be null if a specific user name is not to appear in the provisioning URL, though this is not recommended
     * as it means the user must label the TOTP in their app themselves.
     *
     * The provided user will be URL encoded when the URL is generated, you don't need to (and shouldn't) do this
     * yourself.
     *
     * @return string $user The user.
     */
    public function user(): string
    {
        return $this->m_user;
    }

    /**
     * Set the name of the user for whom the provisioning URL is being generated.
     *
     * The provided user will be URL encoded when the URL is generated, you don't need to (and shouldn't) do this
     * yourself.
     *
     * @param string $user The user.
     *
     * @throws \Equit\Totp\Exceptions\UrlGenerator\InvalidUserException If the provided user is empty.
     */
    public function setUser(string $user): void
    {
        if (empty($user)) {
            throw new InvalidUserException($user, "The user name for the URL must not be empty.");
        }

        $this->m_user = $user;
    }

    /**
     * The protocol part of the generated URL.
     *
     * The default is "otpauth", and you probably don't want to change this.
     *
     * @return string The protocol.
     */
    public function protocol(): string
    {
        return self::Protocol;
    }

    /**
     * Fetch the authentication type for the generated URL.
     *
     * The default is "totp". You can override this in subclasses if you want to use UrlGenerators for OTP
     * authentication types other than TOTP.
     *
     * @return string The authentication type.
     */
    public function authenticationType(): string
    {
        return self::AuthenticationType;
    }

    /**
     * Fetch whether the period will be included in the provisioning URL.
     *
     * A return value of null indicates that the period will be included if it's not the default period.
     *
     * @return bool|null Whether the period will be included.
     */
    public function includesPeriod(): bool | null
    {
        return $this->m_includePeriod;
    }

    /**
     * Set whether the period should be included in the provisioning URL.
     *
     * Set this to null to revert to the default behaviour: that the algorithm will be included if it's not the default
     * algorithm.
     *
     * @param bool|null $include Whether to include the period.
     */
    public function setIncludePeriod(bool | null $include): void
    {
        $this->m_includePeriod = $include;
    }

    /**
     * Fetch whether the number of digits will be included in the provisioning URL.
     *
     * A return value of null indicates that the digits will be included if it's not the default digits.
     *
     * @return bool|null Whether the digits will be included.
     */
    public function includesDigits(): bool | null
    {
        return $this->m_includeDigits;
    }

    /**
     * Set whether the number of digits should be included in the provisioning URL.
     *
     * Set this to null to revert to the default behaviour: that the digits will be included if it's not the default
     * digits.
     *
     * Note that setting this to true will cause an exception to be thrown if any provided TOTP is not using a renderer
     * that implements the IntegerRenderer interface.
     *
     * @param bool|null $include Whether to include the number of digits.
     */
    public function setIncludeDigits(bool | null $include): void
    {
        $this->m_includeDigits = $include;
    }

    /**
     * Fetch whether the hash algorithm will be included in the provisioning URL.
     *
     * A return value of null indicates that the algorithm will be included if it's not the default algorithm.
     *
     * @return bool|null Whether the algorithm will be included.
     */
    public function includesAlgorithm(): bool | null
    {
        return $this->m_includeAlgorithm;
    }

    /**
     * Set whether the hash algorithm should be included in the provisioning URL.
     *
     * Set this to null to revert to the default behaviour: that the algorithm will be included if it's not the default
     * algorithm.
     *
     * @param bool|null $include Whether to include the algorithm.
     */
    public function setIncludeAlgorithm(bool | null $include): void
    {
        $this->m_includeAlgorithm = $include;
    }

    /**
     * Generate the provisioning URL for a given TOTP.
     *
     * @param Totp $totp The TOTP for which to generate the provisioning URL.
     *
     * @return string The URL.
     * @throws \Equit\Totp\Exceptions\UrlGenerator\UnsupportedRendererException if the Totp's renderer is not an
     *     Integer renderer.
     * @throws \Equit\Totp\Exceptions\UrlGenerator\InvalidUserException if no user has been set in the generator.
     * @throws \Equit\Totp\Exceptions\UrlGenerator\UnsupportedReferenceTimeException if the provided Totp's reference time is not 0.
     */
    public function urlFor(Totp $totp): string
    {
        if (empty($this->user())) {
            throw new InvalidUserException($this->user(), "It is not possible to generate a URL with an empty user.");
        }

        if (0 != $totp->referenceTimestamp()) {
            throw new UnsupportedReferenceTimeException($totp->referenceTimestamp(), "The URI scheme for TOTP codes does not permit non-default timestamps.");
        }

        if (true === $this->includesDigits() && !($totp->renderer() instanceof IntegerRenderer)) {
            throw new UnsupportedRendererException($totp->renderer(), "The renderer must be an implementation of " . IntegerRenderer::class . " to include the digits in a generated URL.");
        }

        $url = urlencode($this->protocol()) . "://" . urlencode($this->authenticationType()) . "/";

        if ($this->hasIssuer()) {
            $url .= urlencode($this->issuer()) . ":" . urlencode($this->user());
        } else {
            $url .= urlencode($this->user());
        }

        $url .= "/?secret={$totp->base32Secret()}";

        if ($this->hasIssuer()) {
            $url .= "&issuer=" . urlencode($this->issuer());
        }

        if (true === $this->includesDigits() || (is_null($this->includesDigits()) && $totp->renderer() instanceof IntegerRenderer && Integer::DefaultDigits !== $totp->renderer()->digits())) {
            $url .= "&digits={$totp->renderer()->digits()}";
        }

        if (true === $this->includesAlgorithm() || (is_null($this->includesAlgorithm()) && Totp::DefaultAlgorithm !== $totp->hashAlgorithm())) {
            $url .= "&algorithm=" . strtoupper($totp->hashAlgorithm());
        }

        if (true === $this->includesPeriod() || (is_null($this->includesPeriod()) && Totp::DefaultTimeStep !== $totp->timeStep())) {
            $url .= "&period={$totp->timeStep()}";
        }

        return $url;
    }

    /**
     * @method static self for (string $user)
     * Fluently configure an UrlGenerator for a specified user.
     *
     * This method can be invoked both statically and on an UrlGenerator instance. If invoked on an instance the return
     * value is guaranteed to be the same instance.
     *
     * @param $user string The username.
     *
     * @return static The configured UrlGenerator.
     */

    /**
     * @method static self from(string $issuer)
     * Fluently configure an UrlGenerator for a specified issuer.
     *
     * This method can be invoked both statically and on an UrlGenerator instance. If invoked on an instance the return
     * value is guaranteed to be the same instance.
     *
     * @param $user string The issuer.
     *
     * @return static The configured UrlGenerator.
     */

    /**
     * @method static self withPeriod()
     * Fluently configure an UrlGenerator to include the period in the generated URL.
     *
     * This method can be invoked both statically and on an UrlGenerator instance. If invoked on an instance the return
     * value is guaranteed to be the same instance.
     *
     * @return static The configured UrlGenerator.
     */

    /**
     * @method static self withoutPeriod()
     * Fluently configure an UrlGenerator to exclude the period in the generated URL.
     *
     * This method can be invoked both statically and on an UrlGenerator instance. If invoked on an instance the return
     * value is guaranteed to be the same instance.
     *
     * @return static The configured UrlGenerator.
     */

    /**
     * @method static self withDigits()
     * Fluently configure an UrlGenerator to include the password digit count in the generated URL.
     *
     * In order to include the digits, any Totp instance provided to the urlFor() method MUST use an IntegerRenderer or
     * an InvalidRendererException will be thrown from urlFor().
     *
     * This method can be invoked both statically and on an UrlGenerator instance. If invoked on an instance the return
     * value is guaranteed to be the same instance.
     *
     * @return static The configured UrlGenerator.
     */

    /**
     * @method static self withoutDigits()
     * Fluently configure an UrlGenerator to exclude the password digit count in the generated URL.
     *
     * This method can be invoked both statically and on an UrlGenerator instance. If invoked on an instance the return
     * value is guaranteed to be the same instance.
     *
     * @return static The configured UrlGenerator.
     */

    /**
     * @method static self withAlgorithm()
     * Fluently configure an UrlGenerator to include the hash algorithm name in the generated URL.
     *
     * This method can be invoked both statically and on an UrlGenerator instance. If invoked on an instance the return
     * value is guaranteed to be the same instance.
     *
     * @return static The configured UrlGenerator.
     */

    /**
     * @method static self withoutAlgorithm()
     * Fluently configure an UrlGenerator to exclude the hash algorithm name in the generated URL.
     *
     * This method can be invoked both statically and on an UrlGenerator instance. If invoked on an instance the return
     * value is guaranteed to be the same instance.
     *
     * @return static The configured UrlGenerator.
     */

    /**
     * Magic method to handle calls to methods in the fluent interface.
     *
     * The UrlGenerator class provides a fluent interface that can be used statically. This magic method is required to
     * enable URL generation to be done statically. It implements all the fluent methods for the class. The methods
     * are documented above.
     *
     * @param string $method The method called.
     * @param array $args The arguments provided in the call.
     *
     * @return $this
     */
    public function __call(string $method, array $args): self
    {
        switch (strtolower($method)) {
            case "from":
                $this->setIssuer(...$args);
                return $this;

            case "for":
                $this->setUser(...$args);
                return $this;

            case "withperiod":
                $this->setIncludePeriod(true);
                return $this;

            case "withperiodifcustomised":
                $this->setIncludePeriod(null);
                return $this;

            case "withoutperiod":
                $this->setIncludePeriod(false);
                return $this;

            case "withdigits":
                $this->setIncludeDigits(true);
                return $this;

            case "withdigitsifcustomised":
                $this->setIncludeDigits(null);
                return $this;

            case "withoutdigits":
                $this->setIncludeDigits(false);
                return $this;

            case "withalgorithm":
                $this->setIncludeAlgorithm(true);
                return $this;

            case "withalgorithmifcustomised":
                $this->setIncludeAlgorithm(null);
                return $this;

            case "withoutalgorithm":
                $this->setIncludeAlgorithm(false);
                return $this;
        }

        throw new BadMethodCallException("Method {$method} is not defined.");
    }

    /**
     * Magic method to enable the static fluent interface.
     *
     * Putative example using the fluent interface (bulk provision some users):
     *
     *     $generator = UrlGenerator::from($service)->withDigits();
     *
     *     foreach ($users as $user) {
     *         $totp = Totp::eightDigitTotp();
     *         $user->setTotpSecret(encrypt($totp->base32Secret()));
     *         $user->sendTotpNotification($generator->for($user->userName())->urlFor($totp));
     *     }
     *
     * Any subclasses you create must have a default constructor for the static fluent interface to work.
     *
     * @param string $method The method called.
     * @param array $args The arguments provided in the call.
     *
     * @return static
     */
    public static function __callStatic(string $method, array $args): static
    {
        return (new static())->__call($method, $args);
    }
}
