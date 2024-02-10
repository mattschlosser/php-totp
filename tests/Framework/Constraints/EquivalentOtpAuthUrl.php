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

namespace Equit\TotpTests\Framework\Constraints;

use Equit\TotpTests\Framework\Exceptions\InvalidOtpUrlException;
use PHPUnit\Framework\Constraint\Constraint;
use RuntimeException;

/**
 * Constraint to test whether an OTP auth URL is equivalent to the expected URL.
 */
class EquivalentOtpAuthUrl extends Constraint
{
    /**
     * Regular expression to validate the URL and extract its components.
     */
    private const ValidationRegex = "/otpauth:\\/\\/(totp|hotp)\\/(?:([^\\/]+):)?([^\\/]+)(?:\\/\\?(.*))?/";

    /**
     * @var string The expected URL for reference.
     */
    private string $m_referenceUrl;

    /**
     * @var string The expected OTP type (one of "totp" or "hotp")
     */
    private string $m_referenceOtpType;

    /**
     * @var string The expected issuer. If the reference URL does not have an issuer, this will be an empty string.
     */
    private string $m_referenceIssuer;

    /**
     * @var string The expected user.
     */
    private string $m_referenceUser;

    /**
     * @var string[] The expected parameters.
     */
    private array $m_referenceParameters;

    /**
     * @param string $referenceUrl The URL that tested URLs are expected to match.
     *
     * @throws \Equit\Totp\Tests\Framework\Exceptions\InvalidOtpUrlException
     */
    public function __construct(string $referenceUrl)
    {
        if (!preg_match(self::ValidationRegex, $referenceUrl, $parts)) {
            throw new InvalidOtpUrlException($referenceUrl, "The reference URL is not valid.");
        }

        $this->m_referenceUrl = $referenceUrl;
        [$void, $this->m_referenceOtpType, $this->m_referenceIssuer, $this->m_referenceUser, $params,] = $parts;

        // NOTE the type is always either "totp" or "hotp" so it doesn't need decoding
        $this->m_referenceIssuer = urldecode($this->m_referenceIssuer);
        $this->m_referenceUser   = urldecode($this->m_referenceUser);

        // NOTE we don't need to extract the key/value of each parameter, it's sufficient to check that the full
        // parameter string including its name has a match in the tested URL
        $this->m_referenceParameters = explode("&", $params);
        array_walk($this->m_referenceParameters, [self::class, "urlDecodeParameter",]);
    }

    /**
     * Helper to pass to array_walk to decode the plain-text values for the URL parameters.
     *
     * @param string $value The URL parameter (key and value).
     * @param string $void The array key for the URL parameter (which is ignored).
     */
    private static function urlDecodeParameter(string &$value, string $void): void
    {
        $value = urldecode($value);
    }

    /**
     * Fetch the URL that tested URLs are expected to match.
     * @return string The
     */
    public function referenceUrl(): string
    {
        return $this->m_referenceUrl;
    }

    /**
     * @inheritDoc
     */
    public function toString(): string
    {
        return "is an URL equivalent to {$this->referenceUrl()}";
    }

    /**
     * Check whether a given URL is a match for the reference URL.
     *
     * @param mixed $url The URL to test.
     *
     * @return bool true if the URL matches the reference URL, false if not.
     */
    protected function matches(mixed $url): bool
    {
        if (!is_string($url)) {
            return false;
        }

        if (!preg_match(self::ValidationRegex, $url, $parts)) {
            return false;
        }

        try {
            [$void, $otpType, $issuer, $user, $params,] = $parts;
        }
        catch (RuntimeException $err) {
            return false;
        }

        $params = explode("&", $params);

        if (count($params) !== count($this->m_referenceParameters) ||
            $otpType !== $this->m_referenceOtpType ||       // this is always "totp" or "hotp", never needs url encoding
            urldecode($issuer) !== $this->m_referenceIssuer ||
            urldecode($user) !== $this->m_referenceUser) {
            return false;
        }

        array_walk($params, [self::class, "urlDecodeParameter",]);

        // check that the provided URL contains each of the required parameters
        foreach ($this->m_referenceParameters as $referenceParameter) {
            if (!in_array($referenceParameter, $params)) {
                return false;
            }
        }

        return true;
    }
}
