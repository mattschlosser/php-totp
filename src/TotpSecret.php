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

use Equit\Totp\Exceptions\InvalidBase32DataException;
use Equit\Totp\Exceptions\InvalidBase64DataException;
use Equit\Totp\Exceptions\InvalidSecretException;
use Equit\Totp\Traits\SecurelyErasesProperties;

/**
 * Enforces rules for secrets used in TOTP.
 *
 * Instances of this class can only be instantiated using one of the factory methods fromRaw(), fromBase32() or
 * fromBase64(), and are immutable. The class exists primarily to ensure that it's only possible to intialise a Totp
 * with a valid secret regardless of the encoding in which the secret is available.
 *
 *     $totp = new Totp(TotpSecret::fromBase32($base32Secret), ...);
 *
 * It is not possible to create an instance with invalid Base32 or Base64 data - the factory methods ensure the given
 * string is valid Base32/Base64 respectively before instantiating the TotpSecret object.
 *
 * For convenience the object provides access to the secret in raw, Base32 and Base64 forms. The raw form is always
 * stored internally; the Base64 and Base32 versions are only created the first time they are requested, unless the
 * secret was originally provided in the appropriate form.
 */
final class TotpSecret
{
    /** Import the trait that securely erases all string properties on destruction. */
    use SecurelyErasesProperties;

    /** @var string The raw bytes of the secret. */
    private string $raw;

    /**
     * @var string|null The Base32 encoding of the secret.
     *
     * Will be null if the secret was initialised as raw or Base64 and base32() has yet to be called.
     */
    private ?string $base32 = null;

    /**
     * @var string|null The Base64 encoding of the secret.
     *
     * Will be null if the secret was initialised as Base32 or raw and base64() has yet to be called.
     */
    private ?string $base64 = null;

    /**
     * @param string $secret The raw secret.
     *
     * @throws InvalidSecretException if the secret is less than 128 bits (16 bytes) in length.
     */
    private function __construct(string $secret)
    {
        if (16 > strlen($secret)) {
            throw new InvalidSecretException($secret, "Raw secrets for TOTP are required to be 128 bits (16 bytes) or longer.");
        }

        $this->raw = $secret;
    }

    /**
     * Fetch the raw secret.
     *
     * @return string The secret.
     */
    public function raw(): string
    {
        return $this->raw;
    }

    /**
     * Fetch the Base32 encoded secret.
     *
     * @return string The Base32 encoded secret.
     */
    public function base32(): string
    {
        if (!isset($this->base32)) {
            $this->base32 = Base32::encode($this->raw);
        }

        return $this->base32;
    }

    /**
     * Fetch the Base64 encoded secret.
     *
     * @return string The Base64 encoded secret.
     */
    public function base64(): string
    {
        if (!isset($this->base64)) {
            $this->base64 = Base64::encode($this->raw);
        }

        return $this->base64;
    }

    /**
     * Create a TotpSecret from raw data.
     *
     * @param string $secret The raw secret.
     *
     * @return static The created TotpSecret.
     * @throws InvalidSecretException if the secret is less than 128 bits (16 bytes) in length.
     */
    public static function fromRaw(string $secret): self
    {
        return new self($secret);
    }

    /**
     * Create a TotpSecret from Base32 encoded data.
     *
     * @param string $secret The Base32 encoded secret.
     *
     * @return static The created TotpSecret.
     * @throws InvalidBase32DataException if the provided secret is not valid Base32.
     * @throws InvalidSecretException if the secret is less than 128 bits (16 bytes) in length.
     */
    public static function fromBase32(string $secret): self
    {
        $ret = new self(Base32::decode($secret));
        $ret->base32 = $secret;
        return $ret;
    }

    /**
     * Create a TotpSecret from Base64 encoded data.
     *
     * @param string $secret The Base64 encoded secret.
     *
     * @return static The created TotpSecret.
     * @throws InvalidBase64DataException if the provided secret is not valid Base64.
     * @throws InvalidSecretException if the secret is less than 128 bits (16 bytes) in length.
     */
    public static function fromBase64(string $secret): self
    {
        $ret = new self(Base64::decode($secret));
        $ret->base64 = $secret;
        return $ret;
    }
}
