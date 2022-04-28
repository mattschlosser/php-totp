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

use Equit\Totp\Exceptions\InvalidSecretException;

/**
 * An abstraction of the different ways to set a secret for a Totp object.
 *
 * Instances of this class can only be instantiated using one of the factory mewthods fromRaw(), fromBase32() or
 * fromBase64(), and are immutable. The class exists primarily to ensure that it's easy to intialise a Totp with a
 * secret regardless of the encoding in which the secret is available - it avoids having to pass the Totp constructor
 * the secret's encoding in another parameter.
 *
 *     $totp = new Totp(TotpSecret::fromBase32($base32Secret));
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
    /**
     * @var string The raw bytes of the secret.
     */
    private string $m_raw;

    /**
     * @var string|null The Base32 encoding of the secret.
     *
     * Will be null if the secret was initialised as raw or Base64 and base32() has yet to be called.
     */
    private ?string $m_base32 = null;

    /**
     * @var string|null The Base64 encoding of the secret.
     *
     * Will be null if the secret was initialised as Base32 or raw and base64() has yet to be called.
     */
    private ?string $m_base64 = null;

    /**
     * @param string $secret The raw secret.
     *
     * @throws \Equit\Totp\Exceptions\InvalidSecretException if the secret is less than 128 bits (16 bytes) in length.
     */
    private function __construct(string $secret)
    {
        if (16 > strlen($secret)) {
            throw new InvalidSecretException($secret, "Raw secrets for TOTP are required to be 128 bits (16 bytes) or longer.");
        }

        $this->m_raw = $secret;
    }

    /**
     * Shred the secrets before deallocation.
     */
    public function __destruct()
    {
        Totp::shred($this->m_raw);

        if ($this->m_base32) {
            Totp::shred($this->m_base32);
        }

        if ($this->m_base64) {
            Totp::shred($this->m_base64);
        }
    }

    /**
     * Fetch the raw secret.
     *
     * @return string The secret.
     */
    public function raw(): string
    {
        return $this->m_raw;
    }

    /**
     * Fetch the Base32 encoded secret.
     *
     * @return string The Base32 encoded secret.
     */
    public function base32(): string
    {
        if (!isset($this->m_base32)) {
            $this->m_base32 = Base32::encode($this->m_raw);
        }

        return $this->m_base32;
    }

    /**
     * Fetch the Base64 encoded secret.
     *
     * @return string The Base64 encoded secret.
     */
    public function base64(): string
    {
        if (!isset($this->m_base64)) {
            $this->m_base64 = Base64::encode($this->m_raw);
        }

        return $this->m_base64;
    }

    /**
     * Create a TotpSecret from raw data.
     *
     * @param string $secret The raw secret.
     *
     * @return static The created TotpSecret.
     * @throws \Equit\Totp\Exceptions\InvalidSecretException if the secret is less than 128 bits (16 bytes) in length.
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
     * @throws \Equit\Totp\Exceptions\InvalidBase32DataException if the provided secret is not valid Base32.
     * @throws \Equit\Totp\Exceptions\InvalidSecretException if the secret is less than 128 bits (16 bytes) in length.
     */
    public static function fromBase32(string $secret): self
    {
        $ret           = new self(Base32::decode($secret));
        $ret->m_base32 = $secret;
        return $ret;
    }

    /**
     * Create a TotpSecret from Base64 encoded data.
     *
     * @param string $secret The Base64 encoded secret.
     *
     * @return static The created TotpSecret.
     * @throws \Equit\Totp\Exceptions\InvalidBase64DataException if the provided secret is not valid Base64.
     * @throws \Equit\Totp\Exceptions\InvalidSecretException if the secret is less than 128 bits (16 bytes) in length.
     */
    public static function fromBase64(string $secret): self
    {
        $ret           = new self(Base64::decode($secret));
        $ret->m_base64 = $secret;
        return $ret;
    }
}
