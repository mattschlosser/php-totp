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

use Equit\Totp\Exceptions\InvalidBase64DataException;

/**
 * Codec class for Base64 data.
 *
 * @warn A 64-bit underlying platform is required.
 *
 * Thin wrapper around PHP's built-in base64 encoding/decoding, for consistency with Base32 interface.
 *
 * Encoding/decoding is only performed when required, so the class is relatively lightweight.
 */
class Base64
{
    /**
     * @var string|null The plain data.
     *
     * Always use plain() instead of accessing this - due to the decode-on-read feature, the member will be null after
     * the encoded data has been set until decode() is called.
     */
    private ?string $m_plainData;

    /**
     * @var string|null The plain data.
     *
     * Always use encoded() instead of accessing this - due to the encode-on-read feature, the member will be null after
     * the plain data has been set until encode() is called.
     */
    private ?string $m_encodedData;

    /**
     * Initialise a new object, optionally with some specified plain text.
     *
     * @param string $plainData
     */
    public function __construct(string $plainData = "")
    {
        $this->m_plainData = $plainData;
        $this->m_encodedData = null;
    }

    /**
     * Set the plain-text data.
     *
     * @param string $data The plain-text data to encode.
     */
    public function setPlain(string $data)
    {
        $this->m_plainData = $data;
        $this->m_encodedData = null;
    }

    /**
     * Set the Base64 encoded content.
     *
     * If the provided content is not valid Base64, the state of the object is undefined.
     *
     * @param string $base64
     *
     * @throws InvalidBase64DataException
     */
    public function setEncoded(string $base64)
    {
        // ensure it's valid
        $plain = base64_decode($base64);

        if (false === $plain) {
            throw new InvalidBase64DataException($base64, "Invalid base64 character found in data.");
        }

        // may as well keep the decoded data since we have it
        $this->m_encodedData = $base64;
        $this->m_plainData = $plain;
    }

    /**
     * Fetch the plain-text content.
     *
     * @return string The plain text content of the object.
     */
    public function plain(): string
    {
        if(!isset($this->m_plainData)) {
            $this->decodeBase64Data();
        }

        return $this->m_plainData;
    }

    /**
     * Fetch the Base64 encoded content.
     *
     * If the object is not valid, this is undefined.
     *
     * @return string The Base64 encoded content of the object.
     */
    public function encoded(): string
    {
        if(!isset($this->m_encodedData)) {
            $this->encodePlainData();
        }

        return $this->m_encodedData;
    }

    /**
     * Encode a string as base64.
     *
     * @param string $plain The byte sequence to encode.
     *
     * @return string The base64-encoded string.
     */
    public static function encode(string $plain): string
    {
        return (new static($plain))->encoded();
    }

    /**
     * Decode a base64-encoded string.
     *
     * @param string $base64 The base64 string to decode.
     *
     * @return string The decoded data.
     * @throws InvalidBase64DataException if the provided string is not a valid base64 encoding.
     */
    public static function decode(string $base64): string
    {
        $codec = new static();
        $codec->setEncoded($base64);
        return $codec->plain();
    }

    /**
     * Internal helper to decode the Base64 encoded content.
     *
     * This is called when the plain text content is requested and the internal cache of the plain text content is out of sync.
     */
    protected function decodeBase64Data()
    {
        $this->m_plainData = base64_decode($this->m_encodedData);
    }

    /**
     * Internal helper to encode the plain text content as Base64 when required.
     *
     * This is called when the encoded content is requested and the internal cache of the encoded content is out of sync.
     */
    protected function encodePlainData()
    {
        $this->m_encodedData = base64_encode($this->m_plainData);
    }
}
