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

use Equit\Totp\Exceptions\InvalidBase64DataException;

/**
 * Codec class for Base64 data.
 *
 * Thin wrapper around PHP's built-in base64 encoding/decoding, for consistency with `Base32` interface, and to enforce
 * secure destruction of data. Can be constructed with raw data, or can have either raw or encoded data set using
 * `setRaw()` and `setEncoded()` respectively. The raw and Base64-encoded content can be retrieved using `raw()` and
 * `encoded()` respectively.
 *
 * `setEncoded()` will throw an `InvalidBase64DataException` if given data that is not valid Base64. The class is very
 * strict about Base64 compliance, and the padding with `=` characters at the end of the encoded data must be present if
 * the data requires it.
 *
 * Encoding/decoding is only performed when required, so the class is relatively lightweight.
 *
 * All members are scrubbed on destruction, so this class is safe to use with `Totp` secrets.
 */
class Base64
{
    /**
     * Import the trait that securely erases all string properties on destruction.
     */
    use SecurelyErasesProperties;

    /**
     * The base64 dictionary.
     * @internal
     */
    protected const Dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /**
     * @var string|null The raw data.
     * @internal
     */
    private ?string $m_rawData;

    /**
     * @var string|null The Base64 encoded data.
     * @internal
     */
    private ?string $m_encodedData;

    /**
     * Initialise a new object, optionally with some specified raw data.
     *
     * @param string $rawData
     */
    public function __construct(string $rawData = "")
    {
        $this->m_rawData     = $rawData;
        $this->m_encodedData = null;
    }

    /**
     * Set the raw data.
     *
     * Subsequent calls to `encoded()` will return the Base64 encoding of the provided binary data.
     *
     * @param string $rawData The raw data to encode.
     */
    public function setRaw(string $rawData): void
    {
        $this->m_rawData     = $rawData;
        $this->m_encodedData = null;
    }

    /**
     * Set the Base64 encoded content.
     *
     * Subsequent calls to `raw()` will return the Base64 decoding of the provided Base64 data.
     *
     * If the provided data is not valid Base64, the state of the object is undefined.
     *
     * @param string $base64
     *
     * @throws InvalidBase64DataException if the provided data is not valid Base64.
     */
    public function setEncoded(string $base64): void
    {
        // note base64_decode() is too tolerant of invalid data so we roll our own validation instead of relying on
        // false being returned from base64_decode()
        $length = strlen($base64);

        if (0 !== ($length % 4)) {
            throw new InvalidBase64DataException($base64, "Base64 data must be padded to a multiple of 4 bytes.");
        }

        // ensure any padding is a valid length
        $paddedLength = $length;

        while (0 < $length && $base64[$length - 1] === "=") {
            --$length;
        }

        switch ($paddedLength - $length) {
            case 0:
            case 1:
            case 2:
                break;

            default:
                throw new InvalidBase64DataException($base64, "Base64 data must be padded with either 0, 1 or 2 '=' characters.");
        }

        // ensure all non-padding characters are from the Base64 dictionary
        $validLength = strspn($base64, self::Dictionary, 0, $length);

        if ($length !== $validLength) {
            throw new InvalidBase64DataException($base64, "Invalid base64 character found at position {$validLength}.");
        }

        $this->m_encodedData = $base64;
        $this->m_rawData     = null;
    }

    /**
     * Fetch the raw content.
     *
     * @return string The raw content of the object.
     */
    public function raw(): string
    {
        if (!isset($this->m_rawData)) {
            $this->decodeBase64Data();
        }

        return $this->m_rawData;
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
        if (!isset($this->m_encodedData)) {
            $this->encodeRawData();
        }

        return $this->m_encodedData;
    }

    /**
     * Encode a string as base64.
     *
     * @param string $raw The byte sequence to encode.
     *
     * @return string The base64-encoded string.
     */
    public static function encode(string $raw): string
    {
        return (new static($raw))->encoded();
    }

    /**
     * Decode a base64-encoded string.
     *
     * @param string $base64 The base64 string to decode.
     *
     * @return string The decoded data.
     * @throws InvalidBase64DataException if the provided string is not valid Base64.
     */
    public static function decode(string $base64): string
    {
        $codec = new static();
        $codec->setEncoded($base64);
        return $codec->raw();
    }

    /**
     * Internal helper to decode the Base64 encoded content when required.
     *
     * This is called when the raw content is requested and the internal cache of the raw content is out of sync.
     *
     * @internal
     */
    protected function decodeBase64Data(): void
    {
        $this->m_rawData = base64_decode($this->m_encodedData);
    }

    /**
     * Internal helper to encode the raw content as Base64 when required.
     *
     * This is called when the encoded content is requested and the internal cache of the encoded content is out of
     * sync.
     *
     * @internal
     */
    protected function encodeRawData(): void
    {
        $this->m_encodedData = base64_encode($this->m_rawData);
    }
}
