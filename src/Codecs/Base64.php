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

namespace Equit\Totp\Codecs;

use Equit\Totp\Contracts\Codec;
use Equit\Totp\Exceptions\InvalidBase64DataException;
use Equit\Totp\Traits\SecurelyErasesProperties;

/**
 * Codec class for Base64 data.
 *
 * Thin wrapper around PHP's built-in base64 encoding/decoding, for consistency with Base32 interface.
 *
 * Encoding/decoding is only performed when required, so the class is relatively lightweight.
 *
 * Instances are immutable.
 */
class Base64 implements Codec
{
    /** Ensure all string properties are securely erased on destruction. */
    use SecurelyErasesProperties;

    /** The base64 dictionary. */
    protected const Dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /**
     * @var string|null The raw data.
     *
     * Always use raw() instead of accessing this - due to decode-on-demand, the member will be null after the encoded
     * data has been set until decode() is called.
     */
    private ?string $rawData;

    /**
     * @var string|null The Base64 encoded data.
     *
     * Always use encoded() instead of accessing this - due to encode-on-demand, the member will be null after the raw
     * data has been set until encode() is called.
     */
    private ?string $encodedData;

    /**
     * Initialise a new object, optionally with some specified raw data.
     *
     * @param string $rawData
     */
    public function __construct(string $rawData = "")
    {
        $this->rawData = $rawData;
        $this->encodedData = null;
    }

    /**
     * Set the raw data.
     *
     * @param string $rawData The raw data to encode.
     */
    public function setRaw(string $rawData): void
    {
        $this->rawData = $rawData;
        $this->encodedData = null;
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

        $this->encodedData = $base64;
        $this->rawData = null;
    }

    /**
     * Fetch the raw content.
     *
     * @return string The raw content of the object.
     */
    public function raw(): string
    {
        if (!isset($this->rawData)) {
            $this->decodeBase64Data();
        }

        return $this->rawData;
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
        if (!isset($this->encodedData)) {
            $this->encodeRawData();
        }

        return $this->encodedData;
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
     * @throws InvalidBase64DataException if the provided string is not a valid base64 encoding.
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
     */
    protected function decodeBase64Data(): void
    {
        $this->rawData = base64_decode($this->encodedData);
    }

    /**
     * Internal helper to encode the raw content as Base64 when required.
     *
     * This is called when the encoded content is requested and the internal cache of the encoded content is out of
     * sync.
     */
    protected function encodeRawData(): void
    {
        $this->encodedData = base64_encode($this->rawData);
    }
}
