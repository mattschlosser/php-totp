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

/**
 * Codec class for Base32 data.
 *
 * @warn A 64-bit underlying platform is required.
 *
 * Enables conversion between raw binary and Base32 encoding. Can be constructed with raw data, or can have either raw
 * or encoded data set using setRaw() and setEncoded() respectively. The raw and Base32-encoded content can be retrieved
 * using raw() and encoded() respectively. setEncoded() will throw an InvalidBase32DataException if given data that is
 * not valid base32.
 *
 * Encoding/decoding is only performed when required, so the class is relatively lightweight.
 */
class Base32
{
    /**
     * The base32 dictionary.
     */
    protected const Dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /**
     * @var string|null The raw data.
     *
     * @warn Due to the decode-on-read feature, the member will be null after the encoded data has been set until
     * decode() is called.
     */
    private ?string $m_rawData;

    /**
     * @var string|null The raw data.
     *
     * @warn |Due to the encode-on-read feature, the member will be null after the raw data has been set until encode()
     * is called.
     */
    private ?string $m_encodedData;

    /**
     * Initialise a new object, optionally with some specified raw data.
     *
     * @param string $rawData The raw data.
     */
    public function __construct(string $rawData = "")
    {
        $this->m_rawData     = $rawData;
        $this->m_encodedData = null;
    }

    /**
     * Set the raw data.
     *
     * @param string $data The raw data to encode.
     */
    public function setRaw(string $data)
    {
        $this->m_rawData     = $data;
        $this->m_encodedData = null;
    }

    /**
     * Set the Base32 encoded content.
     *
     * If the provided content is not valid Base32, the state of the object is undefined.
     *
     * @param string $base32 The base-32 encoded content.
     *
     * @throws InvalidBase32DataException
     */
    public function setEncoded(string $base32)
    {
        $length = strlen($base32);

        if (0 !== ($length % 8)) {
            throw new InvalidBase32DataException($base32, "Base32 data must be padded to a multiple of 8 bytes.");
        }

        // ensure any padding is a valid length
        $paddedLength = $length;

        while (0 < $length && $base32[$length - 1] === "=") {
            --$length;
        }

        switch ($paddedLength - $length) {
            case 0:
            case 1:
            case 3:
            case 4:
            case 6:
                break;

            default:
                throw new InvalidBase32DataException($base32, "Base32 data must be padded with either 0, 1, 3, 4 or 6 '=' characters.");
        }

        // ensure all non-padding characters are from the Base32 dictionary
        $validLength = strspn($base32, self::Dictionary, 0, $length);

        if ($length !== $validLength) {
            throw new InvalidBase32DataException($base32, "Invalid base32 character found at position {$validLength}.");
        }

        $this->m_encodedData = $base32;
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
            $this->decodeBase32Data();
        }

        return $this->m_rawData;
    }

    /**
     * Fetch the Base32 encoded content.
     *
     * @return string The Base32 encoded content of the object.
     */
    public function encoded(): string
    {
        if (!isset($this->m_encodedData)) {
            $this->encodeRawData();
        }

        return $this->m_encodedData;
    }

    /**
     * Encode a string as base32.
     *
     * @param string $raw The byte sequence to encode.
     *
     * @return string The base32-encoded string.
     */
    public static function encode(string $raw): string
    {
        return (new static($raw))->encoded();
    }

    /**
     * Decode a base32-encoded string.
     *
     * @param string $base32 The base32 string to decode.
     *
     * @return string The decoded data.
     * @throws InvalidBase32DataException if the provided string is not a valid base32 encoding.
     */
    public static function decode(string $base32): string
    {
        $codec = new static();
        $codec->setEncoded($base32);
        return $codec->raw();
    }

    /**
     * Internal helper to decode the Base32 encoded content.
     *
     * This is called when the raw content is requested and the internal cache of the raw content is out of sync.
     */
    protected function decodeBase32Data()
    {
        $byteSequence    = strtoupper($this->m_encodedData);
        $this->m_rawData = "";

        // tolerate badly terminated encoded strings by padding with = to appropriate len
        $len = strlen($byteSequence);

        if (0 === $len) {
            return;
        }

        $remainder = $len % 8;

        if (0 < $remainder) {
            $byteSequence .= str_repeat("=", 8 - $remainder);
            $len          += 8 - $remainder;
        }

        for ($i = 0; $i < $len; $i += 8) {
            $out = 0x00;

            for ($j = 0; $j < 8; ++$j) {
                if ("=" == $byteSequence[$i + $j]) {
                    break;
                }

                $pos = strpos(self::Dictionary, $byteSequence[$i + $j]);
                assert(false !== $pos, "Found invalid base32 character at position " . ($i + $j) . " - setEncoded() should ensure this can never happen.");
                $out <<= 5;
                $out |= ($pos & 0x1f);
            }

            /* in any chunk we must have processed either 2, 4, 5, 7 or 8 bytes */
            [$outByteCount, $out] = match ($j) {
                8 => [5, $out],
                7 => [4, $out << 5],
                5 => [3, $out << 15],
                4 => [2, $out << 20],
                2 => [1, $out << 30],
                // NOTE this should never happen
                default => assert(false, "Processed invalid chunk size - error in Base32 decoding algorithm implementation."),
            };

            $outBytes        = chr(($out >> 32) & 0xff)
                . chr(($out >> 24) & 0xff)
                . chr(($out >> 16) & 0xff)
                . chr(($out >> 8) & 0xff)
                . chr($out & 0xff);
            $this->m_rawData .= substr($outBytes, 0, $outByteCount);
        }
    }

    /**
     * Internal helper to encode the raw data as Base32 when required.
     *
     * This is called when the encoded content is requested and the internal cache of the encoded content is out of
     * sync.
     */
    protected function encodeRawData()
    {
        $this->m_encodedData = "";
        $len                 = strlen($this->m_rawData);

        if (0 == $len) {
            return;
        }

        $paddedLen = (int)ceil($len / 5.0) * 5;

        if ($paddedLen !== $len) {
            // temporarily pad so that we've a multiple of 5 characters to encode
            $this->m_rawData .= str_repeat("\0", $paddedLen - $len);
        }

        $pos = 0;

        while ($pos < $paddedLen) {
            // 5 chars of raw convert to 8 chars of base32. the 40 bits of the 5 chars are read in 5-bit chunks,
            // each of which is the index of a base32 character in Dictionary
            $bits = 0x00 | (ord($this->m_rawData[$pos]) << 32)
                | (ord($this->m_rawData[$pos + 1]) << 24)
                | (ord($this->m_rawData[$pos + 2]) << 16)
                | (ord($this->m_rawData[$pos + 3]) << 8)
                | (ord($this->m_rawData[$pos + 4]));

            // the bit pattern contains the groups of 5 bits that form the dictionary lookup indices from left to
            // right:
            // bit                     :  39 ... 35 .... 30 .... 25 .... 20 .... 15 .... 10 .... 5 .... 0
            // encoded character offset:  |   0    |   1   |   2   |   3   |   4   |   5   |   6  |  7  |
            //
            // so the next encoded character is identified by bits 35-39, the one after that by bits 30-34 and
            // so on until the eighth encoded character, represented by bits 0-4.
            //
            // this means that we can't just use 0x1f for the mask to successively take the rightmost 5 bits
            // (shifting the bits 5 to the right as we go) and append the appropriate dictionary character to the
            // encoded data. this would result in the right characters but in reverse order. so we need to start
            // with the mask extracting the leftmost 5 bits for the first character and shift the mask in each
            // iteration to extract the next 5 bits, and we need to track how far to shift the extracted bits so
            // that they represent a valid Dictionary index. hence, $mask and $shift
            $shift = 35;
            $mask  = 0x1f << $shift;

            while (0 !== $mask) {
                $this->m_encodedData .= self::Dictionary[($bits & $mask) >> $shift];
                $mask                >>= 5;
                $shift               -= 5;
            }

            $pos += 5;
        }

        // to keep things simple we've padded the data and therefore produced extraneous encoded data. this works
        // out how much to replace with '=' characters
        $encodedPadding = match ($paddedLen - $len) {
            0 => 0,
            1 => 1,
            2 => 3,
            3 => 4,
            4 => 6,
        };

        // undo the temporary padding of the raw data and pad the encoded data
        if (0 != $encodedPadding) {
            $this->m_encodedData = substr($this->m_encodedData, 0, -$encodedPadding) . str_repeat("=", $encodedPadding);
            $this->m_rawData     = substr($this->m_rawData, 0, $len);
        }
    }
}
