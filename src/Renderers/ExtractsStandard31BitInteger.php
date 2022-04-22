<?php

declare(strict_types=1);

namespace Equit\Totp\Renderers;

/**
 * Trait for renderers that use the TOTP standard way of extracting a 31-bit integer from a HMAC.
 *
 * The RFC specifies that the integer is extracted thus:
 * - read the 4 least significant bits of the final byte of the HMAC as an unsigned int
 * - use that as an offset into the HMAC bytes, starting at the first byte, whose offset is 0
 * - interpret the four bytes starting at the offset as a big-endian 32-bit integer and mask off the most significant
 *   bit
 */
trait ExtractsStandard31BitInteger
{
    /**
     * Extract the int from an HMAC.
     *
     * The int extracted is the value of the big-endian integer in to the platform's native byte order. In other words,
     * the value you get is the same value as the bytes would represent on a big-endian platform.
     *
     * @param string $hmac The HMAC from which to extract the int.
     *
     * @return int The extracted int.
     */
    protected static function extractIntFromHmac(string $hmac): int
    {
        $offset = ord($hmac[strlen($hmac) - 1]) & 0xf;

        return (ord($hmac[$offset]) & 0x7f) << 24
            | ord($hmac[$offset + 1]) << 16
            | ord($hmac[$offset + 2]) << 8
            | ord($hmac[$offset + 3]);
    }
}
