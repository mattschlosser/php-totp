<?php

declare(strict_types=1);

namespace Equit\Totp\Types;

use Equit\Totp\Exceptions\InvalidHashAlgorithmException;
use Stringable;

final class HashAlgorithm implements Stringable
{
    public const Sha1Algorithm = "sha1";

    public const Sha256Algorithm = "sha256";

    public const Sha512Algorithm = "sha512";

    public const DefaultAlgorithm = self::Sha1Algorithm;

    private string $algorithm;

    /**
     * Initialise a new HashAlgorithm.
     *
     * @param string $algorithm The algorithm.
     *
     * @throws InvalidHashAlgorithmException if the algorighm is not valid.
     */
    public function __construct(string $algorithm)
    {
        if (self::Sha1Algorithm !== $algorithm && self::Sha256Algorithm !== $algorithm && self::Sha512Algorithm !== $algorithm) {
            throw new InvalidHashAlgorithmException($algorithm, "Expected valid hash algorithm, found \"{$algorithm}\"");
        }

        $this->algorithm = $algorithm;
    }

    /** Get the SHA1 hashing algorithm. */
    public static function sha1(): self
    {
        return new self(self::Sha1Algorithm);
    }

    /** Get the SHA256 hashing algorithm. */
    public static function sha256(): self
    {
        return new self(self::Sha256Algorithm);
    }

    /** Get the SHA512 hashing algorithm. */
    public static function sha512(): self
    {
        return new self(self::Sha512Algorithm);
    }

    /** @return string The algorithm. */
    public function algorithm(): string
    {
        return $this->algorithm;
    }

    public function __toString(): string
    {
        return $this->algorithm;
    }
}
