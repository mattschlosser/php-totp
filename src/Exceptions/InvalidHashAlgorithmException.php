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

namespace Equit\Totp\Exceptions;

use Throwable;

/**
 * Exception thrown when an invalid hashing algorithm is specified for a Totp.
 */
class InvalidHashAlgorithmException extends TotpException
{
    /**
     * @var string The invalid hash algorithm name.
     */
    private string $m_hashAlgorithm;

    /**
     * Initialise a new InvalidHashAlgorithmException.
     *
     * @param string $hashAlgorithm The invalid hash algorithm nane.
     * @param string $message An optional message explaining why it's invalid. Defaults to an empty string.
     * @param int $code An optional code for the error. Defaults to 0.
     * @param \Throwable|null $previous An optional previous Throwable that was thrown immediately before this. Defaults
     * to null.
     */
    public function __construct(string $hashAlgorithm, string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->m_hashAlgorithm = $hashAlgorithm;
    }

    /**
     * Fetch the invalid algorithm name.
     *
     * @return string The algorithm name.
     */
    public function getHashAlgorithm(): string
    {
        return $this->m_hashAlgorithm;
    }
}
