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

namespace Equit\Totp\Exceptions;

use Throwable;

/**
 * Exception thrown when an attempt is made to set an invalid secret for a TOTP generator.
 */
class InvalidSecretException extends TotpException
{
    /**
     * @var string The invalid secret.
     */
    private string $m_secret;

    /**
     * Initialise a new InvalidSecretException.
     *
     * @param string $secret The invalid secret.
     * @param string $message An optional message explaining what's wrong with the secret. Defaults to an empty string.
     * @param int $code An optional exception code. Defaults to 0.
     * @param \Throwable|null $previous An optinal previous exception. Defaults to null.
     */
    public function __construct(string $secret, string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->m_secret = $secret;
    }

    /**
     * Fetch the invalid secret.
     *
     * @return string The secret.
     */
    public function getSecret(): string
    {
        return $this->m_secret;
    }
}
