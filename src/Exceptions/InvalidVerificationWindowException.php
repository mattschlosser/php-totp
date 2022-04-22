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
 * Exception thrown when the window for verification of a one-time password is not valid.
 */
class InvalidVerificationWindowException extends TotpException
{
    /**
     * @var int The invalid window.
     */
    private int $m_window;

    /**
     * @param int $window The invalid window.
     * @param string $message An optional message explaining what's wrong with the window. Defaults to an empty string.
     * @param int $code An optional error code. Defaults to 0.
     * @param Throwable|null $previous An optional Throwable that was thrown immediately before this. Defaults to null.
     */
    public function __construct(int $window, string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->m_window = $window;
    }

    /**
     * Fetch the invalid window.
     *
     * @return int The window.
     */
    public function getWindow(): int
    {
        return $this->m_window;
    }
}
