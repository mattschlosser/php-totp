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
 * Exception thrown when an invalid number of password digits is given for an IntegerTOTP instance.
 */
class InvalidDigitsException extends TotpException
{
    /**
     * @var int The invalid number of digits.
     */
    private int $m_digits;

    /**
     * @param int $digits The invalid number of digits.
     * @param string $message An optional message explaining the error. Defaults to an empty string.
     * @param int $code An optional error code. Defaults to 0.
     * @param \Throwable|null $previous The Throwable that occurred before the exception was thrown. Defaults to null.
     */
    public function __construct(int $digits, string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->m_digits = $digits;
    }

    /**
     * Fetch the invalid number of digits.
     *
     * @return int The number of digits.
     */
    public function getDigits(): int
    {
        return $this->m_digits;
    }
}
