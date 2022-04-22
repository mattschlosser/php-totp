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
 * Exception thrown when an interval < 1 is given for a TOTP instance.
 */
class InvalidIntervalException extends TotpException
{
    /**
     * @var int The invalid interval.
     */
    private int $m_interval;

    /**
     * Initialise a new instance of the exception.
     *
     * @param int $interval The invalid interval.
     * @param string $message An optional message explaining the error. Defaults to an empty string.
     * @param int $code An optional error code. Defaults to 0.
     * @param \Throwable|null $previous The Throwable that occurred before the exception was thrown. Defaults to null.
     */
    public function __construct(int $interval, string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->m_interval = $interval;
    }

    /**
     * Fetch the invalid interval that was used.
     *
     * @return int The interval.
     */
    public function getInterval(): int
    {
        return $this->m_interval;
    }
}
