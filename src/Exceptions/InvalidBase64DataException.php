<?php

declare(strict_types=1);

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

namespace Equit\Totp\Exceptions;

use Exception;
use Throwable;

/**
 * Exception thrown when data that is expected to be base64 encoded is not valid.
 */
class InvalidBase64DataException extends Exception
{
    /**
     * @var string The data that was found to be invalid.
     */
    private string $m_data;

    /**
     * Initialise a new InvalidBase64DataException.
     *
     * @param string $data The invalid base64 data.
     * @param string $message An optional message stating what's wrong. Default is an empty string.
     * @param int $code An optional error code. Default is 0.
     * @param \Throwable|null $previous The previous exception, if any. Default is null.
     */
    public function __construct(string $data, string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->m_data = $data;
    }

    /**
     * Fetch the data that is not valid base64.
     *
     * @return string The data.
     */
    public function getData(): string
    {
        return $this->m_data;
    }
}
