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

namespace Equit\Totp\Exceptions\UrlGenerator;

use Throwable;

/**
 * Exception thrown when the user given to an UrlGenerator is not valid.
 */
class InvalidUserException extends UrlGeneratorException
{
    /**
     * @var string The invalid user.
     */
    private string $m_user;

    /**
     * @param string $user The invalid user.
     * @param string $message An optional message explaining what's wrong with the user. Default is an empty string.
     * @param int $code An optional error code. Default is 0.
     * @param Throwable|null $previous The previous Throwable that was thrown, if any. Defaults to null.
     */
    public function __construct(string $user, string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->m_user = $user;
    }

    /**
     * Fetch the user string that was found to be invalid.
     *
     * @return string The user.
     */
    public function getUser(): string
    {
        return $this->m_user;
    }
}
