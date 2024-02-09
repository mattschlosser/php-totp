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

namespace Equit\Totp\Exceptions\UrlGenerator;

use DateTime;
use DateTimeZone;
use Throwable;

/**
 * Exception thrown when an UrlGenerator encounters a Totp with a timestamp it can't represent.
 *
 * The URI scheme does not allow for custom timestamps, so only the default of 0 is supported.
 */
class UnsupportedReferenceTimeException extends UrlGeneratorException
{
    /**
     * @var int The unsupported timestamp.
     */
    private int $m_timestamp;

    /**
     * @var DateTime The unsupported timestamp as a DateTime object.
     */
    private DateTime $m_time;

    /**
     * Initialise a new exception instance.
     *
     * @param DateTime | int $time The unsupported timestamp.
     * @param string $message An optional message explaining why it's unsupported. Defaults to an empty string.
     * @param int $code An optional error code. Defaults to 0.
     * @param Throwable|null $previous An optional previous Throwable that was thrown. Defaults to null.
     *
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor guaranteed not to throw here.
     */
    public function __construct(DateTime|int $time, string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);

        if ($time instanceof DateTime) {
            $this->m_time = $time;
        } else {
            $this->m_timestamp = $time;
        }
    }

    /**
     * Fetch the unsupported timestamp.
     *
     * @return int The timestamp.
     */
    public function getTimestamp(): int
    {
        if (!isset($this->m_timestamp)) {
            $this->m_timestamp = $this->m_time->getTimestamp();
        }

        return $this->m_timestamp;
    }

    /**
     * Fetch the unsupported time.
     *
     * @return DateTime The time.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor won't throw with timestamp argument.
     */
    public function getTime(): DateTime
    {
        if (!isset($this->m_time)) {
            /** @noinspection PhpUnhandledExceptionInspection DateTime constructor won't throw with timestamp argument. */
            $this->m_time = new DateTime("@{$this->m_timestamp}", new DateTimeZone("UTC"));
        }

        return $this->m_time;
    }
}
