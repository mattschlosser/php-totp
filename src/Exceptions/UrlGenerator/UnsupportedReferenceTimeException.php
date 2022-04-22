<?php

declare(strict_types=1);

namespace Equit\Totp\Exceptions\UrlGenerator;

use DateTime;
use Throwable;

/**
 * Exception thrown when an UrlGenrator encounters a Totp with a timestamp it can't represent.
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
     * @param int | DateTime $time The unsupported timestamp.
     * @param string $message An optional message explaining why it's unsupported. Defaults to an empty string.
     * @param int $code An optional error code. Defaults to 0.
     * @param Throwable|null $previous An optional previous Throwable that was thrown. Defaults to null.
     *
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor guaranteed not to throw here.
     */
    public function __construct(int | DateTime $time, string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);

        if ($time instanceof DateTime) {
            $this->m_time = $time;
            $this->m_timestamp = $time->getTimestamp();
        } else {
            $this->m_timestamp = $time;
            /** @noinspection PhpUnhandledExceptionInspection DateTime constructor will not throw here */
            $this->m_time = new DateTime("@{$time}", new \DateTimeZone("UTC"));
        }
    }

    /**
     * Fetch the unsupported timestamp.
     *
     * @return int The timestamp.
     */
    public function getTimestamp(): int
    {
        return $this->m_timestamp;
    }

    /**
     * Fetch the unsupported time.
     *
     * @return DateTime The time.
     */
    public function getTime(): DateTime
    {
        return $this->m_time;
    }
}