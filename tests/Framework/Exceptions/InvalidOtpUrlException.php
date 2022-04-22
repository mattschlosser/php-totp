<?php

declare(strict_types=1);

namespace Equit\Totp\Tests\Framework\Exceptions;

use Exception;
use Throwable;

/**
 * Exception thrown when an EquivalentUrl constraint is constructed with an invalid reference URL.
 */
class InvalidOtpUrlException extends Exception
{
    /**
     * @var string The invalid URL.
     */
    private string $m_url;

    /**
     * @param string $url The invalid URL.
     * @param string $message An optional message explaining what's wrong with the URL. Defaults to an empty string.
     * @param int $code An optinal error code. Defaults to 0.
     * @param \Throwable|null $previous The optional previous Throwable that was thrown. Defaults to null.
     */
    public function __construct(string $url, string $message = "", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->m_url = $url;
    }

    /**
     * Fetch the invalid URL.
     *
     * @return string The invalid URL.
     */
    public function getUrl(): string
    {
        return $this->m_url;
    }
}
