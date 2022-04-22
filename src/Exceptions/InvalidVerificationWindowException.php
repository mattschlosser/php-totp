<?php

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
