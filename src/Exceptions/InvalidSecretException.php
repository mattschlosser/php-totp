<?php

declare(strict_types=1);

namespace Equit\Totp\Exceptions;

use Throwable;

/**
 * Exception thrown when an attempt is made to set an invalid secret for a TOTP generator.
 */
class InvalidSecretException extends TotpException
{
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
