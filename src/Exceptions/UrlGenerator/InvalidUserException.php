<?php

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
