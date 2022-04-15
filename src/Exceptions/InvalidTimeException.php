<?php

namespace Equit\Totp\Exceptions;

use DateTime;
use DateTimeZone;
use Throwable;

/**
 * Exception thrown when a TOTP is asked to do something at a time that is before its reference time.
 */
class InvalidTimeException extends TotpException
{
	/**
	 * @var int The time that is not valid.
	 */
	private int $m_timestamp;

	/**
	 * @param int $timestamp The invalid timestamp.
	 * @param string $message An optional message describing the problem with the timestamp. Defaults to an empty
	 * string.
	 * @param int $code An optional error code. Defaults to 0.
	 * @param \Throwable|null $previous An optional previous Throwable that was thrown immediately before this. Defaults
	 * to null.
	 */
	public function __construct(int $timestamp, string $message = "", int $code = 0, ?Throwable $previous = null)
	{
		parent::__construct($message, $code, $previous);
		$this->m_timestamp = $timestamp;
	}

	/**
	 * Fetch the erroneous timestamp.
	 *
	 * @return int The timestamp.
	 */
	public function getTimestamp(): int
	{
		return $this->m_timestamp;
	}

	/**
	 * Fetch the erroneous DateTime.
	 *
	 * @return DateTime The DateTime.
	 */
	public function getDateTime(): DateTime
	{
		return DateTime::createFromFormat("U", $this->m_timestamp, new DateTimeZone("UTC"));
	}
}