<?php

namespace Equit\Totp\Renderers;

use Equit\Totp\Exceptions\InvalidDigitsException;

/**
 * Render a TOTP with an arbitrary number of decimal digits.
 *
 * This renders the truncation of the computed HMAC as a number of decimal digits, as specified by the HOTP
 * specification (see RFC 4226, https://datatracker.ietf.org/doc/html/rfc4226). The number of digits must be 6 or more
 * and should ordinarily be 9 or lower.
 */
class Integer implements IntegerRenderer
{
	use RendersStandardIntegerPasswords;

	/**
	 * @var int The number of digits.
	 */
	protected int $digitCount;

	/**
	 * Initialise a new renderer for a given number of digits.
	 *
	 * @param int $digits The digit count for rendered passwords.
	 *
	 * @throws \Equit\Totp\Exceptions\InvalidDigitsException if the number of digits is < 1.
	 */
	public function __construct(int $digits)
	{
		$this->setDigits($digits);
	}

	/**
	 * Set the number of digits in the rendered passwords.
	 *
	 * The TOTP specification mandates that the rendering contains at least 6 decimal digits. There is little point in
	 * specifying more than 9 digits since you're likely to just be adding extra 0 pad characters on the left of the
	 * 9-digit rendering.
	 *
	 * @param int $digits The number of digits.
	 *
	 * @throws \Equit\Totp\Exceptions\InvalidDigitsException if the number of digits is < 6.
	 */
	public function setDigits(int $digits)
	{
		if (6 > $digits) {
			throw new InvalidDigitsException($digits, "Integer renderers must have at least six digits in the password.");
		}

		$this->digitCount = $digits;
	}
}