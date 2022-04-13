<?php

namespace Equit\Totp\Renderers;

use Equit\Totp\Exceptions\InvalidTotpDigitsException;
use Equit\Totp\Renderer;

/**
 * Render a TOTP with an arbitrary number of decimal digits.
 */
class Integer implements Renderer
{
	use RendersIntegerPasswords;

	/**
	 * @var int The number of digits.
	 */
	protected int $digitCount;

	/**
	 * Initialise a new renderer for a given number of digits.
	 *
	 * @param int $digits The digit count for rendered passwords.
	 *
	 * @throws \Equit\Totp\Exceptions\InvalidTotpDigitsException if the number of digits is < 1.
	 */
	public function __construct(int $digits)
	{
		$this->setDigits($digits);
	}

	/**
	 * Set the number of digits in the rendered passwords.
	 *
	 * @param int $digits The number of digits.
	 *
	 * @throws \Equit\Totp\Exceptions\InvalidTotpDigitsException if the number of digits is < 1.
	 */
	public function setDigits(int $digits)
	{
		if (1 > $digits) {
			throw new InvalidTotpDigitsException($digits, "Integer renderers must have a positive number of digits in the password.");
		}

		$this->digitCount = $digits;
	}
}