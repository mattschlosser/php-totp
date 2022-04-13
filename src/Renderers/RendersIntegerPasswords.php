<?php

namespace Equit\Totp\Renderers;

/**
 * Trait for renderers that produce padded integer one-time passwords.
 *
 * The final byte of the HMAC is used to calculate an offset. The four bytes starting at that offset are then
 * interpreted as a 32-bit unsigned integer, and the rightmost N digits of the decimal representation of that number are
 * used as the password. The password is left-padded with 0s if necessary to achieve the required number of digits.
 *
 * Renderer subclasses can import this trait and provide a digitCount property with the number of digits and the trait
 * will take care of the rest. The number of digits must be > 0.
 */
trait RendersIntegerPasswords
{
	/**
	 * @return int The number of digits in the rendered password.
	 */
	protected function digits(): int
	{
		assert (is_int($this->digitCount) && 0 < $this->digitCount, "Invalid digit count in Renderer class " . get_class($this));
		return $this->digitCount;
	}

	/**
	 * Render the integer password from a given HMAC.
	 *
	 * @param string $hmac The HMAC to process.
	 *
	 * @return string The digits of the generated password.
	 */
	public function render(string $hmac): string
	{
		$offset = ord($hmac[19]) & 0xf;

		$password = (
				(ord($hmac[$offset]) & 0x7f) << 24
				| ord($hmac[$offset + 1]) << 16
				| ord($hmac[$offset + 2]) << 8
				| ord($hmac[$offset + 3])
			) % (10 ** $this->digits());

		return str_pad("{$password}", 6, "0", STR_PAD_LEFT);

	}
}