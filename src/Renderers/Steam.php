<?php

namespace Equit\Totp\Renderers;

/**
 * Renderer for Steam authenticator passwords.
 *
 * @warning This is only a tentative implementation, I have not been able to confirm that this is the correct algorithm.
 */
class Steam implements Renderer
{
	/**
	 * The Steam authenticator alphabet.
	 */
	protected const Alphabet = "23456789BCDFGHJKMNPQRTVWXY";

	/**
	 * The number of characters in the rendered passwords.
	 */
	protected const CharacterCount = 5;

	/**
	 * @inheritDoc
	 */
	public function render(string $hmac): string
	{
		$alphabetSize = strlen(self::Alphabet);
		$offset = ord($hmac[19]) & 0xf;

		$passwordValue = (
				(ord($hmac[$offset]) & 0x7f) << 24
				| ord($hmac[$offset + 1]) << 16
				| ord($hmac[$offset + 2]) << 8
				| ord($hmac[$offset + 3])
			);

		$password = "";

		for ($i = 0; $i < self::CharacterCount; ++$i) {
			$password .= self::Alphabet[$passwordValue % $alphabetSize];
			$passwordValue /= $alphabetSize;
		}

		return $password;
	}
}